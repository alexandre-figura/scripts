#!/usr/bin/env python3

import hashlib
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from subprocess import run
from typing import Any, List, Optional

import openstack
import yaml
from cached_property import cached_property
from openstack.exceptions import ResourceNotFound
from openstack.object_store.v1._proxy import Proxy as ObjectStore
from yaml import YAMLError

log = logging.getLogger(__name__)


# Helper functions.

def retrieve_backup(data_container: str, metadata_container: str) -> 'Backup':
    """Retrieve metadata files from online backup, for further processing.

    If files are corrupted, exits abruptly.
    """
    # Retrieve backup metadata from the Cloud.
    cloud = openstack.connect()
    object_store = cloud.object_store
    backup = Backup(object_store, data_container, metadata_container)

    try:
        backup.load()
    except YAMLError as exc:
        sys.exit(f"Cannot decode metadata files: {exc}")

    return backup


def synchronize(directory: Path, backup: 'Backup'):
    """Update an online backup to reflect local state.

    Files are first compared by "Last Modification Time" to detect new changes.
    This allows to not have to compute checksums for every file,
    and thus have a quicker backup.

    Checksums are only computed for files which are not yet detected to be
    in the backup, and after every upload (new files, changes, renaming).
    """
    # Scan directory to backup.
    for path in directory.rglob("*"):  # TODO: Do multiprocessing
        if path.is_file():
            media = Media(path, directory)

            if copy := backup.find_by_path(media):
                # File already exists in the backup.

                if copy.last_modification != media.last_modification:
                    # File has changed since last backup.
                    backup.upload_new_version(media)

            elif copies := backup.find_by_checksum(media):
                # A similar file already exists in the backup.

                for copy in copies:
                    if copy.last_modification == media.last_modification:
                        # A copy has been made, or the file has been renamed.

                        if (directory / copy.original_file).exists():
                            # It is a brand new copy.
                            backup.upload(media)
                        else:
                            # File has been renamed.
                            backup.rename(copy, media)

            else:
                # File is not in backup yet.
                backup.upload(media)

    # Archive files not on disk anymore.
    backup.clean()

           
with open('medias.yaml', 'w') as f:
    dump(medias, f)



# Custom objects.

class Backup:
    # checksum -> obfuscated_name
    CHECKSUMS_FILENAME = 'checksums.yaml'

    # obfuscated_name -> checksum, file, mtime
    MAPPING_FILENAME = 'files.yaml'

    #: External function to obfuscate file paths in the backup.
    obfuscator: Any = hashlib.blake2b

    #: External function to encrypt files in the backup.
    encryptor: Any = None

    def __init__(
            self,
            object_store: ObjectStore,
            data_container: str,
            metadata_container: str,
    ):
        self.object_store = object_store
        self.data_container = data_container
        self.metadata_container = metadata_container

    # Properties

    @cached_property
    def checksums(self):
        try:
            checksums = self.object_store.get_object(
                self.CHECKSUMS_FILENAME,
                container=self.metadata_container,
            )

        except ResourceNotFound:
            checksums = b'{}'
            self.object_store.upload_object(
                self.CHECKSUMS_FILENAME,
                container=self.metadata_container,
                data=checksums,
            )

        return yaml.safe_load(checksums)  # Can raise YAMLError

    @cached_property
    def files(self):
        try:
            files = self.object_store.get_object(
                self.MAPPING_FILENAME,
                container=self.metadata_container,
            )

        except ResourceNotFound:
            files = b'{}'
            self.object_store.upload_object(
                self.MAPPING_FILENAME,
                container=self.metadata_container,
                data=files,
            )

        return yaml.safe_load(files)  # Can raise YAMLError

    # Managers

    def load(self) -> None:
        """Retrieve backup's metadata.

        :raise yaml.YAMLError: when cannot decode metadata files.
        """
        self.checksums  # Can raise YAMLError
        self.files      # Can raise YAMLError

    def clean(self) -> None:
        """Archive in backup files deleted from :attr:`.directory`."""
        # TODO: Don't analyze files already found previously (01/2021)
        for name in self.files:
            item = BackupItem(name, backup=self)

            if not (self.directory / item.original_file).exists():
                self.delete(item)

    # Finders

    def find_by_checksum(self, media: 'Media') -> List['BackupItem']:
        """Look for files in backup with a similar checksum than `media`."""
        items = []

        for obfuscated_name in self.checksums.get(media.checksum, []):
            item = BackupItem(obfuscated_name, backup=self)
            items.append(item)

        return items

    def find_by_path(self, media: 'Media') -> Optional['BackupItem']:
        """Look for a file in backup with a similar path than `media`."""
        obfuscated_name = self.obfuscate_filepath(media)

        try:
            assert media.remote_name in self.mapping
        except AssertionError:
            return

        return BackupItem(obfuscated_name, backup=self)

    # Actions

    def rename(self, item: 'BackupItem', media: 'Media') -> 'BackupItem':
        """Rename file in the backup."""
        assert item.exists(), f"File not in backup: {item.name}"

        obfuscated_name = self.obfuscate_filepath(media)
        new = self.copy(item, obfuscated_name)
        self.delete(item)

        log.info("Renamed in backup: %s", media)

        return new

    def upload(self, media: 'Media', replace: bool = False) -> 'BackupItem':
        """Upload new file to the backup.

        :param replace:
            overwrite file if already in backup.
        :raise <SOMETHING>:
            if file already exists in backup and `replace` is `False`.
        """
        # TODO: Properly compute checksum of files > 5GB.
        error = "Cannot backup files bigger than 5gb for now"
        assert media.stat().st_size < 5368709120, error

        obfuscated_name = self.obfuscated_name(media)
        item = BackupItem(obfuscated_name, backup=self)

        if replace:
            assert item.exists(), f"File not in backup: {item.name}"
            self.delete(item)

        # TODO: Check if it overwrites by default (01/2021)
        while self.object_store.upload_object(
            self.data_container, obfuscated_name, filename=str(media),
        ):
            upload = self.object_store.get_object_metadata(
                obfuscated_name,
                self.data_container,
            )

            if upload.etag == media.checksum:
                break  # Alles gut!
            else:
                log.warning(
                    f"Upload not completed successfully. "
                    f"Remote copy appears to be corrupted. "
                    f"Trying again: {media}"
                )

        # Update metadata.
        if media.checksum in self.checksums:
            self.checksums[media.checksum].append(obfuscated_name)
        else:
            self.checksums[media.checksum] = [obfuscated_name]

        self.files[obfuscated_name] = {
            'checksum': media.checksum,
            'file': media.relative_path,
            'mtime': media.last_modification,
        }

        if replace:
            log.info("Uploaded new version for: %s", media)
        else:
            log.info("Uploaded to backup: %s", media)

        return item

    def upload_new_version(self, media: 'Media') -> 'BackupItem':
        """Update a file in the backup.

        A copy of the previous version is kept for 6 months.
        """
        obfuscated_name = self.obfuscated_name(media)
        item = BackupItem(obfuscated_name, backup=self)
        assert item.exists(), f"File not in backup: {item.name}"

        # TODO: Properly compute checksum of files > 5GB (01/2021)
        error = "Cannot backup files bigger than 5gb for now: {media}"
        assert media.stat().st_size < 5368709120, error

        return self.upload(media, replace=True)

    # Helpers

    def copy(self, item: 'BackupItem', target: str) -> 'BackupItem':
        assert item.exists(), f"File not in backup: {item.name}"

        run(
            f'swift copy '  # Not yet supported by OpenStack SDK
            f'-d /{self.data_container}/{target} '
            f'{self.data_container} {item.name}',
            check=True,  # TODO: Handle errors and check ETAG (01/2021)
        )
        self.files[target] = self.files[item.name]
        self.checksums[item.checksum].append(target)

        return BackupItem(target, backup=self)

    def delete(self, item: 'BackupItem') -> None:
        """Delete file from the backup.

        File is not immediately deleted: an archive is made,
        and kept for 6 months, before getting automatically
        removed from the backup.
        """
        assert item.exists(), f"File not in backup: {item.name}"

        stamp = int(datetime.utcnow().timestamp())
        archive_name = f'{item.name}-{stamp}'

        run(
            f'swift copy '  # Not yet supported by OpenStack SDK
            f'-d /{self.data_container}/{archive_name} '
            f'-H "X-Delete-After: 16070400" '  # 6 months
            f'{self.data_container} {item.name}',
            check=True,  # TODO: Handle errors and check ETAG (01/2021)
        )

        # Update metadata.
        self.files.pop(item.name)

        if len(self.checksums[item.checksum]) == 1:
            self.checksums.pop(item.checksum)
        else:
            self.checksums[item.checksum].remove(item.name)

    def obfuscate_filepath(self, media):
        return self.obfuscator(media.relative_path.encode()).hexdigest()


class BackupItem:
    def __init__(self, name: str, *, backup: 'Backup'):
        self.name = name
        self.backup = backup

    # Properties
    @property
    def checksum(self):
        return self.backup.files[self.name]['checksum']

    @property
    def last_modification(self):
        return self.backup.files[self.name]['mtime']

    @property
    def original_file(self):
        return self.backup.files[self.name]['file'],

    # Methods

    def exists(self):
        return self.name in self.backup.files


class Media(Path):
    def __init__(self, path: Path, directory: Path):
        Path.__init__(self, str(path))
        self.directory = directory

    @cached_property
    def checksum(self) -> str:
        return ''

    @property
    def last_modification(self) -> float:
        return datetime.fromtimetamp(self.stat().st_mtime, tz=timezone.utc)

    @property
    def relative_path(self) -> Path:
        return self.relative_to(self.directory)


# Script.

if __name__ == '__main__':
    directory = sys.argv[1]
    data_container = f'{sys.argv[2]}-data'
    metadata_container = f'{sys.argv[2]}-metadata'

    backup = retrieve_backup(data_container, metadata_container)
    synchronize(directory, backup)
