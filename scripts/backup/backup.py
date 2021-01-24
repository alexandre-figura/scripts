#!/usr/bin/env python3

import hashlib
import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import yaml
from cached_property import cached_property
from openstack import connect
from openstack.exceptions import ResourceNotFound
from openstack.object_store.v1._proxy import Proxy as ObjectStore
from subprocess import run
from yaml import YAMLError

log = logging.getLogger(__name__)


# Helper functions.

def retrieve_backup(data_container: str, metadata_container: str) -> 'Backup':
    """Retrieve metadata files from online backup, for further processing.

    If files are corrupted, exits abruptly.
    """
    # Retrieve backup metadata from the Cloud.
    cloud = connect()
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
                    # File has changed and needs to be uploaded again.
                    backup.upload_new_version(media)

            elif copies := backup.find_by_checksum(media):
                # Files with  similar checksum already exist in the backup.
                # As OpenStack uses MD5 to compute checksums,
                # there can be collisions.

                if len(copies) == 1:
                    # File is already in backup, but has been renamed.
                    backup.rename(copies[0], media)
                else:
                    for copy in copies:
                        # FIXME: Do something!!
                        pass

            else:
                # File is not in backup yet.
                backup.upload(media)

           
with open('medias.yaml', 'w') as f:
    dump(medias, f)



# Custom objects.

class Backup:
    # checksum -> obfuscated_name
    CHECKSUMS_FILENAME = 'checksums.yaml'

    # obfuscated_name -> checksum, file, mtime
    MAPPING_FILENAME = 'files.yaml'

    @dataclass
    class BackupItem:
        checksum: str
        last_modification: float
        obfuscated_name: str
        original_file: str

        def to_dict(self):
            return {
                'checksum': self.checksum,
                'mtime': self.last_modification,
                'file': self.original_file,
            }

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
            return yaml.load(checksums)  # Can raise YAMLError

        except ResourceNotFound:
            self.object_store.upload_object(
                self.CHECKSUMS_FILENAME,
                container=self.metadata_container,
                data=b'',
            )
            return {}

    @cached_property
    def files(self):
        try:
            files = self.object_store.get_object(
                self.MAPPING_FILENAME,
                container=self.metadata_container,
            )
            return yaml.load(files)  # Can raise YAMLError

        except ResourceNotFound:
            self.object_store.upload_object(
                self.MAPPING_FILENAME,
                container=self.metadata_container,
                data=b'',
            )
            return {}

    # Methods

    def load(self) -> None:
        """Retrieve backup's metadata.

        :raise yaml.YAMLError: when cannot decode metadata files.
        """
        self.checksums  # Can raise YAMLError
        self.files      # Can raise YAMLError

    def find_by_checksum(self, media: 'Media') -> List[BackupItem]:
        """Look for files in backup with a similar checksum than `media`."""
        items = []

        for obfuscated_name in self.checksums.get(media.checksum, []):
            item = self.BackupItem(
                checksum=media.checksum,
                last_modification=self.files[obfuscated_name]['mtime'],
                obfuscated_name=obfuscated_name,
                original_file=self.files[obfuscated_name]['file'],
            )
            items.append(item)

        return items

    def find_by_path(self, media: 'Media') -> Optional[BackupItem]:
        """Look for a file in backup with a similar path than `media`."""
        obfuscated_name = self.obfuscate_filepath(media)

        try:
            assert media.remote_name in self.mapping
        except AssertionError:
            return

        return self.BackupItem(
            checksum=self.checksums[obfuscated_name],
            last_modification=self.files[obfuscated_name]['mtime'],
            obfuscated_name=obfuscated_name,
            original_file=self.files[obfuscated_name]['file'],
        )

    def obfuscate_filepath(self, media):
        return hashlib.blake2b(media.relative_path.encode()).hexdigest()

    def rename(self, item: BackupItem, media: 'Media') -> None:
        """Rename file in the backup."""
        error = f"File not in backup: {item.obfuscated_name}"
        assert item.obfuscated_name in self.mapping, error

        obfuscated_name = self.obfuscate_filepath(media)

        run(
            f'swift copy '  # Not yet supported by OpenStack SDK
            f'-d /{self.data_container}/{obfuscated_name} '
            f'{self.data_container} {item.obfuscated_name}',
            check=True,  # TODO: Handle errors (01/2021)
        )
        self.object_store.delete(item.obfuscated_name, self.data_container)

        # Update metadata.
        self.checksums[item.checksum].append(obfuscated_name)
        self.checksums[item.checksum].remove(item.obfuscated_name)

        self.files[target] = self.files[item.obfuscated_name]
        self.files[target]['file'] = media.relative_path
        del self.files[item.obfuscated_name]

    def upload(self, media: 'Media') -> BackupItem:
        """Upload new file to the backup."""
        # TODO: Properly compute checksum of files > 5GB.
        error = "Cannot backup files bigger than 5gb for now"
        assert media.stat().st_size < 5368709120, error

        obfuscated_name = self.obfuscated_name(media)

        while self.object_store.upload_object(
            self.data_container, media.remote_name, filename=str(media),
        ):
            upload = self.object_store.get_object_metadata(
                media.remote_name,
                self.data_container,
            )

            if upload.etag == media.checksum:
                break
            else:
                log.warning(
                    f"Upload not completed successfully. "
                    f"Remote copy appears to be corrupted. "
                    f"Trying again: {media}"
                )

        # Update metadata.
        item = self.BackupItem(
            checksum=media.checksum,
            last_modification=self.files[obfuscated_name]['mtime'],
            obfuscated_name=obfuscated_name,
            original_file=self.files[obfuscated_name]['file'],
        )
        self.files[obfuscated_name] = item.to_dict()

        if media.checksum in self.checksums:
            self.checksums[media.checksum].append(obfuscated_name)
        else:
            self.checksums[media.checksum] = [obfuscated_name]

        log.debug("Uploaded to backup: %s", media)

        return item

    def upload_new_version(self, media: 'Media') -> BackupItem:
        """Update a file in the backup.

        A copy of the previous version is kept for 6 months.
        """
        # TODO: Properly compute checksum of files > 5GB (01/2021)
        error = "Cannot backup files bigger than 5gb for now: {media}"
        assert media.stat().st_size < 5368709120, error

        obfuscated_name = self.obfuscated_name(media)

        try:
            item = self.mapping[obfuscated_name]
        except KeyError:
            raise AssertionError(f"File not yet in backup: {media}")

        # Archive previous version.
        stamp = int(datetime.utcnow().timestamp())
        archive_name = f'{media.remote_name}-{stamp}'

        run(
            f'swift copy '  # Not yet supported by OpenStack SDK
            f'-d /{self.data_container}/{archive_name} '
            f'-H "X-Delete-After: 16070400" '  # 6 months
            f'{self.data_container} {media.remote_name}',
            check=True,  # TODO: Handle errors (01/2021)
        )

        # Upload new version.
        self.object_store.delete(media.remote_name, self.data_container)
        upload = self.upload(media)

        # Update metadata.
        self.checksums[item.checksum].remove(item.obfuscated_name)
        log.debug("Uploaded new version for: %s", media)

        return upload


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
