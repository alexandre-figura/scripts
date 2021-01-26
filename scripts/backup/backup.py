#!/usr/bin/env python3

"""
gpg --gen-key --default-new-key-algo "ed25519/cert,sign+cv25519/encr"
"""

import hashlib
import logging
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import partial
import os
from pathlib import Path
from subprocess import run
from tempfile import NamedTemporaryFile
from typing import Any, Callable, List, Optional, Iterator, Union, cast

import openstack
import yaml
from cached_property import cached_property
from openstack.exceptions import ResourceNotFound
from openstack.object_store.v1._proxy import Proxy as ObjectStore
from openstack.object_store.v1.obj import Object

log = logging.getLogger(__name__)


# Main Functions

def retrieve_backup(data_container: str, metadata_container: str) -> 'Backup':
    """Prepare backup for further synchronization."""
    cloud = openstack.connect()
    object_store = cloud.object_store

    # TODO: Assert containers exist (01/2021)

    return Backup(
        object_store,
        data_container,
        metadata_container,
        encryptor=encrypt_with_gpg,
        decryptor=decrypt_with_gpg,
        obfuscator=obfuscate_with_blake2b,
    )


def synchronize(directory: str, backup: 'Backup'):
    """Update an online backup to reflect local state.

    Files are first compared by "Last Modification Time" to detect new changes.
    This allows to not have to compute checksums for every file,
    and thus have a quicker backup.

    Checksums are only computed for files which are not yet detected to be
    in the backup, and after every upload (new files, changes, renaming).
    """
    # Scan directory to backup.
    medias = [
        LocalFile(path.relative_to(directory))
        for path in Path(directory).rglob('*')
        if path.is_file() and not str(path.relative_to(directory)).startswith('.')
    ]

    if not medias:
        sys.exit("Nothing to backup :(")

    os.chdir(directory)  # Files in backup have relative paths

    # TODO: Do multiprocessing (01/2021)
    for media in medias:
        if copy := backup.find_by_path(media):
            # File already exists in backup.

            if copy.last_modification != media.last_modification:
                # File has changed since last backup.
                backup.upload_new_version(media)

        elif copies := backup.find_by_checksum(media):
            # A similar file already exists in backup.

            for copy in copies:
                if copy.last_modification == media.last_modification:
                    # A copy has been made, or the file has been renamed.

                    if Path(directory, copy.original_file).exists():
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


# Custom Objects

class Backup:
    # checksum -> obfuscated_name
    CHECKSUMS_FILENAME = 'checksums.yaml'

    # obfuscated_name -> checksum, file, mtime
    MAPPING_FILENAME = 'files.yaml'

    #: External function to encrypt files in the backup.
    #: No encryption by default.
    encryptor: Callable = (lambda src, dst: dst.write_bytes(src.read_bytes()))

    #: External function to decrypt files in the backup.
    #: No decryption by default.
    decryptor: Callable = (lambda src, dst: dst.write_bytes(src.read_bytes()))

    #: External function to obfuscate file paths in the backup.
    #: No obfuscation by default.
    obfuscator: Callable = (lambda path: path)

    def __init__(
            self,
            object_store: ObjectStore,
            data_container: str,
            metadata_container: str,
            *,
            encryptor: Callable = None,
            decryptor: Callable = None,
            obfuscator: Callable = None,
    ):
        self.object_store = object_store
        self.data_container = data_container
        self.metadata_container = metadata_container
        self.encryptor = encryptor or Backup.encryptor  # type: ignore[assignment]
        self.decryptor = decryptor or Backup.decryptor  # type: ignore[assignment]
        self.obfuscator = obfuscator or Backup.obfuscator  # type: ignore[assignment]

    # Managers

    @contextmanager
    def open(self, **kwargs) -> Iterator[None]:
        """Open backup for further processing.

        All keyword arguments are forwarded to :attr:`.encryptor`
        and :attr:`.decryptor`.

        Metadata gets automatically synchronized after "closing" the backup.

        :raise yaml.YAMLError: when cannot decode metadata files.
        """
        _encryptor = self.encryptor
        _decryptor = self.decryptor
        self.encryptor = partial(self.encryptor, **kwargs)  # type: ignore[assignment]
        self.decryptor = partial(self.decryptor, **kwargs)  # type: ignore[assignment]

        self._files = self.load_files()          # Can raise YAMLError
        self._checksums = self.load_checksums()  # Can raise YAMLError
        log.info("Retrieved backup metadata")

        try:
            yield

        except KeyboardInterrupt:
            log.warning(
                "Backup manually stopped by user "
                "before synchronization had time to complete"
            )

        finally:
            log.info("Backup synchronization has complete")

            mapping_file = self.obfuscate_filepath(self.MAPPING_FILENAME)
            checksums_file = self.obfuscate_filepath(self.CHECKSUMS_FILENAME)

            try:
                with LocalFile('/tmp', self.MAPPING_FILENAME).open('w') as f:
                    yaml.safe_dump(self._files, f)
                    self._upload(f.name, mapping_file, self.metadata_container)

                with LocalFile('/tmp', self.CHECKSUMS_FILENAME).open('w') as f:
                    yaml.safe_dump(self._checksums, f)
                    self._upload(f.name, checksums_file, self.metadata_container)

            except Exception:
                error = "An unexpected error happened while uploading metadata files"
                log.critical(error, exc_info=True)

                # TODO: Handle errors (01/2021)
                # If a backup is run after having been left
                # in an inconsistent state, dupplicate uploads could happen,
                # or attemps to delete vanished files.
                log.critical(
                    "Metadata files have been saved in /tmp. "
                    "You should manually upload them to the backup. "
                    "Otherwise, backup will end up in an inconsistent state. "
                    "Your files are still safe, but errors could happen "
                    "next time you synchronize the backup."
                )

            else:
                log.info("Updated backup metadata")
                LocalFile('/tmp', self.MAPPING_FILENAME).unlink()
                LocalFile('/tmp', self.CHECKSUMS_FILENAME).unlink()

            finally:
                self.encryptor = _encryptor  # type: ignore[assignment]
                self.decryptor = _decryptor  # type: ignore[assignment]
                del self._files
                del self._checksums

    def clean(self) -> None:
        """Archive in backup files deleted from :attr:`.directory`."""
        # TODO: Don't analyze files already found previously (01/2021)

        # FIXME: How to clean files stored on several external hard drives? (01/2021)
        #
        # When doing a single backup for several hard drives, we want files
        # to have a relative path in the backup. But when backuping one drive
        # at a time, it is impossible to detect files which have been deleted.
        # Thus, we deactivate this function for now, as it only works for backups
        # with absolute paths.
        #
        # for name in self._files:
        #     item = BackupItem(name, backup=self)

        #     if not (self.directory / item.original_file).exists():
        #         self.delete(item)

    # Finders

    def find_by_checksum(self, the_file: 'LocalFile') -> List['BackupItem']:
        """Look for files in backup with a similar checksum than `the_file`."""
        items = []

        for obfuscated_name in self._checksums.get(the_file.checksum, []):
            item = BackupItem(obfuscated_name, backup=self)
            items.append(item)

        return items

    def find_by_path(self, the_file: 'LocalFile') -> Optional['BackupItem']:
        """Look for a file in backup with a similar path than `the_file`."""
        obfuscated_name = self.obfuscate_filepath(str(the_file))

        try:
            assert obfuscated_name in self._files
        except AssertionError:
            return None

        return BackupItem(obfuscated_name, backup=self)

    # Actions

    def rename(self, item: 'BackupItem', the_file: 'LocalFile') -> 'BackupItem':
        """Rename file in the backup."""
        assert item.exists(), f"File not in backup: {item.name}"

        obfuscated_name = self.obfuscate_filepath(str(the_file))
        new = self.copy(item, obfuscated_name)
        self.delete(item)

        log.info("Renamed in backup: %s", the_file)

        return new

    def upload(self, the_file: 'LocalFile', replace: bool = False) -> 'BackupItem':
        """Upload new file to the backup.

        :param replace:
            overwrite file if already in backup.
        :raise <SOMETHING>:
            if file already exists in backup and `replace` is `False`.
        """
        # TODO: Properly compute checksum of files > 5GB.
        error = "Cannot backup files bigger than 5gb for now"
        assert the_file.stat().st_size < 5368709120, error

        obfuscated_name = self.obfuscate_filepath(the_file)
        item = BackupItem(obfuscated_name, backup=self)

        if replace:
            # TODO: Check if it overwrites by default (01/2021)
            assert item.exists(), f"File not in backup: {item.name}"
            self.delete(item)

        self._upload(the_file, obfuscated_name)

        # Update metadata.
        if the_file.checksum in self._checksums:
            self._checksums[the_file.checksum].append(obfuscated_name)
        else:
            self._checksums[the_file.checksum] = [obfuscated_name]

        self._files[obfuscated_name] = {
            'checksum': the_file.checksum,
            'file': str(the_file),
            'mtime': the_file.last_modification.timestamp(),
        }

        if replace:
            log.info("Uploaded new version for: %s", the_file)
        else:
            log.info("Uploaded to backup: %s", the_file)

        return item

    def upload_new_version(self, the_file: 'LocalFile') -> 'BackupItem':
        """Update a file in the backup.

        A copy of the previous version is kept for 6 months.
        """
        obfuscated_name = self.obfuscate_filepath(the_file)
        item = BackupItem(obfuscated_name, backup=self)
        assert item.exists(), f"File not in backup: {item.name}"

        # TODO: Properly compute checksum of files > 5GB (01/2021)
        error = "Cannot backup files bigger than 5gb for now: {the_file}"
        assert the_file.stat().st_size < 5368709120, error

        return self.upload(the_file, replace=True)

    # Helpers

    def copy(self, item: 'BackupItem', target: str) -> 'BackupItem':
        assert item.exists(), f"File not in backup: {item.name}"

        run(
            f'swift copy '  # Not yet supported by OpenStack SDK
            f'-d /{self.data_container}/{target} '
            f'{self.data_container} {item.name}',
            check=True,  # TODO: Handle errors and check ETAG (01/2021)
        )
        self._files[target] = self._files[item.name]
        self._checksums[item.checksum].append(target)

        log.info(f"Made new copy in backup from {item.name}: {target}")
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
        self._files.pop(item.name)

        if len(self._checksums[item.checksum]) == 1:
            self._checksums.pop(item.checksum)
        else:
            self._checksums[item.checksum].remove(item.name)

        log.debug("Deleted file from backup: %s", item.name)

    def load_checksums(self):
        checksums_file = self.obfuscate_filepath(self.CHECKSUMS_FILENAME)

        try:
            checksums = self._download(checksums_file, self.metadata_container)
            log.debug("Retrieved checksums file from backup")

        except ResourceNotFound:
            log.warning("Checksums file not found in backup")

            checksums = b''
            self._upload(checksums, checksums_file, self.metadata_container)

            log.info("Created checksums file in backup")

        return yaml.safe_load(checksums) or {}  # Can raise YAMLError

    def load_files(self):
        mapping_file = self.obfuscate_filepath(self.MAPPING_FILENAME)

        try:
            mapping = self._download(mapping_file, self.metadata_container)
            log.debug("Retrieved mapping file from backup")

        except ResourceNotFound:
            log.warning("Mapping file not found in backup")

            mapping = b''
            self._upload(mapping, mapping_file, self.metadata_container)

            log.info("Created mapping file in backup")

        return yaml.safe_load(mapping) or {}  # Can raise YAMLError

    # Petits Cachotiers

    @contextmanager
    def decrypt_file(self, path: 'LocalFile') -> Iterator['LocalFile']:
        decrypted = Path('/tmp', str(uuid.uuid4()))
        self.decryptor(str(path), str(decrypted))

        msg = "Saved decrypted version of %s into temporary file: %s"
        log.debug(msg, path, str(decrypted))

        try:
            yield LocalFile(decrypted)
        finally:
            decrypted.unlink()
            log.debug("Removed temporarily decrypted file: %s", decrypted.name)

    @contextmanager
    def encrypt_file(self, path: 'LocalFile') -> Iterator['LocalFile']:
        encrypted = Path('/tmp', str(uuid.uuid4()))
        self.encryptor(str(path), str(encrypted))

        msg = "Saved encrypted version of %s into temporary file: %s"
        log.debug(msg, path, str(encrypted))

        try:
            yield LocalFile(encrypted)
        finally:
            encrypted.unlink()
            log.debug("Removed temporarily encrypted file: %s", encrypted.name)

    def obfuscate_filepath(self, path: Union[str, Path]) -> str:
        obfuscated = self.obfuscator(str(path))
        log.debug("Obfuscated path for %s: %s", path, obfuscated)
        return obfuscated

    # Private Thingies

    def _download(self, name: str, container: str = None) -> bytes:
        container = container or self.data_container

        with NamedTemporaryFile() as encrypted:
            download = self.object_store.download_object(name, container=container)
            log.debug("Retrieved encrypted data from backup for: %s", name)

            encrypted.write(download)
            encrypted.flush()

            msg = "Wrote encrypted data in temporary file for %s in: %s"
            log.debug(msg, name, encrypted.name)

            # TODO: Verify checksum (01/2021)
            # FIXME: When implementing file restoration, check memory usage (01/2021)
            with self.decrypt_file(LocalFile(encrypted.name)) as decrypted:
                data = decrypted.read_bytes()

        return data

    def _get(self, name: str, container: str = None) -> Object:
        container = container or self.data_container
        metadata = self.object_store.get_object_metadata(name, container)
        log.debug("Retrieved metadata from backup for: %s", name)
        return metadata

    def _upload(
            self,
            something: Union[bytes, str, 'LocalFile'],
            target: str,
            container: str = None) -> Object:
        container = container or self.data_container

        if isinstance(something, bytes):
            log.debug("Received raw data to upload to: %s", target)

            tmp = NamedTemporaryFile()
            tmp.write(something)
            tmp.flush()

            path = LocalFile('/tmp', tmp.name)
            log.debug("Saved raw data for %s into temporary file: %s", target, path)
        else:
            path = cast(LocalFile, something)

        with self.encrypt_file(path) as encrypted:
            while True:
                self.object_store.upload_object(
                    container, target, filename=str(encrypted),
                )
                log.debug("Uploaded file to backup: %s", path)
                upload = self._get(target, container)

                if upload.etag == encrypted.checksum:  # Alles gut!
                    log.debug("Uploaded file is not corrupted: %s", path)

                    if isinstance(something, bytes):
                        tmp.close()
                        log.debug("Removed temporary file: %s", path)

                    return upload

                else:
                    msg = (
                        "Upload not completed successfully. "
                        "Remote copy appears to be corrupted. "
                        "Trying again: %s"
                    )
                    log.warning(msg, path)


class BackupItem:
    def __init__(self, name: str, *, backup: 'Backup'):
        self.name = name
        self.backup = backup

    # Properties

    @property
    def checksum(self) -> str:
        return self.backup._files[self.name]['checksum']

    @property
    def last_modification(self) -> datetime:
        mtime = self.backup._files[self.name]['mtime']
        return datetime.fromtimestamp(mtime, tz=timezone.utc)

    @property
    def original_file(self) -> str:
        return self.backup._files[self.name]['file']

    # Methods

    def exists(self) -> bool:
        return self.name in self.backup._files


class LocalFile:
    # FIXME: Cannot simply inherit from Path (01/2021)
    # AttributeError: type object 'LocalFile' has no attribute '_flavour
    # And many other errors...

    def __init__(self, *args, **kwargs):
        self._path = Path(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._path, name)

    def __repr__(self) -> str:
        return repr(self._path)

    def __str__(self) -> str:
        return str(self._path)

    @cached_property
    def checksum(self) -> str:
        # Thanks to https://stackoverflow.com/a/3431838/2987526
        md5sum = hashlib.md5()

        with self._path.open('rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5sum.update(chunk)

        return md5sum.hexdigest()

    @property
    def last_modification(self) -> datetime:
        return datetime.fromtimestamp(self._path.stat().st_mtime, tz=timezone.utc)


# Helper Functions

def encrypt_with_gpg(src: str, dst: str, *, recipient: str) -> None:
    cli = f'gpg -e -r {recipient} -o {dst} {src}'
    run(cli.split(' '), check=True)


def decrypt_with_gpg(src: str, dst: str, **kwargs) -> None:
    cli = f'gpg -d -o {dst} {src}'
    run(cli.split(' '), check=True)


def obfuscate_with_blake2b(path: str) -> str:
    return hashlib.blake2b(path.encode()).hexdigest()


# Script

if __name__ == '__main__':
    directory = sys.argv[1]
    data_container = f'{sys.argv[2]}-data'
    metadata_container = f'{sys.argv[2]}-metadata'
    gpg_key = sys.argv[3]

    # Display log messages to console.
    console = logging.StreamHandler()
    log_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console.setFormatter(log_format)
    log.addHandler(console)
    log.setLevel(logging.INFO)

    print("Starting backup...")

    # Run backup.
    backup = retrieve_backup(data_container, metadata_container)

    with backup.open(recipient=gpg_key):
        synchronize(directory, backup)

    print("See you next time!")
