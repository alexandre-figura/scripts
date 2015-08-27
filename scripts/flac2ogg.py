#!/usr/bin/env python

"""
A script to convert Flac files to Ogg Vorbis.

Requirements:

- Python >= 3.4
- Oggenc

"""

import argparse
import multiprocessing
import pathlib
import subprocess


def convert_to_ogg_vorbis(source_file, dest_dir, quality):
    """Convert a music file to Ogg Vorbis with the encoder Oggenc.

    :param source_file: path of the file to convert. Must be a ``pathlib.Path``
                        instance.
    :param dest_dir: destination directory for the converted file. Must be a
                     ``pathlib.Path`` instance.
    :param quality: encoding quality (see Oggenc's documentation).
    :return: the status code returned by Oggenc.
    """
    dest_file = (dest_dir / source_file.name).with_suffix('.ogg')
    command = ('oggenc', '-q', str(quality), '-o', str(dest_file),
               str(source_file))
    return subprocess.call(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
            description='Convert Flac files to Ogg Vorbis.')
    parser.add_argument(
            'source_dir',
            help='Source directory.')
    parser.add_argument(
            'dest_dir',
            help='Destination directory.')
    parser.add_argument(
            '-q', '--quality',
            type=int, choices=range(-1, 11), default=5,
            help='Encoding quality.')
    parser.add_argument(
            '-p', '--proc',
            type=int, default=1,
            help='Number of parallel processes to use for conversion.')
    args = parser.parse_args()

    source_dir, dest_dir = (pathlib.Path(dir)
                            for dir in (args.source_dir, args.dest_dir))
    flac_files = source_dir.rglob('*.flac')

    if not dest_dir.is_dir():
        dest_dir.mkdir(parents=True)

    with multiprocessing.Pool(args.proc) as pool:
        for f in flac_files:
            pool.apply_async(convert_to_ogg_vorbis,
                             args=(f, dest_dir, args.quality))
        pool.close()
        pool.join()
