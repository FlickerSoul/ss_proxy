from __future__ import annotations


import argparse
import enum
import json
import logging
import pathlib

from __doc__ import *


class _LoggingMapping(enum.Enum):
    debug = logging.DEBUG
    info = logging.INFO
    warn = logging.WARN
    error = logging.ERROR
    critical = logging.CRITICAL


def main() -> None:
    parser = argparse.ArgumentParser(description=__description__)
    parser.add_argument('type', dest='type', choices=['server', 'client'], type=str, default='server')
    parser.add_argument('-c',
                        dest='config_file',
                        type=pathlib.Path,
                        default=pathlib.Path(__file__).parent / 'conf.json')
    parser.add_argument('--version', action='version', version=f'{__title__} {__version__}')

    args: argparse.Namespace = parser.parse_args()
    config_file: pathlib.Path = args.config_file
    if not config_file.is_file():
        logging.error(f'configuration {config_file} is not a file.')
        logging.error('exit')
        exit(1)

    logging.info(f'Got configuration path {config_file}.')

    with open(config_file) as file:
        try:
            config_file = json.load(file)
        except json.JSONDecodeError:
            logging.error(f'Cannot parse json file {config_file}')
            exit(1)
