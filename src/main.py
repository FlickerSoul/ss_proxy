from __future__ import annotations

import argparse
import importlib
import sys
from typing import Type

from __doc__ import *
from client import ClientHandler, SocksClient
from server import SocksServer, ServerHandler
from utils import Server, Handler, output_error_exc, get_logger, \
    set_default_level
from configs import ConfigBase, ServerConfig, RemoteClientConfig, LocalClientConfig


def _config_import(config_name: str) -> Type[ConfigBase]:
    config_name = config_name.strip()
    config_info = config_name.rsplit('.', maxsplit=1)
    if len(config_info) == 1:
        config_path, config_class = 'configs', config_name
    else:
        config_path, config_class = config_info
    try:
        module = importlib.import_module(config_path)
        target_class = getattr(module, config_class)

        del module
        del sys.modules[config_class]

        return target_class
    except ImportError as e:
        print(f'cannot import config from {config_path}.py since {e}')
        raise
    except AttributeError as e:
        print(f'cannot find attribute {config_class}. Error: {e}')
        raise
    except Exception as e:
        print(f'unknown error during importing config {config_name}. Error: {e}')
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__description__)
    parser.add_argument('type',
                        choices=['server', 'client'],
                        type=str,
                        default='server')
    parser.add_argument('--config', '-c', type=str, default='')
    parser.add_argument('--level', '-l',
                        choices=['info', 'debug', 'warn', 'error'],
                        type=str,
                        default='info')

    parser.add_argument('--version', action='version', version=f'{__title__} {__version__}')

    args: argparse.Namespace = parser.parse_args()

    set_default_level(args.level)

    logger = get_logger('main')

    server_type: str = args.type
    server_config: str = args.config
    logger.info(f'launch {server_type}')

    launcher_cls: Type[Server]
    launcher_handler: Type[Handler]
    launcher_config_cls: Type[ConfigBase]

    if args.type == 'server':
        launcher_cls = SocksServer
        launcher_handler = ServerHandler
        if server_config == '':
            launcher_config_cls = ServerConfig
        else:
            launcher_config_cls = _config_import(server_config)
    elif server_type == 'client':
        launcher_cls = SocksClient
        launcher_handler: Type[ClientHandler] = ClientHandler
        if server_config == 'local_client' or server_config == '':
            launcher_config_cls = LocalClientConfig
        elif server_config == 'remote_client':
            launcher_config_cls = RemoteClientConfig
        else:
            launcher_config_cls = _config_import(server_config)
        launcher_handler.socks_server_addr = launcher_config_cls.address
        launcher_handler.socks_server_port = launcher_config_cls.port
    else:
        logger.error(f'unrecognized type {args.type}')
        raise

    logger.info(f'launcher type: {launcher_cls}')
    logger.info(f'launcher config type: {launcher_config_cls}')
    logger.info(f'launcher handler type: {launcher_handler}')

    try:
        config = launcher_config_cls(launcher_handler)
        launcher = launcher_cls(config)
        logger.info(f'started server at {""}:{config.local_port}')
        launcher.run_server()
    except KeyboardInterrupt:
        logger.error('Key board interrupted')
        output_error_exc(logger)
    except Exception as err:
        logger.error(f'error {err} occurs.')
    finally:
        logger.info('server stopped')


if __name__ == '__main__':
    main()
