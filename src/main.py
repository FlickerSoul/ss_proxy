from __future__ import annotations

import argparse
from typing import Type

from __doc__ import *
from client import ClientHandler, SocksClient
from server import SocksServer, ServerHandler
from utils import ServerConfig, RemoteClientConfig, LocalClientConfig, Server, Handler, output_error_exc, get_logger, \
    set_default_level


def main() -> None:
    parser = argparse.ArgumentParser(description=__description__)
    parser.add_argument('type',
                        choices=['server', 'remote_client', 'local_client'],
                        type=str,
                        default='server')
    parser.add_argument('--level', '-l', choices=['info', 'debug', 'warn', 'error'], type=str)

    parser.add_argument('--version', action='version', version=f'{__title__} {__version__}')

    args: argparse.Namespace = parser.parse_args()

    set_default_level(args.level)

    logger = get_logger('main')

    server_type: str = args.type
    logger.info(f'launch {server_type}')

    launcher_cls: Type[Server]
    launcher_handler: Type[Handler]
    launcher_config_cls: Type[argparse.Namespace]

    if args.type == 'server':
        launcher_cls = SocksServer
        launcher_handler = ServerHandler
        launcher_config_cls = ServerConfig
    elif server_type.endswith('client'):
        launcher_cls = SocksClient
        launcher_handler: Type[ClientHandler] = ClientHandler
        if server_type == 'remote_client':
            launcher_config_cls = RemoteClientConfig
        elif server_type == 'local_client':
            launcher_config_cls = LocalClientConfig
        else:
            logger.error(f'unknown client type: {server_type}')
            raise
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
