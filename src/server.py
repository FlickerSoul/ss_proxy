from __future__ import annotations

import socket
import struct
import logging
from typing import Tuple

from utils import AddrType, Handler, Server, ServerConfig, output_error_exc, get_logger


class SocksServer(Server):
    pass


class ServerHandler(Handler):
    def generate_remote(self, addr_info: Tuple) -> socket.socket:
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect(addr_info)
        return remote

    def handle(self) -> None:
        address_type = ord(self.client.recv(1))

        if address_type == AddrType.ipv4:
            data = self.read_file.read(4)
            self.logger.debug(f'{data} is ipv4')
            addr = socket.inet_ntoa(data)
        elif address_type == AddrType.ipv6:
            data = self.read_file.read(16)
            self.logger.debug(f'{data} is ipv6')
            addr = socket.inet_ntop(socket.AF_INET6, data)
        elif address_type == AddrType.domain:
            length = ord(self.client.recv(1))
            addr = self.read_file.read(length)
            self.logger.debug(f'{addr} is domain name')
        else:
            self.logger.error('addr type not supported')
            return

        port = struct.unpack('>H', self.read_file.read(2))[0]
        self.logger.debug(f'got port {port}')

        try:
            remote = self.generate_remote((addr, port))
            self.logger.info(f'connecting {(addr, port)}')
            self.connect(remote)
        except socket.error as e:
            self.logger.error(e)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    config = ServerConfig(ServerHandler)

    logger = get_logger('server_main')

    try:
        server = SocksServer(config)
        logger.info(f'started server at {""}:{config.local_port}')
        server.run_server()
    except socket.error as err:
        logger.error(f'error {err} occurs.')
    except KeyboardInterrupt:
        logger.error('Key board interrupted')
        output_error_exc(logger)
    finally:
        logger.info('server stopped')
