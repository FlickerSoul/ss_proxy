from __future__ import annotations

import socket
import struct
from typing import Tuple

from utils import AddrType, Handler, Server, output_error_exc, get_logger, set_default_level
from configs import ServerConfig


class SocksServer(Server):
    pass


class ServerHandler(Handler):
    def generate_remote(self, addr_info: Tuple, family_type: int = socket.AF_INET) -> socket.socket:
        self.logger.debug(f'family type: {family_type}, connection info: {addr_info}')
        remote = socket.socket(family_type, socket.SOCK_STREAM)
        remote.connect(addr_info)
        self.logger.debug(f'established')
        return remote

    def _handle(self) -> None:
        address_type = ord(self.client.recv(1))

        if address_type == AddrType.ipv4:
            data = self.client.recv(4)
            addr = socket.inet_ntoa(data)
            self.logger.debug(f'{data} ({addr}) is ipv4')
            family = socket.AF_INET
        elif address_type == AddrType.ipv6:
            data = self.client.recv(16)
            addr = socket.inet_ntop(socket.AF_INET6, data)
            self.logger.debug(f'{data} ({addr}) is ipv6')
            family = socket.AF_INET6
        elif address_type == AddrType.domain:
            length = ord(self.client.recv(1))
            addr = self.client.recv(length)
            self.logger.debug(f'{addr} is domain name')
            family = socket.AF_INET
        else:
            self.logger.error('addr type not supported')
            return

        port = struct.unpack('>H', self.client.recv(2))[0]
        self.logger.debug(f'got port {port}')

        try:
            self.logger.info(f'generating remote socket')
            remote = self.generate_remote((addr, port), family)
            self.logger.info(f'connecting {(addr, port)}')
            self.connect(remote)
        except socket.error as e:
            self.logger.error(e)
            output_error_exc(self.logger)


if __name__ == '__main__':
    set_default_level('debug')
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
