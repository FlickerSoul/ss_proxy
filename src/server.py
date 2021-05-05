from __future__ import annotations

import socket
import struct
import logging
from typing import Tuple

from utils import AddrType, Handler, Server, ServerConfig


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
            addr = socket.inet_ntoa(self.read_file.read(4))
            logging.debug('is ipv4')
        elif address_type == AddrType.ipv6:
            addr = socket.inet_ntop(socket.AF_INET6, self.read_file.read(16))
            logging.debug('is ipv6')
        elif address_type == AddrType.domain:
            length = ord(self.client.recv(1))
            addr = self.read_file.read(length)
            logging.debug('is domain name')
        else:
            logging.error('addr type not supported')
            return

        port = struct.unpack('>H', self.read_file.read(2))[0]
        logging.debug(f'got port {port}')

        try:
            remote = self.generate_remote((addr, port))
            self.connect(remote)
        except socket.error as e:
            logging.error(e)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    config = ServerConfig(ServerHandler)

    try:
        server = SocksServer(config)
        print(f'started server at {""}:{config.local_port}')
        server.run_server()
    except socket.error as err:
        print(f'error {err} occurs.')

    except KeyboardInterrupt:
        print('Key board interrupted')
    finally:
        print('server stopped')
