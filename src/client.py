from __future__ import annotations

import logging
import struct
import socket
from typing import Tuple, Optional

from utils import Server, Handler, ClientConfig, ReplyType, AddrType, CommandType


class SocksClient(Server):
    pass


class ClientHandler(Handler):
    socks_server_addr = None
    socks_server_port = None
    ipv6_flag: bool = False

    default_addr: bytes = socket.inet_aton('0.0.0.0')
    handshake_pack_format: str = 'BB'

    def write(self, fmt, *args) -> None:
        send_data = struct.pack(fmt, *args)

        self.client.send(
            send_data
        )

        logging.debug(
            f'send data via send: {send_data}'
        )

    def reply(self,
              code: ReplyType,
              address_type: AddrType = AddrType.ipv4,
              addr: bytes = default_addr,
              port: int = 0) -> None:

        logging.debug(f'reply code {code}, addr type: {address_type}, addr: {addr}, port: {port}')
        self.write(
            '!BBBB',  0x05, code, 0x00, address_type.value
        )
        self.client.send(addr)
        self.write('!H', port)

    def handshake(self) -> bool:

        handshake_data = self.client.recv(struct.calcsize(self.handshake_pack_format))

        try:
            version, method_len = struct.unpack(
                self.handshake_pack_format, handshake_data
            )
            logging.debug(f'got handshake data, ver: {version}, method len: {method_len}')
        except struct.error:
            self.reply(
                ReplyType.general_failure
            )
            return False

        if version != 0x05:
            self.reply(
                ReplyType.connection_refuse
            )
            logging.error(f'not socks5')
            return False

        self.client.recv(method_len)

        self.write(
            'BB', 0x05, 0x00
        )
        logging.debug(f'replied handshake')

        return True

    def get_request(self) -> Optional[Tuple[Tuple[str, int], bytes]]:
        logging.debug('start getting request')
        data: bytes = self.client.recv(4)
        ver, cmd, _, addr_type = struct.unpack('BBBB', data)

        logging.debug(
            f'request data, ver: {ver}, cmd: {cmd}, addr type: {addr_type}'
        )

        if cmd != CommandType.connect:
            self.reply(
                ReplyType.command_not_supported
            )
            logging.error(f'command is not CONNECT')
            return None

        addr_to_send: bytes = data[3:]

        if addr_type == AddrType.ipv4:
            addr_ip: bytes = self.read_file.read(4)
            addr = socket.inet_ntoa(addr_ip)
            addr_to_send += addr_ip
            logging.debug('is ipv4')
        elif addr_type == AddrType.domain:
            addr_len: bytes = self.read_file.read(1)
            addr = self.read_file.read(ord(addr_len))
            addr_to_send += addr_len + addr
            logging.debug('is domain name')
        elif addr_type == AddrType.ipv6:
            addr_ip = self.read_file.read(16)
            addr = socket.inet_ntoa(addr_ip)
            addr_to_send += addr_ip
            logging.debug('is ipv6')
        else:
            logging.error('address type not supported')
            return None

        addr_port = self.read_file.read(2)

        addr_to_send += addr_port

        port = struct.unpack('>H', addr_port)[0]

        logging.debug(f'got port {port}')

        self.reply(
            ReplyType.succeed
        )
        logging.debug('replied succeed')

        return (
            (addr, port), addr_to_send
        )

    def generate_remote(self, addr_info: Tuple) -> socket.socket:
        if self.ipv6_flag:
            remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        remote.settimeout(None)
        remote.connect(addr_info)
        return remote

    def handle(self) -> None:
        try:
            status = self.handshake()
            if not status:
                raise
            logging.debug('finished handshake')

            request_feedback = self.get_request()
            if request_feedback is None:
                raise

            connect_dest, request_bytes = request_feedback
            logging.debug('finished getting request')

            try:
                # reply immediately
                remote = self.generate_remote((self.socks_server_addr, self.socks_server_port))
                # remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                # self.send_encrypt(remote, addr_to_send)
                remote.send(request_bytes)
            except socket.error as e:
                logging.error(e)
                return
            logging.info(f'connecting {connect_dest}')
            self.connect(self.client, remote)
        except socket.error as e:
            logging.error(e)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    config = ClientConfig(ClientHandler)

    try:
        ClientHandler.socks_server_addr = config.address
        ClientHandler.socks_server_port = config.port
        server = SocksClient(config)
        logging.info(
            f':{config.local_port} -> {ClientHandler.socks_server_addr}:{ClientHandler.socks_server_port}'
        )
        server.run_server()
    except KeyboardInterrupt:
        logging.info('Key board interrupted')
    except socket.error as err:
        logging.error(f'error "{err}" occurs.')
        import traceback
        traceback.print_exc()
    finally:
        logging.info('server stopped')
