from __future__ import annotations

import struct
import socket
from typing import Tuple, Optional

from utils import Server, Handler, ReplyType, AddrType, CommandType, \
    output_error_exc, get_logger, set_default_level

from configs import RemoteClientConfig, LocalClientConfig


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

        self.client.sendall(send_data)

        self.logger.debug(f'send data via send: {send_data}')

    def reply(self,
              code: ReplyType,
              address_type: AddrType = AddrType.ipv4,
              addr: bytes = default_addr,
              port: int = 0) -> None:
        """reply socks5 request, only handles TCP CONNECT in use
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        """

        self.logger.debug(f'reply code {code}, addr type: {address_type}, addr: {addr}, port: {port}')
        self.write('!BBBB',  0x05, code, 0x00, address_type.value)
        self.client.send(addr)
        self.write('!H', port)

    def handshake(self) -> bool:
        """handshake request and response
        response format;
        method is always 0x00 since we're not using authentication here
         +----+--------+
         |VER | METHOD |
         +----+--------+
         | 1  |   1    |
         +----+--------+
        """

        handshake_data = self.client.recv(struct.calcsize(self.handshake_pack_format))

        try:
            version, method_len = struct.unpack(
                self.handshake_pack_format, handshake_data
            )
            self.logger.debug(f'got handshake data, ver: {version}, method len: {method_len}')
        except struct.error as e:
            self.reply(ReplyType.general_failure)
            self.logger.error(f'unpack handshake data error: {e}')
            return False

        if version != 0x05:
            self.reply(ReplyType.connection_refuse)
            self.logger.error(f'connection is not socks5')
            return False

        self.client.recv(method_len)

        self.write('BB', 0x05, 0x00)
        self.logger.debug(f'accepted handshake')

        return True

    def get_request(self) -> Optional[Tuple[Tuple[str, int], bytes]]:
        """get socks request
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        :return None if connection failed, (addr_info, server_request_header)
                where the addr_info is a tuple (DST.ADDR, DST.PORT)
                and proxy_server_bytes is
                +------+----------+----------+
                | ATYP | DST.ADDR | DST.PORT |
                +------+----------+----------+
                |  1   | Variable |    2     |
                +------+----------+----------+
        """
        self.logger.debug('start getting request')
        data: bytes = self.client.recv(4)
        ver, cmd, _, addr_type = struct.unpack('BBBB', data)

        self.logger.debug(
            f'request data, ver: {ver}, cmd: {cmd}, addr type: {addr_type}'
        )

        if cmd != CommandType.connect:
            self.reply(ReplyType.command_not_supported)
            self.logger.error(f'command is not CONNECT')
            return None

        server_request_header: bytes = bytes([addr_type])

        if addr_type == AddrType.ipv4:
            raw_addr: bytes = self.client.recv(4)
            addr = socket.inet_ntoa(raw_addr)
            server_request_header += raw_addr
            self.logger.debug(f'{raw_addr} ({addr}) is ipv4')
        elif addr_type == AddrType.ipv6:
            raw_addr = self.client.recv(16)
            addr = socket.inet_ntop(socket.AF_INET6, raw_addr)
            server_request_header += raw_addr
            self.logger.debug(f'{raw_addr} ({addr}) is ipv6')
        elif addr_type == AddrType.domain:
            addr_len: bytes = self.client.recv(1)
            addr = raw_addr = self.client.recv(ord(addr_len))
            server_request_header += addr_len + raw_addr
            self.logger.debug(f'{raw_addr} is domain name')
        else:
            self.logger.error('address type not supported')
            return None

        addr_port = self.client.recv(2)

        server_request_header += addr_port

        port = struct.unpack('>H', addr_port)[0]

        self.logger.debug(f'got port {port}')

        self.reply(ReplyType.succeed)
        self.logger.debug('request accepted')

        return (
            (addr, port), server_request_header
        )

    def generate_remote(self, addr_info: Tuple, family_type: int = socket.AF_INET) -> socket.socket:
        """use addr_info to generate remote connection to proxy server"""
        remote = socket.socket(family_type, socket.SOCK_STREAM)
        remote.settimeout(None)
        remote.connect(addr_info)
        return remote

    def _handle(self) -> None:
        """handles the proxy server connection and data transfer"""
        try:
            # socks5 handshake
            status = self.handshake()
            if not status:
                raise Exception('handshake failed')
            self.logger.debug('finished handshake')

            # socks5 request parsing
            request_feedback = self.get_request()
            if request_feedback is None:
                raise Exception('request handling failed')

            connect_dest, request_bytes = request_feedback
            self.logger.debug('finished getting request')
            self.logger.debug(f'request bytes: {request_bytes}')

            try:
                # always connect to proxy server and send header
                remote = self.generate_remote((self.socks_server_addr, self.socks_server_port))
                remote.send(request_bytes)
            except socket.error as e:
                self.logger.error(f'failed to talk to remote server: {e})')
                output_error_exc(self.logger)
                return
            self.logger.info(f'connecting {connect_dest}')
            self.connect(remote)
        except socket.error as e:
            self.logger.error(f'socket error happened: {e}')
            output_error_exc(self.logger)


if __name__ == '__main__':
    set_default_level('debug')
    
    logger = get_logger('client_main')
    is_remote = False
    if is_remote:
        config = RemoteClientConfig(ClientHandler)
    else:
        config = LocalClientConfig(ClientHandler)

    try:
        ClientHandler.socks_server_addr = config.address
        ClientHandler.socks_server_port = config.port
        server = SocksClient(config)
        logger.info(
            f':{config.local_port} -> {ClientHandler.socks_server_addr}:{ClientHandler.socks_server_port}'
        )
        server.run_server()
    except KeyboardInterrupt:
        logger.info('Key board interrupted')
    except socket.error as err:
        logger.error(f'error "{err}" occurs.')
        output_error_exc(logger)
    finally:
        logger.info('server stopped')
