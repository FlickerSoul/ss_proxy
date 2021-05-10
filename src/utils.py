from __future__ import annotations

import abc
import argparse
import enum
import logging
import selectors
import socket
import threading
from selectors import DefaultSelector
from typing import Any, List, Tuple, Type


class CommandType(enum.IntEnum):
    """socks5 commands
    turns out not to be super helpful
    o  CMD
     o  CONNECT X'01'
     o  BIND X'02'
     o  UDP ASSOCIATE X'03'
    """
    connect = 0x01
    bind = 0x02
    udp = 0x03


class AddrType(enum.IntEnum):
    """socks5 address types
    o  ATYP   address type of following address
     o  IP V4 address: X'01'
     o  DOMAINNAME: X'03'
     o  IP V6 address: X'04'
    """
    ipv4 = 0x01
    domain = 0x03
    ipv6 = 0x04


class ReplyType(enum.IntEnum):
    """sockst reply types
    only used some of them, not supper helpful here
    o  REP    Reply field:
     o  X'00' succeeded
     o  X'01' general SOCKS server failure
     o  X'02' connection not allowed by ruleset
     o  X'03' Network unreachable
     o  X'04' Host unreachable
     o  X'05' Connection refused
     o  X'06' TTL expired
     o  X'07' Command not supported
     o  X'08' Address type not supported
     o  X'09' to X'FF' unassigned
    """
    succeed = 0x00
    general_failure = 0x01
    con_not_allowed = 0x02
    network_unreachable = 0x03
    host_unreachable = 0x04
    connection_refuse = 0x05
    ttl_expired = 0x06
    command_not_supported = 0x07
    addr_type_not_supported = 0x08
    ff_unassigned = 0x09


class _LoggingMapping(enum.Enum):
    """used to set logger level"""
    debug = logging.DEBUG
    info = logging.INFO
    warn = logging.WARN
    error = logging.ERROR


class LoggerHelper:
    """logger wrapper"""
    default_level: int = logging.INFO

    @classmethod
    def set_default_level(cls, level_name: str) -> None:
        cls.default_level = getattr(_LoggingMapping, level_name, _LoggingMapping.info).value

    @classmethod
    def get_logger(cls,
                   name: str,
                   level: int = None,
                   handler: logging.Handler = logging.StreamHandler()) -> logging.Logger:
        """get a new logger by specifying the name"""
        logger = logging.getLogger(name)
        if level is None:
            logger.setLevel(cls.default_level)
        else:
            logger.setLevel(level)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger


# some helpful alias
get_logger = LoggerHelper.get_logger
set_default_level = LoggerHelper.set_default_level


class Server:
    """The client and proxy server"""
    def __init__(self, args: argparse.Namespace = None):
        self.logger = get_logger('server')
        self.address_family = args.address_family
        self.socket_type = args.socket_type
        self.socket_address = args.address
        self.remote_port = args.port
        self.local_port = args.local_port
        self.socket_client_num: int = args.client_num

        self.handler: Type[Handler] = args.handler

        self.socket: socket.socket = self.init_socket()

        self.shut_down_event: threading.Event = threading.Event()
        self.shut_down: bool = False

        self.threads: List[threading.Thread] = []
        self.blocking: bool = args.blocking

        self.logger.debug(f'init {self}')

    def __str__(self):
        return f'server to {self.socket_address}:{self.remote_port}'

    def init_socket(self) -> socket.socket:
        """initialize socket instance
        set up a socket to listen to the 127.0.0.1:<local_port>
        so that this handles requests from socks5 protocol or client
        """
        s = socket.socket(self.address_family, self.socket_type)
        s.bind(('', self.local_port))
        self.logger.debug(f'socket bonded port {self.local_port}')
        s.listen(self.socket_client_num)
        return s

    def close_socket(self) -> None:
        """close socket"""
        if self.socket:
            self.socket.close()

    def join_threads(self) -> None:
        """wait for threads to stop"""
        for t in self.threads:
            t.join()

    def stop_server(self) -> None:
        """coroutine to stop the server
        not useful in the current application though
        """
        self.shut_down = True
        self.shut_down_event.wait()

    def fileno(self) -> int:
        """to be used with selector"""
        return self.socket.fileno()

    def run_server(self, interval: float = 0.5) -> None:
        """run server"""
        self.shut_down_event.clear()
        try:
            with DefaultSelector() as selector:
                selector.register(self, selectors.EVENT_READ)

                while not self.shut_down:
                    read_list = selector.select(interval)
                    if read_list:
                        self.handle_request()
        finally:
            self.shut_down = False
            self.shut_down_event.set()

    def accept_client(self) -> Tuple[socket.socket, Any]:
        return self.socket.accept()

    @staticmethod
    def close_client(client: socket.socket) -> None:
        """close the server socket"""
        # client.shutdown(socket.SHUT_WR)
        client.close()

    def handle_request(self) -> None:
        """handler for accepting client request"""
        try:
            client, client_addr = self.accept_client()
            self.logger.debug(f'accepted client {client.getpeername()} at {client_addr}')
        except socket.error as e:
            self.logger.error(f'socket error when accepting new client {e}')
            return

        t = threading.Thread(
            target=self._thread_helper,
            args=(client, client_addr)
        )
        self.threads.append(t)
        t.start()
        self.logger.info(f'started handler thread for client {client_addr}')

    def _thread_helper(self, client: socket.socket, client_addr: Tuple) -> None:
        try:
            self.logger.info('start handling')
            self.handler(client, client_addr).handle()
        except Exception as e:
            self.logger.error(f'error {e} occurred when talking to client {client_addr}')
            output_error_exc(self.logger)
        finally:
            self.close_client(client)
            self.logger.debug(f'closed client {client_addr}')


class Handler:
    def __init__(self, client: socket.socket, client_addr: Any) -> None:
        self.logger = get_logger('handler')
        self.client = client
        self.client_addr = client_addr

    @abc.abstractmethod
    def _handle(self) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def generate_remote(self, addr_info: Tuple, family_type: int = socket.AF_INET) -> socket.socket:
        raise NotImplementedError

    def connect(self, remote, interval: float = 0.5) -> None:
        """transport data
        self.client <-> remote

        As a proxy client, the  self.client is a connection to
        local application connected with socks5 protocol
        and remote is the proxy server

        As a proxy server, the self.client is a connection to
        the proxy client and remote is the target server specified
        in DST.ADDR and DST.PORT
        """
        try:
            self.logger.debug(f'connect client {self.client.getsockname()} -> {self.client.getpeername()}')
            self.logger.debug(f'connect remote {remote.getsockname()} -> {remote.getpeername()}')

            with DefaultSelector() as selector:
                # register both sockets in select
                selector.register(self.client, selectors.EVENT_READ)
                selector.register(remote, selectors.EVENT_READ)

                while True:
                    # wait for the system call
                    read = tuple(c[0].fileobj for c in selector.select(interval))

                    self.logger.debug(f'read descriptors: {read}')

                    # transport client data to remote
                    if self.client in read:
                        data = self.client.recv(4096)
                        self.logger.debug(f'read client: {data}')
                        if len(data) <= 0:
                            self.logger.debug('client break')
                            break
                        result = remote.sendall(data)
                        self.logger.debug(f'send remote: {data}')
                        if result is not None:
                            raise Exception('failed to send data to remote')

                    # transport remote data to client
                    if remote in read:
                        data = remote.recv(4096)
                        self.logger.debug(f'read remote: {data}')
                        if len(data) <= 0:
                            self.logger.debug('client break')
                            break
                        result = self.client.sendall(data)
                        self.logger.debug(f'send client: {data}')
                        if result is not None:
                            raise Exception('failed to send data to client')
        finally:
            self.client.close()
            remote.close()

    def handle(self):
        try:
            self._handle()
        finally:
            self.logger.info(f"handled {self.client_addr}")


def output_error_exc(lgr: logging.Logger) -> None:
    import traceback
    lgr.error("error traceback: ")
    lgr.error(traceback.format_exc())


class ConfigBase(argparse.Namespace):
    def __init__(self):
        super(ConfigBase, self).__init__()


class ServerConfig(ConfigBase):
    address_family = socket.AF_INET
    socket_type = socket.SOCK_STREAM
    address = ''
    port = 0
    local_port = 12344
    client_num = 5
    blocking = False

    def __init__(self, handler: Type[Handler]):
        super(ServerConfig, self).__init__()
        self.handler = handler


class LocalClientConfig(ConfigBase):
    address_family = socket.AF_INET
    socket_type = socket.SOCK_STREAM
    address = ''
    port = 12344
    local_port = 7690
    client_num = 5
    blocking = False

    def __init__(self, handler: Type[Handler]) -> None:
        super(LocalClientConfig, self).__init__()
        self.handler = handler


class RemoteClientConfig(ConfigBase):
    address_family = socket.AF_INET
    socket_type = socket.SOCK_STREAM
    address = 'freedom.flicker-soul.me'
    port = 12344
    local_port = 7790
    client_num = 5
    blocking = False

    def __init__(self, handler: Type[Handler]):
        super(RemoteClientConfig, self).__init__()
        self.handler = handler
