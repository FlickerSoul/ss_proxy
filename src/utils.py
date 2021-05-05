from __future__ import annotations

import abc
import argparse
import enum
import logging
import select
import selectors
import socket
import threading
from selectors import PollSelector
from typing import Any, BinaryIO, Callable, List, Tuple, Optional


class CommandType(enum.IntEnum):
    """
    o  CMD
     o  CONNECT X'01'
     o  BIND X'02'
     o  UDP ASSOCIATE X'03'
    """
    connect = 0x01
    bind = 0x02
    udp = 0x03


class AddrType(enum.IntEnum):
    """
    o  ATYP   address type of following address
     o  IP V4 address: X'01'
     o  DOMAINNAME: X'03'
     o  IP V6 address: X'04'
    """
    ipv4 = 0x01
    domain = 0x03
    ipv6 = 0x04


class ReplyType(enum.IntEnum):
    """
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


class Server:
    def __init__(self, args: argparse.Namespace = None):
        self.address_family = args.address_family
        self.socket_type = args.socket_type
        self.socket_address = args.address
        self.socket_port = args.port
        self.socket_client_num: int = args.client_num

        self.handler: Callable = args.handler

        self.socket: socket.socket = self.init_socket()

        self.shut_down_event: threading.Event = threading.Event()
        self.shut_down: bool = False

        self.threads: List[threading.Thread] = []
        self.blocking: bool = args.blocking

    def init_socket(self) -> socket.socket:
        s = socket.socket(self.address_family, self.socket_type)
        # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print(self.socket_address)
        s.bind(
            (self.socket_address, self.socket_port)
        )
        s.listen(self.socket_client_num)

        return s

    def close_socket(self) -> None:
        if self.socket:
            self.socket.close()

    def join_threads(self) -> None:
        for t in self.threads:
            t.join()

    def stop_server(self) -> None:
        self.shut_down = True
        self.shut_down_event.wait()

    def fileno(self) -> int:
        return self.socket.fileno()

    def run_server(self) -> None:
        self.shut_down_event.clear()
        try:
            with PollSelector() as selector:
                selector.register(self, selectors.EVENT_READ)

                while not self.shut_down:
                    has_request = selector.select()
                    if has_request:
                        self.handle_request()
        finally:
            self.shut_down = False
            self.shut_down_event.set()

    def accept_client(self) -> Tuple[socket.socket, Any]:
        return self.socket.accept()

    @staticmethod
    def close_client(client: socket.socket) -> None:
        # client.shutdown(socket.SHUT_WR)
        client.close()

    def handle_request(self) -> None:
        try:
            client, client_addr = self.accept_client()
            logging.debug(f'accepted client {client.getpeername()} at {client_addr}')
        except socket.error as e:
            logging.error(f'encountered socket error {e}')
            return

        t = threading.Thread(
            target=self._thread_helper,
            args=(client, client_addr)
        )
        self.threads.append(t)
        t.start()
        logging.info('started handler thread')

    def _thread_helper(self, client: socket.socket, client_addr: Tuple) -> None:
        try:
            self.handler(client, client_addr, self)()
        except Exception as e:
            logging.debug(f'error {e} occurred when talking to client {client_addr}')
            import traceback
            traceback.print_exc()
        finally:
            self.close_client(client)
            logging.debug(f'closed client {client_addr}')


class Handler:
    def __init__(self, client: socket.socket, client_addr: Any, server: Server) -> None:
        self.client = client
        self.client_addr = client_addr
        self.server = server
        self.read_file: Optional[BinaryIO] = None
        self.write_file: Optional[BinaryIO] = None

    def init(self) -> None:
        self.read_file: BinaryIO = self.client.makefile('rb')
        self.write_file: BinaryIO = self.client.makefile('wb')

    @abc.abstractmethod
    def handle(self) -> None:
        raise NotImplementedError

    @staticmethod
    def send_all(sock: socket.socket, data: bytes) -> int:
        bytes_sent = 0
        while True:
            r = sock.send(data[bytes_sent:])
            if r < 0:
                return r
            bytes_sent += r
            if bytes_sent == len(data):
                return bytes_sent

    def connect(self, remote) -> None:
        try:
            file_descriptors = [self.client, remote]
            while True:
                read, _, _ = select.select(file_descriptors, [], [])
                if self.client in read:
                    data = self.client.recv(4096)
                    if len(data) <= 0:
                        break
                    result = self.send_all(remote, data)
                    if result < len(data):
                        raise Exception('failed to send data to remote')

                if remote in read:
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    result = self.send_all(self.client, data)
                    if result < len(data):
                        raise Exception('failed to send data to client')
        finally:
            self.client.close()
            remote.close()

    def end(self) -> None:
        if not self.write_file.closed:
            try:
                self.write_file.flush()
            except socket.error:
                pass
        self.write_file.close()
        self.read_file.close()

    def __call__(self, *args, **kwargs):
        self.init()
        try:
            self.handle()
        finally:
            self.end()


class ServerConfig(argparse.Namespace):
    def __init__(self, handler):
        super(ServerConfig, self).__init__()
        self.address_family = socket.AF_INET
        self.socket_type = socket.SOCK_STREAM
        self.address = '127.0.0.1'
        self.port = 13245
        self.local_port = 0
        self.client_num = 5
        self.handler = handler
        self.blocking = False


class ClientConfig(argparse.Namespace):
    def __init__(self, handler):
        super(ClientConfig, self).__init__()
        self.address_family = socket.AF_INET
        self.socket_type = socket.SOCK_STREAM
        self.address = '127.0.0.1'
        self.port = 7590
        self.local_port = 7590
        self.client_num = 5
        self.handler = handler
        self.blocking = False
