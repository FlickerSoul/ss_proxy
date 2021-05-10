from __future__ import annotations

import argparse
import socket
from typing import Type

from utils import Handler


class ConfigBase(argparse.Namespace):
    address_family: int = socket.AF_INET
    socket_type: int = socket.SOCK_STREAM
    address: str = ''
    port: int = 0
    local_port: int = 12344
    client_num: int = 5
    blocking: bool = False

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
