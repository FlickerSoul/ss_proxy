from __future__ import annotations

import enum


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
    con_not_allowed= 0x02
    network_unreachable = 0x03
    host_unreachable = 0x04
    connection_refuse = 0x05
    ttl_expired = 0x06
    command_not_supported = 0x07
    addr_type_not_supported = 0x08
    ff_unassigned = 0x09
