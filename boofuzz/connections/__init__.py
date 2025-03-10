# Import connections at this level for API backwards compatibility.
from .base_socket_connection import BaseSocketConnection
from .file_connection import FileConnection
from .iserial_like import ISerialLike
from .itarget_connection import ITargetConnection
from .netconf_connection import NETCONFConnection
from .raw_l2_socket_connection import RawL2SocketConnection
from .raw_l3_socket_connection import RawL3SocketConnection
from .raw_l4_socket_connection import RawL4SocketConnection
from .serial_connection import SerialConnection
from .serial_connection_low_level import SerialConnectionLowLevel
from .socket_connection import SocketConnection
from .ssl_socket_connection import SSLSocketConnection
from .tcp_socket_connection import TCPSocketConnection
from .udp_socket_connection import UDPSocketConnection
from .unix_socket_connection import UnixSocketConnection

__all__ = [
    "BaseSocketConnection",
    "FileConnection",
    "ISerialLike",
    "ITargetConnection",
    "NETCONFConnection",
    "RawL2SocketConnection",
    "RawL3SocketConnection",
    "RawL4SocketConnection",
    "SerialConnection",
    "SerialConnectionLowLevel",
    "SocketConnection",
    "SSLSocketConnection",
    "TCPSocketConnection",
    "UDPSocketConnection",
    "UnixSocketConnection",
]
