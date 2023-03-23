import errno
import socket
import sys

from boofuzz import exception
from boofuzz.connections import base_socket_connection

class RawL4SocketConnection(base_socket_connection.BaseSocketConnection):
    """
    Uses a raw socket to send and receive data, including IP Headers, fuzzing layer 4 protocols(eg. TCP, UDP, ICMP, etc.)
    
    .. versionadded:: spwpun-dev-1.0

    Args:
        host (str): Hostname or IP address of target system
        ip_proto (int): IP Protocol number, eg. socket.IPPROTO_TCP
        send_timeout (float): Timeout for send operations. Default 5.0.
        recv_timeout (float): Timeout for recv operations. Default 5.0.
        packet_size (int): Maximum packet size. Default 1500.
    """

    def __init__(self,
                    host,
                    ip_proto,
                    send_timeout=5.0,
                    recv_timeout=5.0,
                    packet_size=1500):
            super(RawL4SocketConnection, self).__init__(send_timeout, recv_timeout)
    
            self.host = host
            self.ip_proto = ip_proto
            self.send_timeout = send_timeout
            self.recv_timeout = recv_timeout
            self.packet_size = packet_size
    
    def open(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.ip_proto)
        self._sock.settimeout(self.recv_timeout)
    
        super(RawL4SocketConnection, self).open()
    
    def recv(self, max_bytes):
        """
        Receives a packet from the raw socket. If max_bytes < packet_size, only the first max_bytes are returned and
        the rest of the packet is discarded. Otherwise, return the whole packet.
    
        Args:
            max_bytes (int): Maximum number of bytes to return. 0 to return the whole packet.
    
        Returns:
            Received data
        """
        try:
            data = self._sock.recv(self.packet_size)
        except socket.timeout:
            data = b""
        except socket.error as e:
            if e.errno == errno.EINTR:
                data = b""
            else:
                raise exception.BoofuzzTargetConnectionFailedError(e)
    
        if max_bytes > 0 and len(data) > max_bytes:
            data = data[:max_bytes]
    
        return data
    
    def send(self, data):
        """
        Sends data to the target.
    
        Args:
            data (bytes): Data to send.
        """
        num_sent = 0

        data = data[: self.packet_size]

        try:
            num_sent = self._sock.sendto(data, (self.host, 0))
        except socket.error as e:
            if e.errno == errno.ECONNABORTED:
                raise exception.BoofuzzTargetConnectionAborted(
                    socket_errno=e.errno, socket_errmsg=e.strerror
                ).with_traceback(sys.exc_info()[2])
            elif e.errno in [errno.ECONNRESET, errno.ENETRESET, errno.ETIMEDOUT]:
                raise exception.BoofuzzTargetConnectionReset().with_traceback(sys.exc_info()[2])
            elif e.errno == errno.EWOULDBLOCK:
                pass
            else:
                raise
        
        return num_sent
    
    @property
    def info(self):
        return "RawL4SocketConnection: host=%s, ip_proto=%d" % (self.host, self.ip_proto)