from ipaddress import IPv4Address
from socket import socket

class RawPacket():
    header: bytes
    data: bytes
    footer: bytes

    def __init__(self, header = "", data = None, footer = b'EOT\x00\x00\x00') -> None:
        self.set_header(header)
        self.footer = footer

    def set_header(self, header: str):
        self.header = b"\xFF\xFF\xFF\xFF" + bytes(header, encoding="utf-8") + b"\n "
        return self.header

    def get_header(self) -> str:
        return self.header.lstrip(b"\xFF").rstrip(b'\n ')
    
    def get_bytes(self) -> bytes:
        return self.header + self.data + self.footer

    @staticmethod
    def get_bytes_from_dict(input:dict):
        bytes = bytearray()
        lst = [bytes(k)+b"\\"+bytes(v) for k, v in input.items()]
        bytes += b"\\".join(lst)
        return bytes

    def send(self, socket: socket, address: IPv4Address) -> None:
        socket.sendto(self.get_bytes(), address)
    
    # def __hash__(self) -> int:
    #     super.__hash__(self)
    
    def __str__(self) -> str:
        return f"header: {self.header}\ndata: {self.data}\nfooter: {self.footer}\n"