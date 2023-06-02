from dataclasses import dataclass
import socket
from struct import pack, unpack
from ipaddress import IPv4Address

header = b"\xFF\xFF\xFF\xFFgetserversResponse\n "
@dataclass
class GameServer():
    ip:str
    port:int = 28960
    def __str__(self) -> str: return f"{self.ip}:{self.port}"
def get_server_list() -> list[GameServer]: 
    serverList = [
        GameServer(ip="192.168.2.1", port = 28960),
        GameServer(ip="192.168.2.2", port = 28961),
        GameServer(ip="192.168.2.3", port = 28962),
    ]
    return serverList
def encode_servers(servers: list[GameServer]) -> bytes:
    server_data = bytearray()
    for i, server in enumerate(servers):
        server: GameServer
        ip_bytes = IPv4Address(server.ip).packed
        port_bytes = pack('>H', server.port)  # use 'H' format for unsigned short
        server_bytes = ip_bytes + port_bytes + b"\xFF"
        server_data += server_bytes
    response_buffer = header + server_data
    return response_buffer

def decode_servers(packet:bytes) -> list[GameServer]:
    print("decode_servers(packet=",packet)
    servers = []
    data = packet[24:] # Strip b"\xFF\xFF\xFF\xFFgetserversResponse\\" header
    print("data=",data)
    while len(data) != 0:
        print("while len(data) loop, len=",len(data))
        print("\tdata=",data)
        tokens = data[0:7]
        print("\ttokens=",tokens)
        if b'EOT\x00\x00\x00' in tokens:
            print("\found end of data in tokens")
            break
        ip_bytes = data[0:4]
        print("\tip_bytes=",ip_bytes)
        ip_str = socket.inet_ntoa(ip_bytes)
        print("\tip_str=",ip_str)
        port_bytes = data[4:6]
        print("\tport_bytes=",port_bytes)
        port_int = unpack(">H", port_bytes)[0]
        print("\tport_int=",port_int)
        servers.append(GameServer(ip_str, port_int))
        data = data[7:]
        print("\tnext_data=",data)
    return servers

servers = get_server_list()
encoded = encode_servers(servers)
decoded = decode_servers(encoded)