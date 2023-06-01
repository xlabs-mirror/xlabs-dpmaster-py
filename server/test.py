from dataclasses import dataclass
import datetime
import json
import os
import socket
import sys
from struct import pack, unpack
from pprint import pformat, pprint
from urllib import request
from urllib.parse import quote
from ssl import SSLContext

header = b"\xFF\xFF\xFF\xFFgetserversResponse\n "

def pprint_bytearray(bytearr:bytes):
    print("Original Bytearray:")
    print(bytearr)
    print("len:",len(bytearr))
    
    print("\nHexadecimal Representation:")
    hex_repr = ' '.join(f'{byte:02x}' for byte in bytearr)
    print(hex_repr)
    print("len:",len(hex_repr))
    
    print("\nDecimal Representation:")
    dec_repr = ' '.join(str(byte) for byte in bytearr)
    print(dec_repr)
    print("len:",len(dec_repr))
    
    print("\nBinary Representation:")
    bin_repr = ' '.join(f'{byte:08b}' for byte in bytearr)
    print(bin_repr)
    print("len:",len(bin_repr))


@dataclass
class GameServer():
    ip:str
    port:int = 28960
    def ip_bytes(self): return socket.inet_aton(self.ip)
    def port_bytes(self): return self.port.to_bytes(2, byteorder="big")
    def __str__(self) -> str: return f"{self.ip}:{self.port}"
    def bytes(self) -> str: return f"{self.ip_bytes()}:{self.port_bytes()}"

def get_server_list() -> list[GameServer]: 
    serverList = [
        GameServer(ip="192.168.2.1", port = 28960),
        GameServer(ip="192.168.2.2", port = 28961),
        GameServer(ip="192.168.2.3", port = 28962),
    ]
    return serverList

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
        port_int = unpack(">H", port_bytes) # [0]
        print("\tport_int=",port_int)
        servers.append(GameServer(ip_str, port_int))
        data = data[7:]
        print("\tnext_data=",data)
    return servers

def encode_servers(servers: list[GameServer]) -> bytes:
    print("encode_servers(servers=",pformat(servers))
    # header = bytearray([0xFF, 0xFF, 0xFF, 0xFF])  # Header
    # header += b'getserversResponse'

    server_data = bytearray()
    for i, server in enumerate(servers):
        print("for server in servers:",i+1,"/",len(servers))
        ip_bytes_aton = socket.inet_aton(server.ip)
        print("\tip_bytes_aton:",pprint_bytearray(ip_bytes_aton))
        ip_parts = server.ip.split('.')
        print("\tip_parts:",pformat(ip_parts))
        ip_bytes = bytes([int(part) for part in ip_parts])
        print("\tip_bytes:",pprint_bytearray(ip_bytes))
        port_bytes = pack('!H', server.port)
        print("\tport_bytes:",pprint_bytearray(port_bytes))
        server_bytes = ip_bytes + port_bytes
        print("\tserver_bytes:",pprint_bytearray(server_bytes))
        server_data += server_bytes

    response_buffer = header + server_data
    print("response_buffer:",pprint_bytearray(response_buffer))

    return response_buffer



# pprint_bytearray(header)
servers = get_server_list()
# print("servers:"); pprint(servers)
encoded = encode_servers(servers)
# print("encoded:"); pprint(encoded)
# decoded = decode_servers(encoded)
# print("decoded:"); pprint(decoded)