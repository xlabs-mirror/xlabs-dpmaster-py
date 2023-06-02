from dataclasses import dataclass
from ipaddress import IPv4Address
from struct import pack
from .GameServerInfo import GameServerInfo

@dataclass
class GameServerEntry():
    domain: str
    ip: IPv4Address
    port: int
    def __init__(self, domain = "0.0.0.0", port = 28960):
        self.domain = domain
        self.ip = IPv4Address(domain)
        self.port = port
    def ip_bytes(self): return self.ip.packed
    def port_bytes(self): return pack('>H', self.port) # self.port.to_bytes(2, byteorder="big")
    def __str__(self) -> str: return f"{self.ip}:{self.port}"
    def bytes(self) -> str: return self.ip_bytes() + self.port_bytes() + b"\xFF"

@dataclass
class GameServer(GameServerEntry):
    variables:dict
    info:GameServerInfo