from logging import getLogger

from . import RawPacket
from .. import GameServer


class getServersResponse(RawPacket):
    logger = getLogger(__name__)
    servers: list[GameServer]
    def __init__(self, servers:list[GameServer] = None) -> None:
        super().__init__("getServersResponse")
        self.servers = servers

    def get_servers_bytes(self, servers:list[GameServer]):
        servers_bytes = bytearray()
        for i, server in enumerate(servers):
            server: GameServer
            server_bytes = server.bytes()
            self.logger.log(f"{server} > {server_bytes}")
            servers_bytes += server_bytes
        return servers_bytes

    def get_bytes(self) -> bytes:
        self.data = self.get_servers_bytes()
        return super().get()
