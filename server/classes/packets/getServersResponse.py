from __future__ import annotations

from logging import getLogger
from . import RawPacket
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .. import GameServerEntry


class getServersResponse(RawPacket):
    logger = getLogger(__name__)
    servers: list[GameServerEntry]
    def __init__(self, servers:list[GameServerEntry] = None) -> None:
        super().__init__("getServersResponse")
        self.servers = servers

    def get_servers_bytes(self, servers:list[GameServerEntry]):
        servers_bytes = bytearray()
        for i, server in enumerate(servers):
            server: GameServerEntry
            server_bytes = server.bytes()
            self.logger.log(f"{server} > {server_bytes}")
            servers_bytes += server_bytes
        return servers_bytes

    def get_bytes(self) -> bytes:
        self.data = self.get_servers_bytes()
        return super().get()
