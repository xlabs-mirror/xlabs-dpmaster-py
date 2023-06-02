from __future__ import annotations
from logging import getLogger
from . import RawPacket
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..GameServer import GameServerEntry

# def process_getinfo(targetIP:str, targetPort:int):
#     response = b"\xFF\xFF\xFF\xFFgetinfoResponse\\"
#     response += b"hostname\\My Server\\"
#     response += b"gamename\\IW4\\"
#     response += b"protocol\\150\\"
#     response += b"mapname\\mp_crash\\"
#     response += b"clients\\10\\"
#     response += b"sv_maxclients\\20\\"
#     response += b"EOT\x00\x00\x00"
#     return response

class getInfoResponse(RawPacket):
    logger = getLogger(__name__)
    server: GameServerEntry
    server_info: dict
    def __init__(self, server:GameServerEntry, server_info:dict) -> None:
        super().__init__("getInfoResponse")
        self.server = server
        self.server_info = server_info

    def get_bytes(self) -> bytes:
        self.data = self.get_bytes_from_dict(self.server_info)
        return super().get_bytes()
