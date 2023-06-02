from enum import Enum
from dataclasses import dataclass

class GameName(Enum):
    IW4 = "IW4",
    IW5 = "IW5",
    IW6 = "IW6",
    T5 = "T5",
    S1X = "S1X"

@dataclass
class GameServerInfo():
    hostname:str
    gamename:GameName
    protocol:int
    mapname:str
    clients:int
    sv_maxclients:int