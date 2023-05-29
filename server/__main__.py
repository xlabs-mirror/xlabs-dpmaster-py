from dataclasses import dataclass
import datetime
import json
import os
import socket
import sys
from struct import unpack
from pprint import pprint


def calculate_rcv_buffer_size(batch_count: int):
    """A helper function for calculating a suggested size for a socket receive
       buffer that will be handling batch_count number of server responses.

       Maximum suggested size is 2**29 bytes (or 64MB).

    Args:
        batch_count (int): The maximum number of servers in each batch

    Returns:
        int: A suggested number of bytes to be used for the socket rcv buffer.
    """

    for i in range(0, 30):
        if 2**i > ((2048 * batch_count) + 2048):
            return 2**i
    return 2**29


# Master server domain and port.
MASTER_SERVER_DOMAIN = "127.0.0.1"          # The FQDN of the master server.
MASTER_SERVER_PORT = 20810                  # The port of the master server.
MASTER_SERVER_SOCKET_TIMEOUT = 1            # The socket timeout (in seconds) for the getservers packet.

# Game protocol versions, which are required parameters when querying the master server.
IW4X_PROTOCOL_VERSION = 150                 # https://github.com/XLabsProject/iw4x-client/blob/master/src/Game/Structs.hpp#L3 (0x96 = 150)
IW6X_PROTOCOL_VERSION = 1                   # https://github.com/XLabsProject/iw6x-client/blob/master/src/client/game/structs.hpp#L4
S1X_PROTOCOL_VERSION = 1                    # https://github.com/XLabsProject/s1x-client/blob/master/src/client/game/structs.hpp#L4

# Configurable options for the infoResponse packet.
SERVER_BATCH_COUNT = 150                    # Number of servers to process in a batch.
SOCKET_TIMEOUT = 0.5                        # The socket timeout (in seconds) when processing infoResponses.

# Calculated constants. It isn't necessary to touch these values as they are calculated from constants above.
MASTER_SERVER_IP = socket.gethostbyname(MASTER_SERVER_DOMAIN)
RCV_BUFFER_SIZE = calculate_rcv_buffer_size(SERVER_BATCH_COUNT)

localMasterIP = "192.168.2.38"
localMasterPort = 20810

# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Bind to address and IP
UDPServerSocket.bind((localMasterIP, localMasterPort))
print("UDP server up and listening")

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


def process_getinfo(targetIP:str, targetPort:int):
    response = b"\xFF\xFF\xFF\xFFgetinfoResponse\\"
    response += b"hostname\\My Server\\"
    response += b"gamename\\IW4\\"
    response += b"protocol\\150\\"
    response += b"mapname\\mp_crash\\"
    response += b"clients\\10\\"
    response += b"sv_maxclients\\20\\"
    response += b"EOT\x00\x00\x00"
    return response

def send_packet(s:socket, packet:bytes, address:tuple = None):
    print("=== send_packet ===")
    pprint(packet)
    pprint(address)
    s.sendto(packet, address)

# Listen for incoming datagrams
while True:
    bytesAddressPair = UDPServerSocket.recvfrom(RCV_BUFFER_SIZE)
    clientAddress = bytesAddressPair[1]
    print("Client IP Address: {}".format(clientAddress))
    clientMessage = bytesAddressPair[0]
    print("Message from Client: {}".format(clientMessage))
    clientMessageStripped = clientMessage.lstrip(b"\xFF")
    print("Message from Client (Stripped): {}".format(clientMessageStripped))
    # Process client message and generate response
    if clientMessageStripped.startswith(b'getinfo'):
        # Extract the target IP and port from the command
        targetIP, targetPort = clientMessage.split()[1], int(clientMessage.split()[2])

        # Process the target IP and port and generate a response
        response = process_getinfo(targetIP, targetPort)

        # Send the response back to the client
        UDPServerSocket.sendto(response.encode('latin-1'))
    elif clientMessageStripped.startswith(b"getservers"):
        response = b"\xFF\xFF\xFF\xFFgetserversResponse\\"

        # Creating a list of server IP addresses and ports
        serverList = get_server_list()
        # response += str(len(serverList)).encode("latin-1")
        print("=== response with len ===")
        pprint(response)
        # Adding server IPs and ports to the response
        for server in serverList:
            print("Adding server",server,"as",server.bytes())
            response += server.ip_bytes()
            response += server.port_bytes()

        response += b"EOT\x00\x00\x00"

        # Sending the response to the client
        send_packet(UDPServerSocket, response, clientAddress)
    else:
        # Sending a default response to the client
        send_packet(UDPServerSocket, b"default response", clientAddress)
