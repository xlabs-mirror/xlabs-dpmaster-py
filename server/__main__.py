from dataclasses import dataclass
import datetime
import json
import os
import socket
import sys
from struct import pack, unpack
from pprint import pprint
from urllib import request
from urllib.parse import quote
from ssl import SSLContext

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
MASTER_SERVER_DOMAIN = "192.168.2.38"       # The FQDN of the master server.
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

# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Bind to address and IP
UDPServerSocket.bind((MASTER_SERVER_IP, MASTER_SERVER_PORT))
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

def send_notification(lines:list[str]):
    try:
        base_url = 'https://minopia.de/api/boxtogo/rc/?host=192.168.2.44&pw=27121995&mode=8&cmd=notifyondemand%20'
        parsed_message = '~'.join(["dpmaster-py"]+[quote(l) for l in lines])
        url = base_url + "~" + parsed_message
        request.urlopen(url, context=SSLContext(), timeout=1)
    except: pass

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

def generate_data(addresses):
    header = b"\xFF\xFF\xFF\xFFgetserversResponse\\"
    data = b"" + header
    for ip, port in addresses:
        ip_bytes = socket.inet_aton(ip)
        port_bytes = pack(">H", port)  # '>H' is a big-endian unsigned short
        data += ip_bytes + port_bytes
    data += b'EOT\x00\x00\x00'
    return data

def decode_servers(packet:bytes) -> list[GameServer]:
    servers = []
    data = packet[24:] # Strip b"\xFF\xFF\xFF\xFFgetserversResponse\n " header
    while len(data) != 0:
        tokens = data[0:7]
        if b'EOT\x00\x00\x00' in tokens: break
        ip_str = socket.inet_ntoa(data[0:4])
        port_int = unpack(">H", data[4:6])[0]
        servers.append(GameServer(ip_str, port_int))
        data = data[7:]
    return servers

def encode_servers(servers:list[GameServer]) -> bytes:
    packet = bytearray()
    for server in servers:
        ip = socket.inet_aton(server.ip)
        port = pack(">H", server.port)
        packet += ip
        packet += port
    packet += b'EOT\x00\x00\x00'
    return packet

def process_getservers3(servers=None) -> bytes:
    print("=== process_getservers ===")
    if not servers: servers = get_server_list()
    response = generate_data([(s.ip, s.port) for s in servers])
    return response
def process_getservers(servers: list[GameServer] = None):
    print("=== process_getservers ===")
    if not servers: servers = get_server_list()
    response = b"\xFF\xFF\xFF\xFFgetserversResponse\\"
    # response += str(len(servers)).encode("latin-1")
    print(f"Got server list with {len(servers)} servers.")
    pprint(response)
    # Adding server IPs and ports to the response
    for server in servers:
        print("Adding server",server,"as",server.bytes())
        response += server.ip_bytes()
        response += server.port_bytes()
    response += b"EOT\x00\x00\x00"
    return response
def process_getservers2(servers=None) -> bytes:
    print("=== process_getservers2 ===")
    if servers is None:
        servers = get_server_list()
    data = []
    # Reverse the servers list
    for server in reversed(servers):
        ip_str = server.ip
        port_int = server.port
        # Split the IP address into octets
        ip_octets = ip_str.split('.')
        # Ensure each octet is within the range of 0-255
        ip_octets = [int(octet) for octet in ip_octets]
        # Convert the octets to bytes
        ip_bytes = bytes(ip_octets)
        # Convert the port number to a 2-byte big-endian unsigned short
        port_bytes = pack(">H", port_int)
        # Concatenate the IP and port bytes
        token = ip_bytes + port_bytes
        # Prepend the token to the data list
        data = [token] + data
    # Add the end marker
    data = [b'EOT\x00\x00\x00'] + data
    response = b"".join(data)
    response = b"\xFF\xFF\xFF\xFFgetserversResponse\\" + response
    print("response:")
    print(response)
    return response

def send_packet(s:socket, packet:bytes, address:tuple = None):
    print("=== send_packet ===")
    pprint(packet)
    pprint(address)
    s.sendto(packet, address)

def server_loop():
    # Listen for incoming datagrams
    while True:
        bytesAddressPair = UDPServerSocket.recvfrom(RCV_BUFFER_SIZE)
        clientAddress = bytesAddressPair[1]
        print("Client IP Address: {}".format(clientAddress))
        clientMessage = bytesAddressPair[0]
        print("Message from Client: {}".format(clientMessage))
        clientMessageStripped = clientMessage.lstrip(b"\xFF")
        print("Message from Client (Stripped): {}".format(clientMessageStripped))
        send_notification([str(clientAddress), str(clientMessageStripped)])
        # Process client message and generate response
        if clientMessageStripped.startswith(b'getinfo'):
            # Extract the target IP and port from the command
            targetIP, targetPort = clientMessage.split()[1], int(clientMessage.split()[2])

            # Process the target IP and port and generate a response
            response = process_getinfo(targetIP, targetPort)

            # Send the response back to the client
            UDPServerSocket.sendto(response, clientAddress)
        elif clientMessageStripped.startswith(b"getservers"):
            response = process_getservers3()
            # Sending the response to the client
            send_packet(UDPServerSocket, response, clientAddress)
        else:
            # Sending a default response to the client
            send_packet(UDPServerSocket, b"default response", clientAddress)

servers = get_server_list()
print("servers:"); pprint(servers)
encoded = encode_servers(servers)
print("encoded:"); pprint(encoded)
decoded = decode_servers(encoded)
print("decoded:"); pprint(decoded)