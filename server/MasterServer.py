from __future__ import annotations

from ipaddress import IPv4Address
from dataclasses import dataclass
import datetime
import json
import os
from socket import socket, AF_INET, SOCK_DGRAM, gethostbyname
import sys
from struct import pack, unpack
from pprint import pprint
from time import sleep
from threading import Thread
from utils import calculate_buffer_size, send_notification
from classes.GameServer import GameServerEntry
from classes.packets.getServersResponse import getServersResponse
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ApiServer import XLabsMasterServerAPI

class XLabsMasterServer:
    running: bool = False
    paused: bool = False
    api: XLabsMasterServerAPI
    socket: socket
    # Master server domain and port.
    MASTER_SERVER_DOMAIN: str  # The FQDN of the master server.
    MASTER_SERVER_PORT: int  # The port of the master server.
    MASTER_SERVER_SOCKET_TIMEOUT = 1  # The socket timeout (in seconds) for the getservers packet.

    # Game protocol versions, which are required parameters when querying the master server.
    IW4X_PROTOCOL_VERSION = 150  # https://github.com/XLabsProject/iw4x-client/blob/master/src/Game/Structs.hpp#L3 (0x96 = 150)
    IW6X_PROTOCOL_VERSION = 1  # https://github.com/XLabsProject/iw6x-client/blob/master/src/client/game/structs.hpp#L4
    S1X_PROTOCOL_VERSION = 1  # https://github.com/XLabsProject/s1x-client/blob/master/src/client/game/structs.hpp#L4

    # Configurable options for the infoResponse packet.
    SERVER_BATCH_COUNT = 150  # Number of servers to process in a batch.
    SOCKET_TIMEOUT = 0.5  # The socket timeout (in seconds) when processing infoResponses.

    # Calculated constants. It isn't necessary to touch these values as they are calculated from constants above.
    MASTER_SERVER_IP: IPv4Address
    TX_BUFFER_SIZE: int

    def __init__(self, domain="0.0.0.0", port=20810):
        self.MASTER_SERVER_DOMAIN = domain
        self.MASTER_SERVER_PORT = port
        self.MASTER_SERVER_IP = self.get_host_ip()
        self.TX_BUFFER_SIZE = calculate_buffer_size(self.SERVER_BATCH_COUNT)

        # Create a datagram socket
        self.socket = socket(family=AF_INET, type=SOCK_DGRAM)

        # Bind to address and IP
        self.socket.bind((self.MASTER_SERVER_IP, self.MASTER_SERVER_PORT))
        print("UDP server ready")

    def get_host_ip(self): return gethostbyname(self.MASTER_SERVER_DOMAIN)

    def get_server_list(self):
        serverList = [
            GameServerEntry("192.168.2.1", 28960),
            GameServerEntry("192.168.2.2", 28961),
            GameServerEntry("192.168.2.3", 28962),
        ]
        return serverList

    def send_packet(self, packet: bytes, address: tuple = None):
        print("=== send_packet ===")
        pprint(packet)
        pprint(address)
        self.socket.sendto(packet, address)

    def parse_packet(self, client_address:IPv4Address, data:bytes):
        clientMessageStripped = data.lstrip(b"\xFF")
        print("Message from Client (Stripped): {}".format(clientMessageStripped))
        # Process client message and generate response
        if clientMessageStripped.startswith(b'getinfo'):
            targetIP, targetPort = data.split()[1], int(data.split()[2])
            response = self.process_getinfo(targetIP, targetPort)
            self.socket.sendto(response.encode('latin-1'))
        elif clientMessageStripped.startswith(b"getservers"):
            # Creating a list of server IP addresses and ports
            serverList = self.get_server_list()
            response = getServersResponse(serverList)
            # Sending the response to the client
            self.send_packet(response.get_bytes(serverList), client_address)
        else:
            # Sending a default response to the client
            self.send_packet(b"default response", client_address)

    def run(self):
        self.running = True
        # Listen for incoming datagrams
        while self.running:
            if not self.paused:
                bytesAddressPair = self.socket.recvfrom(self.TX_BUFFER_SIZE)
                clientAddress = bytesAddressPair[1]
                print("Client IP Address: {}".format(clientAddress))
                clientMessage = bytesAddressPair[0]
                print("Message from Client: {}".format(clientMessage))
                self.parse_packet(clientAddress, clientMessage)
            else: sleep(.1)

    def run_threaded(self):
        self.thread = Thread(target=self.run)
        self.thread.start()

    def stop(self):
        try:
            self.running = False
            self.UDPServerSocket.close()
            # self.UDPServerSocket.shutdown(1)
            if self.thread: self.thread = None
            return True, None
        except Exception as ex:
            pprint(ex)
            return False, ex