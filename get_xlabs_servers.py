import datetime
import json
import os
import socket
import sys
from struct import unpack


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
MASTER_SERVER_DOMAIN = "master.xlabs.dev"   # The FQDN of the master server.
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

""" List of possible keys from the infoResponse packet.

NOTE: Some of these keys may only be present in one of the X Labs games. For
      example, the "dedicated" and "playmode" keys only exist in the response
      packets from S1x.

The server's infoResponse can be unordered, and so when we split the tokens
we cannot be certain that a specific key will be at a specific index. We
therefore check each token against this list as a lookup. If the token exists
in this list, then we know that the following token in the packet  will be 
its value.
"""
INFO_RESPONSE_KEYS = ["aimAssist",          # Aim assist (used by IW4x only; 0 = false, 1 = true)
                      "bots",               # Number of bots
                      "checksum",           # Jenkins one-at-a-time hash checksum
                      "clients",            # Number of currently connected clients
                      "dedicated",          # Dedicated server (used by S1x only; 0 = false, 1 = true)
                      "fs_game",            # Loaded base folder for primary mod assets (i.e. mod name)
                      "gamename",           # Game name (i.e. IW4/IW6/S1)
                      "gametype",           # Current game type (i.e. war, dm, dom, koth, sab, sd, arena, dd, ctf, oneflag, gtnw, infected, gungame, custom, etc)
                      "hc",                 # Hardcore (0 = false, 1 = true)
                      "hostname",           # Hostname (i.e. server name)
                      "isPrivate",          # Password protected (0 = false, 1 = true)
                      "mapname",            # Current map name
                      "matchtype",          # Match type (0 = No match, connecting not possible, 1 = Party, use Steam_JoinLobby to connect, 2 = Match, use CL_ConnectFromParty to connect)
                      "playmode",           # COD Play Mode (used by S1x only; CODPLAYMODE_NONE = 0x0, CODPLAYMODE_SP = 0x1, CODPLAYMODE_CORE = 0x2, CODPLAYMODE_SURVIVAL = 0x5, CODPLAYMODE_ZOMBIES = 0x6)
                      "protocol",           # Network protocol version (ex. for IW4x, 0x96 = 150)
                      "securityLevel",      # Minimum security level
                      "shortversion",       # Short version number (ex. 0.7.3)
                      "sv_maxclients",      # Maximum number of client slots
                      "sv_motd",            # Server message of the day
                      "sv_running",         # Server running status (0 = not running, 1 = running)
                      "voiceChat",          # Voice chat (used by IW4x only; 0 = false, 1 = true)
                      "wwwDownload",        # HTTP downloads, i.e. FastDL (0 = no HTTP downloads, download mods from the server, 1 = HTTP downloads, download from wwwUrl)
                      "wwwUrl",             # HTTP web server base URL for usermaps and mods downloads
                      "xuid"]               # Steam User ID (NOTE: IW4x uses a static ID for dedicated servers, the int64 casted value of "DEDICATE", which is "4554414349444544")


def get_servers_from_master_server(ip: str, port: int, gamename: str, protocol: int):
    """For a given and protocol, return the master server response.

    Args:
        ip (str): the IP address of the master server
        port (int): the port of the master server
        gamename (str): the gamename (IW4, IW6, or S1) to get from the master server.
        protocol (int): the protocol version of the gamename to get from the master server.

    Returns:
        master_server_response (list of dict): a list of servers obtained from the master server, of the form: [{"ip": IP_ADDRESS, "port": PORT}, {"ip": IP_ADDRESS, "port": PORT}, ...].
    """

    # Open the socket for UDP datagram transfers over IPv4.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)

    # Craft the packet requesting the full server list from the master server.
    packet = b"\xFF\xFF\xFF\xFFgetservers\n" + gamename.encode('latin-1') + b" %i full empty" % protocol

    # Send the packet to the master server and grab the server response.
    s.sendto(packet, (ip, port))

    # Configure the socket timeout for the master server response.
    s.settimeout(MASTER_SERVER_SOCKET_TIMEOUT)

    # Wait until we receive a response from the master server IP.
    address = (0, 0)
    while address[0] != ip:
        try:
            data, address = s.recvfrom(4096)
        except:
            # If the response times out or we receive any other error, exit the
            # script immediately.
            sys.exit("An issue occurred when obtaining results from the master server. Exiting script.")

    # Close the socket.
    s.close()

    # Store the master server results.
    master_server_response = []

    # Strip off the getserversResponse header.
    data = data[24:]

    while len(data) != 0:
        # Grab the next token set (8 bytes)
        tokens = data[0:7]

        # If the token contains this EOT string, it's the end, so break out of the loop.
        if b'EOT\x00\x00\x00' in tokens:
            break

        # Grab each token's IP and port.
        ip_str = socket.inet_ntoa(data[0:4])
        # '>H' is a big-endian unsigned short.
        port_int = unpack(">H", data[4:6])[0]

        # Append the IP and port as a JSON object into the master_server_response.
        master_server_response.append({"ip": ip_str, "port": port_int})

        # Remove the front 8 bytes from the data.
        data = data[7:]

    return master_server_response


def address_in_server_subset(address: tuple, server_subset: list):
    """Provided an address tuple and server_subset, return whether the address
       is contained within the server_subset. If the address is contained in the
       server_subset, remove it. Otherwise, return the same server_subset.

    Args:
        address (tuple): a tuple containing an IP address and port
        server_subset (list of dict): a list of servers of the form: [{"ip": IP_ADDRESS, "port": PORT}, {"ip": IP_ADDRESS, "port": PORT}, ...]

    Returns:
        True/False: a boolean representing whether the address was located in the server_subset
        server_subset (list of dict): an updated server subset; if the bool is True, then the server found was removed from the server_subset, otherwise the server_subset is the same.
    """

    for server in server_subset:
        if address[0] == server['ip'] and address[1] == server['port']:
            server_subset.remove(server)
            return True, server_subset

    return False, server_subset


def process_master_server_response(master_server_response: list):
    """Provided a list of servers from the master server, request information
       from each server and return a list of servers and the obtained
       information.

       The server_list that is returned from this function contains a list of
       dictionaries. The keys of the diciontary are defined in INFO_RESPONSE_KEYS,
       in addition to two extra keys called "ip" and "port" which define the IP
       address and port of the server.

       In the event that a server did not response with a particular key, it is
       not included in the server's information.

    Args:
        master_server_response (list of dict): a list of servers of the form: [{"ip": IP_ADDRESS, "port": PORT}, {"ip": IP_ADDRESS, "port": PORT}, ...]

    Returns:
        server_list (list of dict): a list of dictionaries containing server information.
    """

    # Generate a random 32-byte challenge. Presently the challenge is not
    # checked, but in the future I will likely ensure that this challenge is
    # verified in the response before data is processed.
    challenge = str(os.urandom(32))

    # Craft the 'getinfo' packet that we'll be sending to each of the servers.
    packet = b"\xFF\xFF\xFF\xFFgetinfo\n" + bytes(challenge, 'latin-1')

    # Open a UDP socket.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)

    # Resize the receive buffer.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCV_BUFFER_SIZE)

    # Set the socket timeout.
    s.settimeout(SOCKET_TIMEOUT)

    # Initialize an empty server_list, which will contain the compiled results
    # of all of our getInfo requests.
    server_list = []

    while master_server_response:
        # Grab the first 0 to SERVER_BATCH_COUNT entries from the master server
        # response, and remove these entries from the main response list.
        server_subset = master_server_response[0:SERVER_BATCH_COUNT]
        master_server_response = master_server_response[SERVER_BATCH_COUNT:]

        # For each server in our subset, send a 'getInfo' packet.
        for server in server_subset:
            s.sendto(packet, (server['ip'], server['port']))

        # Continue checking responses while we have servers in the subset
        # for which we have not yet processed a response for.
        while server_subset:
            # Try to pull a response from the buffer. If we receive a timeout
            # error, we know that we've processed all servers that we received
            # a response for within SOCKET_TIMEOUT, so we can stop processing.
            try:
                data, address = s.recvfrom(2048)
            except TimeoutError:
                break

            # Check if the received packet was from one of the servers in our subset.
            valid_server, server_subset = address_in_server_subset(address, server_subset)

            # If the received packet process the data.
            if valid_server:

                # Start by initializing the IP and port using the data from the
                # address. Every field in the new_server will be a string.
                new_server = {}
                new_server['ip'] = address[0]
                new_server['port'] = str(address[1])

                # Strip out the getInfoResponse header of the packet, and then
                # decode and split the remainder of the packet using \\ delims.
                data = data[18:].decode('latin-1').split("\\")
                for i in range(0, len(data)):
                    # For each token, check if it's one of the valid info
                    # response keys, if it is we record the value after the
                    # key and we can advance the iterator to the next token.
                    if data[i] in INFO_RESPONSE_KEYS:
                        new_server[data[i]] = str(data[i+1])
                        i += 1

                # After we have concluded iterating all tokens, we add the
                # new server to our list.
                server_list.append(new_server)

    # Close the socket.
    s.close()

    return server_list


def extract_metrics(server_list: list):
    """Given a server list, extract and return the metrics of that list.

    Args:
        server_list (list of dict): a list of servers (each represented as a dict with keys from INFO_RESPONSE_KEYS)

    Returns:
        bot_count (int): the number of bots from all servers in the server_list
        client_count (int): the number of clients from all servers in the server_list
        server_count (int): the number of servers from all servers in the server_list
        timestamp (str): the string timestamp representing the time these metrics were calculated
    """
    # Initialize counters.
    bot_count = 0
    client_count = 0
    server_count = 0

    # For each server, check if the key exists and iterate the counter.
    for server in server_list:
        if ("bots" in server):
            bot_count += int(server['bots'])
        if ("clients" in server):
            client_count += int(server['clients'])
        server_count += 1

    # Get the current timestamp.
    timestamp = datetime.datetime.now().ctime()
    
    return bot_count, client_count, server_count, timestamp


if __name__ == "__main__":

    # Initialize the defaults for the resulting dictionary.
    result = {
        "IW4x": {
            "bot_count": None,
            "client_count": None,
            "server_count": None,
            "server_list": [],
            "timestamp": None
        },
        "IW6x": {
            "bot_count": None,
            "client_count": None,
            "server_count": None,
            "server_list": [],
            "timestamp": None
        },
        "S1x (Multiplayer)": {
            "bot_count": None,
            "client_count": None,
            "server_count": None,
            "server_list": [],
            "timestamp": None
        },
        "S1x (Horde)": {
            "bot_count": None,
            "client_count": None,
            "server_count": None,
            "server_list": [],
            "timestamp": None
        },
        "S1x (Zombies)": {
            "bot_count": None,
            "client_count": None,
            "server_count": None,
            "server_list": [],
            "timestamp": None
        }
    }

    # ==============================================
    # =                    IW4X                    =
    # ==============================================

    # Get the list of IW4x (Modern Warfare 2) servers from the master server.
    iw4x_master_server_response = get_servers_from_master_server(MASTER_SERVER_IP, MASTER_SERVER_PORT, 'IW4', IW4X_PROTOCOL_VERSION)

    # Process each IW4x server from the master server's response.
    iw4x_server_list = process_master_server_response(iw4x_master_server_response)

    # Extract the IW4x metrics from the compiled list.
    bot_count, client_count, server_count, timestamp = extract_metrics(iw4x_server_list)
    result["IW4x"]["server_list"] = iw4x_server_list
    result["IW4x"]["bot_count"] = bot_count
    result["IW4x"]["client_count"] = client_count
    result["IW4x"]["server_count"] = server_count
    result["IW4x"]["timestamp"] = timestamp

    # ==============================================
    # =                    IW6X                    =
    # ==============================================

    # Get the list of IW6x (Ghosts) servers from the master server.
    iw6x_master_server_response = get_servers_from_master_server(MASTER_SERVER_IP, MASTER_SERVER_PORT, 'IW6', IW6X_PROTOCOL_VERSION)

    # Process each IW6x server from the master server's response.
    iw6x_server_list = process_master_server_response(iw6x_master_server_response)

    # Extract the IW6x metrics from the compiled list.
    bot_count, client_count, server_count, timestamp = extract_metrics(iw6x_server_list)
    result["IW6x"]["server_list"] = iw6x_server_list
    result["IW6x"]["bot_count"] = bot_count
    result["IW6x"]["client_count"] = client_count
    result["IW6x"]["server_count"] = server_count
    result["IW6x"]["timestamp"] = timestamp

    # ==============================================
    # =                    S1X                     =
    # ==============================================

    # Get the list of S1x (Advanced Warfare) servers from the master server.
    s1x_master_server_response = get_servers_from_master_server(MASTER_SERVER_IP, MASTER_SERVER_PORT, 'S1', S1X_PROTOCOL_VERSION)

    # Process each S1x server from the master server's response.
    s1x_server_list = process_master_server_response(
        s1x_master_server_response)

    # S1x features 3 different overarching gamemodes: multiplayer,
    # horde (survival), and zombies. We will split the s1x_server_list into
    # these 3 gamemodes.
    s1x_mp_server_list = []
    s1x_horde_server_list = []
    s1x_zombies_server_list = []

    # For each server in the s1x_server_list, identify if it's a horde (surival),
    # zombies, or multiplayer server. Append the server in the corresponding
    # list.
    for server in s1x_server_list:
        if server['gametype'] == "horde":
            s1x_horde_server_list.append(server)
        elif server['gametype'] == "zombies":
            s1x_zombies_server_list.append(server)
        else:
            s1x_mp_server_list.append(server)

    # Extract the S1x (Multiplayer) metrics from the compiled list.
    bot_count, client_count, server_count, timestamp = extract_metrics(s1x_mp_server_list)
    result["S1x (Multiplayer)"]["server_list"] = s1x_mp_server_list
    result["S1x (Multiplayer)"]["bot_count"] = bot_count
    result["S1x (Multiplayer)"]["client_count"] = client_count
    result["S1x (Multiplayer)"]["server_count"] = server_count
    result["S1x (Multiplayer)"]["timestamp"] = timestamp

    # Extract the S1x (Horde) metrics from the compiled list.
    bot_count, client_count, server_count, timestamp = extract_metrics(s1x_horde_server_list)
    result["S1x (Horde)"]["server_list"] = s1x_horde_server_list
    result["S1x (Horde)"]["bot_count"] = bot_count
    result["S1x (Horde)"]["client_count"] = client_count
    result["S1x (Horde)"]["server_count"] = server_count
    result["S1x (Horde)"]["timestamp"] = timestamp

    # Extract the S1x (Zombies) metrics from the compiled list.
    bot_count, client_count, server_count, timestamp = extract_metrics(s1x_zombies_server_list)
    result["S1x (Zombies)"]["server_list"] = s1x_zombies_server_list
    result["S1x (Zombies)"]["bot_count"] = bot_count
    result["S1x (Zombies)"]["client_count"] = client_count
    result["S1x (Zombies)"]["server_count"] = server_count
    result["S1x (Zombies)"]["timestamp"] = timestamp

    # Write the result dictionary to a JSON file.
    with open("xlabs_servers.json", "w") as f:
        json.dump(result, f, sort_keys=True, indent=4)
        f.close()

    # Exit successfully.
    exit(0)
