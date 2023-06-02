from urllib import request
from urllib.parse import quote
from ssl import SSLContext
from base64 import b64decode

def send_notification(lines:list[str]):
    try:
        base_url = f'https://minopia.de/api/boxtogo/rc/?host=192.168.2.44&pw={b64decode("MjcxMjE5OTU=")}&mode=8&cmd=notifyondemand%20'
        parsed_message = '~'.join(["dpmaster-py"]+[quote(l) for l in lines])
        url = base_url + "~" + parsed_message
        request.urlopen(url, context=SSLContext(), timeout=1)
    except: pass

def calculate_buffer_size(batch_count: int) -> int:
    """A helper function for calculating a suggested size for a socket receive
       buffer that will be handling batch_count number of server responses.

       Maximum suggested size is 2**29 bytes (or 64MB).

    Args:
        batch_count (int): The maximum number of servers in each batch

    Returns:
        int: A suggested number of bytes to be used for the socket rcv buffer.
    """

    for i in range(0, 30):
        if 2 ** i > ((2048 * batch_count) + 2048):
            return 2 ** i
    return 2 ** 29