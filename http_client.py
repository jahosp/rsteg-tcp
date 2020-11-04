#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

from scapy.layers.http import HTTPRequest, HTTP
from rsteg_socket import RstegSocket
import logging

logger = logging.getLogger(__name__)

class HttpClient():
    """A simple HTTP Client build over RstegSocket."""
    def __init__(self, port=49512):
        self.sport = port
        self.s = RstegSocket(self.sport)
        self.timeout = 5

    def request(self, req, host):
        """Send the request to host and return response."""
        self.s.connect(host, 80)
        self.s.send(req)
        res = self.s.recv(1024, self.timeout)
        self.s.close()

        return res

if __name__ == '__main__':
    # Logger configuration
    logging.basicConfig(filename='http_client.log',
                        filemode='w',
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p',
                        level=logging.DEBUG)
    logger.setLevel(logging.DEBUG)

HOST = '192.168.1.67'
DPORT = 80
SPORT = 49512

cover_data = open('/home/jahos/TFG/payloads/payload.jpeg', 'rb').read()
secret_data = open('/home/jahos/TFG/payloads/payload.gif', 'rb').read()
data = open('/home/jahos/TFG/payloads/secret.jpg', 'rb').read()

get_req = HTTP() / HTTPRequest(
    Accept_Encoding=b'gzip, deflate',
    Cache_Control=b'no-cache',
    Connection=b'keep-alive',
    Host=b'localhost',
    Pragma=b'no-cache'
)

get_req_non = HTTP() / HTTPRequest(
    Accept_Encoding=b'gzip, deflate',
    Path=b'/test',
    Cache_Control=b'no-cache',
    Connection=b'keep-alive',
    Host=b'localhost',
    Pragma=b'no-cache'
)

post_req = HTTP() / HTTPRequest(
    Method=b'POST',
    Path=b'/upload',
    Host=b'localhost',
    Connection=b'keep-alive',
    Content_Length=str(len(data)).encode(),
    Content_Type=b'image/jpeg'
) / data


c = HttpClient(SPORT)
res = c.request(bytes(get_req_non), HOST)
if res:
    print(res.decode())
else:
    print('Request timed-out. Server not available.')


