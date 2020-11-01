#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

from scapy.layers.http import HTTPRequest
from rsteg_socket import RstegSocket
import logging

logger = logging.getLogger(__name__)

def send_req(s, req, host):
    s.connect(host, 80)
    s.send(req)
    s.close()

def get_res(s):
    s.listen()
    s.accept()
    data = s.receive()
    return data


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


req = HTTPRequest(
    Accept_Encoding=b'gzip, deflate',
    Cache_Control=b'no-cache',
    Connection=b'keep-alive',
    Host=b'localhost',
    Pragma=b'no-cache'
)

s = RstegSocket()
send_req(s, bytes(req), HOST)
data = get_res(s)


"""
s = RstegSocket()
s.connect(HOST, DPORT)
print('> RSTEG-TCP Client connected to ' + HOST + ' on port ' + str(DPORT))
print('> Sending cover data and secret...')
#s.rsend(cover_data, secret_data)  # sneaky send
s.send(bytes(req))
res = s.receive()
print('> Data transfer ended.')
s.close()
print('> Closing connection.')
"""



