#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

from scapy.layers.http import HTTPResponse
from rsteg_socket import RstegSocket
import logging

logger = logging.getLogger(__name__)

def send_res(s, res, host, port):
    s.connect(host, port)
    s.send(res)
    s.close()




if __name__ == '__main__':
    # Logger configuration
    logging.basicConfig(filename='http_server.log',
                        filemode='w',
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p',
                        level=logging.DEBUG)
    logger.setLevel(logging.DEBUG)

HOST = ''
PORT = 80
data = None

res = HTTPResponse()


s = RstegSocket(sport=PORT)
s.bind(HOST, PORT)
s.listen()
s.accept()
data = s.receive()
req = data[0]
if req[:3] == b'GET':
    send_res(s, bytes(res), '192.168.1.36', 49152)



"""
s.bind(HOST, PORT)
print('Binding server to parameters.')
s.listen()
print('RSTEG-TCP Server listening on port ' + str(PORT))
s.accept()
print('Connection established')
data = s.receive()
print('Data transfer ended')
if len(data) > 1: # cover with secret
    open('payload.jpeg', 'wb').write(data[0])
    print('Cover bytes received: ' + str(len(data[0])))
    open('secret.jpg', 'wb').write(data[1])
    print('Secret bytes received: ' + str(len(data[1])))
else:  # regular data
    open('payload.gif', 'wb').write(data[0])
    print('Cover bytes received: ' + str(len(data[0])))
print('Connection closed')
"""


