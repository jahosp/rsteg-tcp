#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

from rsteg_socket import RstegSocket
import logging

logger = logging.getLogger(__name__)

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

s = RstegSocket(sport=PORT)
s.bind(HOST, PORT)
s.listen()
print('RSTEG-TCP Server listening on port ' + str(PORT))
s.accept()
while s.listening:
    data = s.receive()

if len(data) > 1: # cover with secret
    open('payload.gif', 'wb').write(data[0])
    print('Cover bytes received: ' + str(len(data[0])))
    open('secret.jpg', 'wb').write(data[1])
    print('Secret bytes received: ' + str(len(data[1])))
else:  # regular data
    open('payload.gif', 'wb').write(data[0])
    print('Cover bytes received: ' + str(len(data[0])))


