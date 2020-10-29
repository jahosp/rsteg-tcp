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
print(data)


