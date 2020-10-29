#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

from rsteg_socket import RstegSocket
import logging

logger = logging.getLogger(__name__)

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

s = RstegSocket()
s.connect(HOST, DPORT)
print('RSTEG-TCP Client connected to ' + HOST + ' on port ' + str(DPORT))
# s.send('Hemlo')  # normal send
s.rsend(cover_data, secret_data)  # sneaky send
print('DATA SENT')
s.close()
print('Closing connection.')


