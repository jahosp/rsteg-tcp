#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

from scapy.layers.http import HTTPResponse, HTTP
from rsteg_socket import RstegSocket
import logging

logger = logging.getLogger(__name__)

class HttpServer():
    """A simple HTTP Server using RstegSocket."""
    def __init__(self, port):
        """Constructor"""
        self.s = RstegSocket(sport=port)
        self.s.bind('', port)

        # GET / response
        res_data = open('./index.html', 'rb').read()
        self.res = HTTP() / HTTPResponse(
            Content_Length=str(len(res_data)).encode(),
        ) / res_data

    def start(self):
        """Starts the server and listens for requests."""
        self.s.listen()
        print('#####################################')
        print('# HTTP Server listening on port: ' + str(PORT) + ' #')
        print('#####################################')
        logger.debug('Server listening on port: ' + str(PORT))
        self.s.accept()
        self.listen()

    def listen(self):
        """Read the socket for requests and send a response accordingly."""
        req = b''
        while True:
            buf = self.s.recv(1024)
            if not buf:
                pass
            else:
                req += buf

            if req[:3] == b'GET':
                print('GET / HTTP 1.1')
                logger.debug('GET / HTTP 1.1')
                self.s.send(bytes(self.res))
                req = b''
                print('200 OK')

            if self.s.rtcp.end_event.is_set():
                self.s.listen()
                self.s.accept()



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


s = HttpServer(PORT)
s.start()


