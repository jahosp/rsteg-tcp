#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

from scapy.layers.http import HTTPResponse, HTTP, HTTPRequest
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
        self.res = HTTP() / HTTPResponse()
        self.index = HTTP() / HTTPResponse(
            Content_Length=str(len(res_data)).encode(),
        ) / res_data
        self.not_found = HTTP() / HTTPResponse(
            Status_Code = b'404',
            Reason_Phrase = b'Not Found'
        )

    def start(self):
        """Starts the server and listens for requests."""
        self.s.listen()
        print('#####################################')
        print('# HTTP Server listening on port: ' + str(PORT) + ' #')
        print('#####################################')
        logger.debug('Server listening on port: ' + str(PORT))
        self.s.accept()
        self.listen()

    def process_request(self, req):
        if req[HTTPRequest].Method == b'POST':
            path = req[HTTPRequest].Path
            version = req[HTTPRequest].Http_Version
            length = req[HTTPRequest].Content_Length
            print('POST ' + path.decode() + ' ' + version.decode())
            data = b''
            data += bytes(req[HTTPRequest].payload)
            while len(data) < int(length):
                buf = self.s.recv(1500)
                if buf:
                    data += buf
                # print(str(len(data)) + ' of ' + str(length))
            print('RECEIVED ' + str(len(data)) + ' BYTES')
            open('upload.jpg', 'wb').write(data)
            self.s.send(bytes(self.res))


        if req[HTTPRequest].Method == b'GET':
            path = req[HTTPRequest].Path
            version = req[HTTPRequest].Http_Version
            print('GET ' + path.decode() + ' ' + version.decode())
            if path == b'/':
                self.s.send(bytes(self.index))
                print('200 OK')
            else:
                self.s.send(bytes(self.not_found))
                print('404 NOT FOUND')

    def listen(self):
        """Read the socket for requests and send a response accordingly."""
        req = self.s.recv(1024)
        if req:
            http_req = HTTPRequest(req)
            self.process_request(http_req)

        while True:
            req = self.s.recv(1024)
            if req:
                http_req = HTTPRequest(req)
                self.process_request(http_req)
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


