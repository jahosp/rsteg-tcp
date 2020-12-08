#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: Javier Hospital <jahos@protonmail.com>

from scapy.layers.http import HTTPResponse, HTTP, HTTPRequest
from rsteg_socket import RstegSocket
import logging

logger = logging.getLogger(__name__)


class HttpServer:
    """A simple HTTP Server using RstegSocket."""
    def __init__(self, port, rprob=0.07):
        """Constructor"""
        self.s = RstegSocket(rprob=rprob, sport=port)
        self.s.bind('', port)

        # Load in memory the html responses
        index_data = open('./index.html', 'rb').read()
        upload_data = open('./upload.html', 'rb').read()
        # Load the HTTP Response data structure
        self.res = HTTP() / HTTPResponse()
        self.index = HTTP() / HTTPResponse(
            Content_Length=str(len(index_data)).encode(),
        ) / index_data
        self.upload = HTTP() / HTTPResponse(
            Content_Length=str(len(upload_data)).encode(),
        ) / upload_data
        self.not_found = HTTP() / HTTPResponse(
            Status_Code=b'404',
            Reason_Phrase=b'Not Found'
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
        """Process the request and send the proper response back.
        :param req: HTTP request received from RstegSocket
        """
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
            print('RECEIVED ' + str(len(data)) + ' BYTES')
            open('upload.jpg', 'wb').write(data)
            if len(self.s.rtcp.ingress_secret_buffer) > 0:
                secret = self.s.rtcp.ingress_secret_buffer
                self.s.rtcp.ingress_secret_buffer = b''
                print('RECEIVED ' + str(len(secret)) + ' SECRET BYTES')
                open('secret.jpg', 'wb').write(secret)
            self.s.send(bytes(self.res))

        if req[HTTPRequest].Method == b'GET':
            path = req[HTTPRequest].Path
            version = req[HTTPRequest].Http_Version
            print('GET ' + path.decode() + ' ' + version.decode())
            if path == b'/':
                self.s.send(bytes(self.index))
                print('200 OK')
            elif path == b'/upload':
                self.s.send(bytes(self.upload))
                print('200 OK')
            else:
                self.s.send(bytes(self.not_found))
                print('404 NOT FOUND')

    def listen(self):
        """Poll the socket for requests, process them and send a response accordingly."""
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
