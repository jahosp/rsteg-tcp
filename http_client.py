#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

from scapy.layers.http import HTTPRequest, HTTP
from rsteg_socket import RstegSocket
import logging

logger = logging.getLogger(__name__)

class HttpClient():
    """A simple HTTP Client build over RstegSocket."""
    def __init__(self, port=49512, rprob=0.07):
        self.sport = port
        self.s = RstegSocket(self.sport, rprob)
        self.timeout = 10

    def request(self, req, host):
        """Send the request to host and return response."""
        self.s.connect(host, 80)
        self.s.send(req)
        res = self.s.recv(1024, self.timeout)
        self.s.close()

        return res

    def rsteg_request(self, req, secret, host):
        """Send the request to host and return response."""
        self.s.connect(host, 80)
        self.s.rsend(req, secret)
        res = self.s.recv(1024, self.timeout)
        self.s.close()

        return res

    def create_post_request(self, host, path, data, content_type ):
        post_req = HTTP() / HTTPRequest(
            Method=b'POST',
            Path=path.encode(),
            Host=host.encode(),
            Connection=b'keep-alive',
            Content_Length=str(len(data)).encode(),
            Content_Type=content_type.encode()
        ) / data
        return post_req

    def create_get_request(self, host, path):
        get_req = HTTP() / HTTPRequest(
            Accept_Encoding=b'gzip, deflate',
            Cache_Control=b'no-cache',
            Connection=b'keep-alive',
            Host=host.encode(),
            Path=path.encode(),
            Pragma=b'no-cache'
        )
        return get_req

if __name__ == '__main__':
    # Logger configuration
    logging.basicConfig(filename='http_client.log',
                        filemode='w',
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p',
                        level=logging.DEBUG)
    logger.setLevel(logging.DEBUG)

