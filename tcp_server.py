#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

from rsteg_socket import RstegSocket
import logging


logger = logging.getLogger(__name__)

if __name__ == '__main__':
    # Logger configuration
    logging.basicConfig(filename='tcp_server.log',
                        filemode='w',
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p',
                        level=logging.DEBUG)
    logger.setLevel(logging.DEBUG)

    wait_flag = False

    s = RstegSocket(sport=80)
    s.listen()
    print('TCP Rsteg Socket listening on port 80.')
    s.accept()
    print('Connection accepted.')
    if wait_flag:
        d = s.wait_and_recv()
    else:
        data = b''
        while True:
            buf = s.recv(1500)
            if buf:
                data += buf
            if s.rtcp.end_event.is_set():
                print('RECV ' + str(len(data)) + ' BYTES')
                data = b''
                print('RECV ' + str(len(s.rtcp.ingress_secret_buffer)) + ' SECRET BYTES')
                s.rtcp.ingress_secret_buffer = b''
                print('Connection closed.')
                s.listen()
                s.accept()
                print('Connection accepted.')
