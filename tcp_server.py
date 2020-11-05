#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

from rsteg_socket import RstegSocket


if __name__ == '__main__':

    s = RstegSocket(sport=80)
    s.listen()
    print('TCP Rsteg Socket listening on port 80.')
    s.accept()
    print('Connection accepted.')
    data = b''
    while True:
        buf = s.recv(1024)
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