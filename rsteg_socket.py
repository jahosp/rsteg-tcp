#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

from rsteg_tcp import RstegTcp
from utils import State, retrans_prob
import threading
import time

class RstegSocket:

    def __init__(self, host=None, dport=None , sport=49512):
        """Class constructor.
        """
        self.sport = sport  # Source port, defaults to 49512
        self.dport = dport  # Destination port
        self.dst = host  # Destination host
        self.rtcp = RstegTcp(self.sport)  # Rsteg_Tcp instance
        self.th = None
        # Flags
        self.listening = False  # Socket is listening on sport

    def accept(self):
        while self.rtcp.state != State.ESTAB:
            pass

    def bind(self, host, port):
        self.dst = host
        self.sport = port
        self.rtcp.sport = self.sport

    def listen(self):
        self.th = threading.Thread(target=self.rtcp.start)
        self.th.start()
        self.listening = True

    def connect(self, host, port):
        if not self.listening:
            self.rtcp.start()
        self.rtcp.connect(host, port)
        while self.rtcp.state != State.ESTAB:
            pass

    def send(self, data):
        data_chunks = []
        interval = 1444  # payload chunk length
        # Slice the binary data in chunks the size of the payload length
        for n in range(0, len(data), interval):
            data_chunks.append(data[n:n + interval])
        # Send chunks
        for chunk in data_chunks:
            self.rtcp.send_data(chunk)
            # Wait for receiver to ACK
            while self.rtcp.ack != self.rtcp.out_pkt.seq:
                pass

    def rsend(self, cover, secret):
        """Chunks the data and the secret according to the MSS. The data and secret will be sent to the
        TCP receiver with the RSTEG method.
        :param cover: binary data to transmit as cover
        :param secret: binary data to transmit during fake retransmission
        """
        cover_chunks = []
        interval = 1414  # payload chunk length
        # Slice the binary data in chunks the size of the payload length
        for n in range(0, len(cover), interval):
            cover_chunks.append(cover[n:n + interval])
        # Do the same for the secret
        secret_chunks = []
        interval = 1444
        for n in range(0, len(secret), interval):
            secret_chunks.append(secret[n:n + interval])
        self.rtcp.secret_chunks = secret_chunks
        start_time = time.time()
        for chunk in cover_chunks:
            if self.rtcp.secret_signal:
                self.rtcp.send_data(chunk)  # data with signal
                timer = time.time()
                while self.rtcp.ack != self.rtcp.out_pkt.seq:
                    if (time.time() - timer) > 0.009:
                        self.rtcp.send_secret()
                        while self.rtcp.ack != self.rtcp.out_pkt.seq:
                            # wait for secret ack
                            pass
            else:
                self.rtcp.send_data(chunk)  # data without signal
                while self.rtcp.ack != self.rtcp.out_pkt.seq:
                    # todo timer
                    pass

            if not self.rtcp.secret_sent:
                self.rtcp.secret_signal = retrans_prob(self.rtcp.retrans_prob)
            else:
                self.rtcp.secret_signal = False
        print('Transfer time: %.2f' % round(time.time() - start_time, 2))

    def receive(self):
        if self.rtcp.transfer_end:
            recv_data = [self.rtcp.ingress_buffer]
            if len(self.rtcp.ingress_secret_buffer) > 0:
                recv_data.append(self.rtcp.ingress_secret_buffer)
            self.listening = False
        else:
            recv_data = None
        return recv_data

    def close(self):
        self.rtcp.close()
