#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

from rsteg_tcp import RstegTcp
from utils import State, retrans_prob
import time


class RstegSocket:
    """A wrapper for RstegTcp that offers socket primitives for communicating like Python sockets."""
    def __init__(self, host=None, dport=None, sport=49512, rprob=0.07):
        """Class constructor."""
        self.sport = sport  # Source port, defaults to 49512
        self.dport = dport  # Destination port
        self.dst = host  # Destination host
        self.rtcp = RstegTcp(self.sport, rprob)  # Rsteg_Tcp instance
        self.f_index = 0
        # Flags
        self.listening = False  # Socket is listening on sport

    def bind(self, host, port):
        """Configures the socket with the parameters supplied."""
        self.dst = host
        self.sport = port
        self.rtcp.sport = self.sport

    def listen(self):
        """Starts the RestegTCP module."""
        self.rtcp.restart(self.sport)
        self.rtcp.start()
        self.listening = True

    def accept(self):
        """Waits for a established TCP connection."""
        while self.rtcp.state != State.ESTAB:
            pass

    def connect(self, host, port):
        """Establishes a TCP connection with the host on port."""
        if not self.listening:
            self.listen()
        self.rtcp.connect(host, port)
        while self.rtcp.state != State.ESTAB:
            pass

    def send(self, data):
        """Chunks the data according to MSS and sends it to the TCP receiver."""
        data_chunks = []
        interval = 1446  # payload chunk length
        # Slice the binary data in chunks the size of the payload length
        for n in range(0, len(data), interval):
            data_chunks.append(data[n:n + interval])
        # Send chunks
        for chunk in data_chunks:
            self.rtcp.send_data(chunk)
            # Wait for ack event
            self.rtcp.ack_event.wait()
            self.rtcp.ack_event.clear()

    def rsend(self, cover, secret):
        """Chunks the data and the secret according to the MSS. The data and secret will be sent to the
        TCP receiver with the RSTEG method.
        :param cover: binary data to transmit as cover
        :param secret: binary data to transmit during fake retransmission
        """

        # Do the same for the secret
        secret_chunks = []
        interval = 1444
        for n in range(0, len(secret), interval):
            secret_chunks.append(secret[n:n + interval])
        self.rtcp.secret_chunks = secret_chunks
        n = 0
        start_time = time.time()

        # Send cover
        while len(cover) > 0:
            # Send cover signal and secret
            if self.rtcp.secret_signal:
                chunk = cover[:1414]
                cover = cover[1414:]
                self.rtcp.send_data(chunk)  # data with signal
                timer = time.time()
                while not self.rtcp.ack_flag:
                    if (time.time() - timer) > 0.008:
                        self.rtcp.send_secret()
                        n += 1
                        self.rtcp.ack_event.wait()
                        self.rtcp.ack_event.clear()  # clear ack event
            # Send cover
            else:
                chunk = cover[:1446]
                cover = cover[1446:]
                self.rtcp.send_data(chunk)  # data without signal
                self.rtcp.ack_event.wait()  # wait for ack event
                self.rtcp.ack_event.clear()  # clear ack event

            # Update secret_signal flag according to the retrans_prob except if the secret has been sent.
            if not self.rtcp.secret_sent:
                self.rtcp.secret_signal = retrans_prob(self.rtcp.retrans_prob)
            else:
                self.rtcp.secret_signal = False

        if self.rtcp.secret_sent:
            print('Secret successfully delivered.')
        else:
            print('# Cover data ended before delivering all the secret!')
            print('# Delivered ' + str(n * 1444) + ' secret bytes')

        print('# Transfer time: %.2f' % round(time.time() - start_time, 2))

        return (n * 1444)

    def recv(self, size, timeout=0):
        """Reads the RstegTCP data buffer for new recv data.
        :param size: integer for the data read size
        :param timeout: seconds for waiting to new pushed data in the buffer
        :return:
        """
        data = None
        self.rtcp.psh_event.wait(timeout)
        if len(self.rtcp.ingress_buffer) != 0:  # check if empty
            if len(self.rtcp.ingress_buffer) <= size:  #
                length = len(self.rtcp.ingress_buffer)
                data = self.rtcp.ingress_buffer[:length]  # take chunk
                self.rtcp.ingress_buffer = self.rtcp.ingress_buffer[length:]
                return data
            else:
                data = self.rtcp.ingress_buffer[:size]  # take chunk
                self.rtcp.ingress_buffer = self.rtcp.ingress_buffer[size:]
                return data
        else:  # if buffer is empty return None
            return data

    def wait_and_recv(self):
        """Waits until end_event is set before accessing to the data buffer."""
        data = []
        self.rtcp.end_event.wait()
        if self.rtcp.ingress_buffer:
            data.append(self.rtcp.ingress_buffer)
            print('RECV ' + str(len(data[0])) + ' BYTES')
        if self.rtcp.ingress_secret_buffer:
            data.append(self.rtcp.ingress_secret_buffer)
            print('RECV ' + str(len(data[1])) + ' SECRET BYTES')
        return data

    def close(self):
        """Closes the TCP stream."""
        self.rtcp.close()
        while self.rtcp.state != State.TIME_WAIT:
            pass
