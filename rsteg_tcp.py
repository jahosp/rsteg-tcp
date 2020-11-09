#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

"""ATTENTION: linux sends an RST for crafted SYN packets. Execute the following to disable this behaviour
for the selected SPORT:
# iptables -A OUTPUT -p tcp --sport <SPORT> --tcp-flags RST RST -j DROP
"""

import hashlib
import logging
import threading

from scapy.all import *
from scapy.layers.inet import TCP, IP
from utils import State, find_compensation

logger = logging.getLogger(__name__)


class RstegTcp:

    def __init__(self, sport, rprob=0.07):
        """Class constructor.
        :param sport: Source port number.
        """
        self.s = L3RawSocket()  # L3 RawSocket used for sending and recv packets
        self.listen_thread = None  # Listener thread for incoming packets

        # TCP properties
        self.sport = sport  # Source port
        self.state = State.LISTEN  # TCP State
        self.seq = random.randrange(0, 2 ** 32)  # Sequence number
        self.ack = 0  # ACK number
        self.ack_flag = False
        self.ack_event = threading.Event()
        self.end_event = threading.Event()
        self.psh_event = threading.Event()
        self.out_pkt = IP() / TCP(sport=sport, seq=self.seq)  # Scapy packet with TCP segment
        self.ingress_buffer = b''  # Buffer for ingress binary data
        self.transfer_end = False

        # RSTEG properties
        self.retrans_prob = rprob  # Probability for fake retransmission
        self.secret_sent = False  # Flag for secret delivery (client side)
        self.secret_wait = False  # Flag for secret delivery (server side)
        self.secret_signal = False  # Flag for secret delivery signal
        self.secret_chunks = None  # Buffer for RSTEG secret binary data (client side)
        self.ingress_secret_buffer = b''  # Buffer for RSTEG secret binary data (server side)
        self.stego_key = 'WRONG_GENESIS'  # Shared key for the signal hash
        self.last_payload = None  # Store the payload of the signal segment (for the next checksum)
        self.rt_seq = 0

        # RTO properties
        self.timer = time.time()
        self.rtt = 0
        self.start_time = 0

        conf.recv_poll_rate = 0.0001

    def start(self):
        """Starts a thread executing function listen()."""
        self.state = State.LISTEN
        self.listen_thread = threading.Thread(target=self.listen)
        self.listen_thread.start()

    def restart(self, sport):
        """Restarts all class properties to their initial state."""
        self.listen_thread = None  # Listener thread for incoming packets
        self.sport = sport  # Source port
        self.state = State.LISTEN  # TCP State
        self.seq = random.randrange(0, 2 ** 32)  # Sequence number
        self.ack = 0  # ACK number
        self.ack_flag = False
        self.ack_event.clear()
        self.end_event.clear()
        self.psh_event.clear()
        self.out_pkt = IP() / TCP(sport=sport, seq=self.seq)  # Scapy packet with TCP segment
        self.ingress_buffer = b''  # Buffer for ingress binary data
        self.transfer_end = False
        # RSTEG properties
        self.retrans_prob = 0.07  # Probability for fake retransmission
        self.secret_sent = False  # Flag for secret delivery (client side)
        self.secret_wait = False  # Flag for secret delivery (server side)
        self.secret_signal = False  # Flag for secret delivery signal
        self.secret_chunks = None  # Buffer for RSTEG secret binary data (client side)
        self.ingress_secret_buffer = b''  # Buffer for RSTEG secret binary data (server side)
        self.last_payload = None  # Store the payload of the signal segment (for the next checksum)
        self.rt_seq = 0
        # RTO properties
        self.timer = time.time()
        self.rtt = 0
        self.start_time = 0

    def listen(self):
        """Sniffs recv TCP segments on sport until flag 'run' is set to False."""
        t = threading.currentThread()
        while getattr(t, 'run', True):
            # Sniff IP datagram
            datagram = self.s.recv(MTU)
            # Check if it's a TCP ACK and is destination is our listening port
            if datagram.haslayer(TCP) and datagram[TCP].dport == self.sport:
                self.handle_packet(datagram)

    def on_close(self):
        self.transfer_end = True
        self.psh_event.set()
        self.end_event.set()

    def rst(self, pkt):
        """Sends packet with RST segment to the source of pkt.
        :param pkt: recv packet
        """
        logger.debug('SND -> RST | LISTEN')
        self.out_pkt[IP].dst = pkt[IP].dst
        self.out_pkt[TCP].dport = pkt[TCP].dport
        self.out_pkt[TCP].flags = 'RA'
        self.s.outs.sendto(bytes(self.out_pkt), (self.out_pkt[IP].dst, 0))

    def connect(self, dst, dport):
        """Sends packet with SYN segment to the target supplied.
        :param dst: destination ip
        :param dport: destination port
        """
        logger.debug('SND -> SYN | SYN_SENT')
        self.state = State.SYN_SENT
        self.out_pkt[IP].dst = dst
        self.out_pkt[TCP].dport = dport
        self.out_pkt[TCP].flags = 'S'
        self.s.outs.sendto(bytes(self.out_pkt), (dst, 0))
        self.out_pkt[TCP].seq += 1

    def send_synack(self, pkt):
        """Sends packet with SYN_ACK segment in response to recv SYN.
        :param pkt: recv packet
        """
        logger.debug('SND -> SYN/ACK')
        self.out_pkt[IP].dst = pkt[IP].src
        self.out_pkt[TCP].dport = pkt[TCP].sport
        self.out_pkt[TCP].flags = 'SA'
        self.out_pkt[TCP].ack = pkt[TCP].seq + 1
        self.s.outs.sendto(bytes(self.out_pkt), (self.out_pkt[IP].dst, 0))

    def synack_recv(self, pkt):
        """Sends packet with ACK segment in response to the SYN_ACK.
        This ends the 3-way handshake and state shifts to ESTABLISHED.
        :param pkt: recv packet
        """
        logger.debug('SND -> ACK-SYN/ACK')
        self.out_pkt[TCP].ack = pkt[TCP].seq + 1
        self.out_pkt[TCP].flags = 'A'
        self.s.outs.sendto(bytes(self.out_pkt), (self.out_pkt[IP].dst, 0))
        self.state = State.ESTAB

    def close(self):
        """Start the 3-way Close by sending a packet with FIN segment."""
        logger.debug('SND -> FIN | FIN_WAIT1')
        self.state = State.FIN_WAIT1
        self.out_pkt[TCP].flags = 'F'
        self.s.outs.sendto(bytes(self.out_pkt), (self.out_pkt[IP].dst, 0))

    def last_ack(self, pkt):
        """Sends packet with the last ACK segment of the connection.
        :param pkt: recv packet
        """
        logger.debug('SND -> ACK | TIME_WAIT')
        self.state = State.TIME_WAIT
        self.out_pkt[TCP].flags = 'A'
        self.out_pkt[TCP].ack = pkt[TCP].seq + 1
        self.out_pkt[TCP].seq = pkt[TCP].ack
        self.s.outs.sendto(bytes(self.out_pkt), (self.out_pkt[IP].dst, 0))
        # TODO timer for time_wait
        time.sleep(0.1)
        self.listen_thread.run = False
        self.state = State.TIME_WAIT

    def ack_fin(self, pkt):
        """Sends packet with the FIN/ACK segment to recv FIN.
        :param pkt: recv packet
        """
        logger.debug('SND -> FIN/ACK | LAST_ACK')
        self.state = State.LAST_ACK
        self.out_pkt[TCP].flags = 'FA'
        self.out_pkt[TCP].ack = pkt[TCP].seq + 1
        self.out_pkt[TCP].seq = pkt[TCP].ack
        self.s.outs.sendto(bytes(self.out_pkt), (self.out_pkt[IP].dst, 0))

    def receive_data(self, pkt):
        """Extracts payload from PSH segment and ACK back.
        :param pkt: recv packet
        """
        logger.debug('INGRESS DATA')
        # Extract id_seq
        payload = bytes(pkt[TCP].payload)
        id_seq = payload[-32:]
        # Check id seq for retrans signal
        calc_id_seq = hashlib.sha256((self.stego_key + str(pkt[TCP].seq) + str(1)).encode()).digest()
        if calc_id_seq == id_seq:
            # Trigger fake retransmission
            self.secret_wait = True
            logger.debug('IS MATCH - TRIGGER RETRANS')
            # Clean payload from IS
            payload = payload[:-32]
        else:
            self.out_pkt[TCP].seq = pkt[TCP].ack
            self.out_pkt[TCP].ack += len(payload)
            self.out_pkt[TCP].flags = 'A'
            self.s.outs.sendto(bytes(self.out_pkt), (self.out_pkt[IP].dst, 0))

        # Add data to buffer
        self.ingress_buffer += payload
        self.psh_event.set()
        self.psh_event.clear()
        logger.debug('DATA RCV')

    def receive_secret(self, pkt):
        """Extracts secret from retransmitted PSH segment and ACK back.
        :param pkt: fake retransmission packet
        """
        logger.debug('SECRET DATA')
        # Flip wait flag
        self.secret_wait = False
        # Extract secret
        secret = bytes(pkt[TCP].payload)
        # Send ACK
        self.out_pkt[TCP].seq = pkt[TCP].ack
        self.out_pkt[TCP].ack += len(secret)
        self.out_pkt[TCP].flags = 'A'
        self.s.outs.sendto(bytes(self.out_pkt), (self.out_pkt[IP].dst, 0))
        # Clean and store secret
        secret = secret[:-2]  # strip compensation code
        secret = secret.strip(b'/')  # strip padding
        self.ingress_secret_buffer += secret  # add data to buffer

    def send_data(self, d):
        """Sends packet with PSH segment and payload data.
        The Identifying Sequence (IS) is appended to the payload data:
                           IS = H(SK + SEQ NUM + BIT)
            If BIT = 1 we're signaling the listener for a fake retrans
            If BIT = 0 we're just sending a normal packet
        :param d: binary data to send
        """
        logger.debug('EGRESS DATA')
        self.out_pkt[TCP].flags = "PA"

        # Append IS with the correct bit
        if self.secret_signal:
            id_seq = hashlib.sha256((self.stego_key + str(self.out_pkt[TCP].seq) + str(1)).encode()).digest()
            d = d + id_seq
            self.last_payload = d
            logger.debug('SND -> SIGNAL')
        else:
            # id_seq = hashlib.sha256((self.stego_key + str(self.out_pkt[TCP].seq) + str(0)).encode()).digest()
            # d = d + id_seq
            logger.debug('SND -> PSH')

        self.ack_flag = False
        self.s.outs.sendto(bytes(self.out_pkt / d), (self.out_pkt[IP].dst, 0))
        self.rt_seq = self.out_pkt.seq
        self.out_pkt.seq += len(d)

    def send_secret(self):
        """Prepares and sends fake retransmission packet with the secret."""
        logger.debug('SND -> SECRET')
        if len(self.secret_chunks) == 1:  # Last secret chunk
            self.secret_sent = True
            secret_payload = self.secret_chunks.pop(0)
        else:
            secret_payload = self.secret_chunks.pop(0)
        secret_payload = secret_payload.ljust(1444, b'/')  # Add padding to the secret for obfuscation
        # Find compensation value in order to obtain the same checksum as the last segment
        compensation_value = find_compensation(self.last_payload, secret_payload)
        compensation_value = struct.pack('H', compensation_value)  # Transform integer to unsigned 16b
        secret_payload = secret_payload + compensation_value
        self.out_pkt[TCP].flags = "PA"
        self.out_pkt[TCP].seq = self.rt_seq
        self.ack_flag = False
        self.s.outs.sendto(bytes(self.out_pkt / secret_payload), (self.out_pkt[IP].dst, 0))
        self.out_pkt[TCP].seq += len(secret_payload)

    def receive_ack(self, pkt):
        """Updates RTT timer and ack number."""
        # self.rtt = time.time() - self.timer
        self.ack = pkt[TCP].ack
        self.ack_flag = True

        if self.ack_event.is_set():
            self.ack_event.clear()
        self.ack_event.set()

        if self.psh_event.is_set():
            self.psh_event.clear()


    def handle_packet(self, pkt):
        """Send incoming packet to a handler function according to the current TCP state
        :param pkt: recv packet
        """
        flag = pkt[TCP].flags  # incoming packet flag
        if self.state == State.ESTAB:
            if flag & 0x01:  # FIN
                logger.debug('RCV -> FIN | CLOSE_WAIT')
                self.state = State.CLOSE_WAIT
                return self.ack_fin(pkt)
            if flag & 0x08:  # PSH
                self.start_time = time.time()
                if self.secret_wait:
                    logger.debug('RCV -> SCRT')
                    return self.receive_secret(pkt)
                else:
                    logger.debug('RCV -> PSH | ESTAB')
                    return self.receive_data(pkt)
            if flag & 0x10:  # ACK
                logger.debug('RCV -> ACK | ESTAB')
                return self.receive_ack(pkt)

        if self.state == State.LISTEN:
            if flag & 0x02:  # SYN
                logger.debug('RCV -> SYN | SYN_RCVD')
                self.state = State.SYN_RCVD
                return self.send_synack(pkt)
            return self.rst(pkt)

        if self.state == State.SYN_RCVD:
            if flag & 0x10:  # ACK
                logger.debug('RCV -> ACK | ESTAB')
                self.state = State.ESTAB
            return

        if self.state == State.SYN_SENT:
            if flag & 0x12:  # SYN_ACK
                logger.debug('RCV -> SYN_ACK ')
                return self.synack_recv(pkt)

        if self.state == State.FIN_WAIT1:
            if flag & 0x11:  # ACK for FIN
                logger.debug('RCV -> ACK FIN1')
                self.state = State.TIME_WAIT
                return self.last_ack(pkt)

        if self.state == State.LAST_ACK:
            if flag & 0x10:  # ACK
                logger.debug('RCV -> LAST_ACK')
                self.state = State.CLOSED
                self.listen_thread.run = False
                self.on_close()

        if self.state == State.CLOSE_WAIT:
            if flag & 0x11:  # FIN/ACK
                logger.debug('RCV -> FIN/ACK')


if __name__ == '__main__':
    # Logger configuration
    logging.basicConfig(filename='listener.log',
                        filemode='w',
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p',
                        level=logging.DEBUG)
    logger.setLevel(logging.DEBUG)
