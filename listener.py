#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

"""ATTENTION: linux sends an RST for crafted SYN packets. Execute the following to disable this behaviour
for the selected SPORT:
# iptables -A OUTPUT -p tcp --sport <SPORT> --tcp-flags RST RST -j DROP

"""

from enum import Enum
from scapy.all import *
from scapy.layers.inet import TCP, IP
import logging

logger = logging.getLogger(__name__)


class State(Enum):
    """TCP states as defined in the RFC 793."""
    CLOSED = 1
    LISTEN = 2
    ESTAB = 3
    SYN_RCVD = 4
    SYN_SENT = 5
    CLOSE_WAIT = 6
    LAST_ACK = 7
    FIN_WAIT1 = 8
    FIN_WAIT2 = 9
    CLOSING = 10
    TIME_WAIT = 11


class RstegTcpServer:
    """This class creates a RSTEG TCP server with Scapy as a packet crafting method.
    - Listens incoming packets and handles the response according to TCP states.
    - 3-way handshake, ack data transfer, 3-way termination.
    - Timeouts and retry handled by Scapy except for secret transfer.
    - Saves data transferred to disk
    - RSTEG: first data rcv is not ack and waits for secret
    TODO:
        - implement tcp sliding window
        - implement threads for faster ack
        - implement other rsteg situations
        - implement other tcp features

    """

    def __init__(self, sport):
        """Class constructor.
        :param sport: Source port number.
        """
        self.ip = None  # Scapy IP packet with the client IP
        self.dport = 0  # Destination port
        self.sport = sport  # Source port
        self.seq = 0  # Sequence number
        self.ack = 0  # Acknowledge Number
        self.connected = False  # Connection established
        self.state = State.LISTEN  # Current server TCP state
        self.timeout = 3  # Timeout window for retransmission (in seconds)
        self.payload = b''  # Binary data recv
        self.rsteg_trigger = True  # Flag for rsteg mechanism
        self.rsteg_wait = False  # Flag that marks if we're waiting the secret
        self.window_size = None

    def handle_packet(self, pkt):
        """Reads the TCP flag from the packet in order to choose the function that handles it (according to the state).
        :param pkt: Scapy packet received by the L3 socket.
        :return: Returns the appropriated handling function.
        """
        flag = pkt[TCP].flags  # incoming packet flag

        if self.state == State.LISTEN:
            if flag & 0x02:  # SYN
                logger.debug('RCV -> SYN | SYN_RCVD')
                self.state = State.SYN_RCVD
                return self.syn_ack(pkt)
            return self.rst(pkt)

        if self.state == State.SYN_RCVD:
            if flag & 0x10:  # ACK
                logger.debug('RCV -> ACK | ESTAB')
                self.state = State.ESTAB
            return

        if self.state == State.ESTAB:
            if flag & 0x01:  # FIN
                logger.debug('RCV -> FIN | CLOSE-WAIT')
                self.state = State.CLOSE_WAIT
                return self.ack_fin(pkt)
            if flag & 0x08:  # PSH
                if self.rsteg_wait:  # we're waiting for the secret
                    logger.debug('RCV -> SCRT')
                    return self.ack_scrt(pkt)
                else:  # normal data
                    logger.debug('RCV -> PSH | DATA-TRANSFER')
                    return self.ack_psh(pkt)
            return

        if self.state == State.LAST_ACK:
            if flag & 0x10:  # ACK:
                logger.debug('RCV -> ACK | CLOSED')
                self.state = State.CLOSED
                return self.save_payload()
            return

        if self.state == State.CLOSED:
            if not flag & 0x04:  # all except RST
                logger.debug('SND -> RST | CLOSED')
                return self.rst(pkt)
            return

        logger.debug('None')

    def syn_ack(self, pkt):
        """Build and send the SYN/ACK packet in response to client SYN.
        :param pkt: Scapy SYN packet.
        """
        self.seq = random.randrange(0, (2 ** 32) - 1)
        self.ip = IP(dst=pkt[IP].src)
        self.dport = pkt[TCP].sport
        self.ack = pkt[TCP].seq + 1
        syn_ack = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='SA', ack=self.ack)
        send(syn_ack)
        logger.debug('SND -> SYN/ACK')

    def ack_fin(self, pkt):
        """Build and send the FIN/ACK packet in response to client FIN.
        :param pkt:
        """
        self.state = State.LAST_ACK
        self.ack = pkt[TCP].seq + 1
        self.seq = pkt[TCP].ack
        ack_fin = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='FA', ack=self.ack)
        logger.debug('SND -> FIN/ACK | LAST_ACK')
        send(ack_fin)

    def ack_psh(self, pkt):
        """Extracts payload data and acknowledges back."""
        payload = bytes(pkt[TCP].payload)
        logger.debug('DATA RCV')
        self.payload += payload

        if self.rsteg_trigger:
            # We have the packet but we'll trigger a retransmission for the payload
            logger.debug('TRIGGER SECRET')
            self.rsteg_wait = True
            self.rsteg_trigger = False
        else:
            self.ack = pkt[TCP].seq + len(pkt[TCP].payload)
            self.seq = pkt[TCP].ack
            ack = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='A', ack=self.ack)
            send(ack)
            logger.debug('SND -> ACK | DATA-TRANSFER')

    def ack_scrt(self, pkt):
        """Extracts secret data and acknowledges back."""
        secret = bytes(pkt[TCP].payload)
        logger.debug('SCRT RCV')
        print(str(secret))
        self.rsteg_wait = False
        self.ack = pkt[TCP].seq + len(pkt[TCP].payload)
        self.seq = pkt[TCP].ack
        ack = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='A', ack=self.ack)
        send(ack)
        logger.debug('SND -> ACK | DATA-TRANSFER')

    def rst(self, pkt):
        """Build and send a RST packet to non existing connection."""
        ip = IP(dst=pkt[IP].src)
        rst = ip / TCP(sport=self.sport, dport=pkt[TCP].sport, flags='RA', seq=0, ack=0)
        send(rst)

    def save_payload(self):
        """Saves the payload to disk and changes state back to LISTEN."""
        open('meme.jpg', 'wb').write(self.payload)
        logger.debug('Payload saved to disk')
        self.state = State.LISTEN
        print('LISTEN')
        self.rsteg_trigger = True
        self.rsteg_wait = False


if __name__ == '__main__':
    # Logger configuration
    logging.basicConfig(filename='listener.log',
                        filemode='w',
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p',
                        level=logging.DEBUG)
    logger.setLevel(logging.DEBUG)

    # Config params
    SPORT = 80

    server = RstegTcpServer(SPORT)

    # Create a Layer 3 RawSocket from where we'll sniff packets
    socket = L3RawSocket()
    while True:
        # Sniff IP datagram
        datagram = socket.recv(MTU)
        # Check if it's TCP and is destination is our listening port
        if datagram.haslayer(TCP) and datagram[TCP].dport == SPORT:
            server.handle_packet(datagram)  # process the packet
