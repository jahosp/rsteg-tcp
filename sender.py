#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

"""ATTENTION: linux sends an RST for crafted SYN packets. Execute the following to disable this behaviour
for the selected SPORT:
# iptables -A OUTPUT -p tcp --sport <SPORT> --tcp-flags RST RST -j DROP

"""

from scapy.all import *
from scapy.layers.inet import IP, TCP
from utils import is_ipv4, retrans_prob, find_chk_collision
import PySimpleGUIQt as sg
import logging
import hashlib
import time

logger = logging.getLogger(__name__)


class RstegTcpClient:
    """This class creates a RSTEG TCP client with Scapy as a packet crafting method.
    - Connect to a HOST:PORT from a desired port and establish a 3-way handshake.
    - Build and send PSH packets for sending the payload.
    - Build and send a secret packet as a retransmission
    - ACK received packets.
    - Close session with the 3-way termination.

    """

    def __init__(self, dhost, dport, secret, sport=49152, rprob=0.07):
        """Class constructor.
        :param dhost: String with the destination IP addr.
        :param dport: Integer with the destination port number.
        :param secret: Steganogram to be delivered during.
        :param sport: Optional parameter for the source port number. Defaults to 1009.
        """
        self.s = L3RawSocket()  # L3 Scapy Raw Socket
        self.ip = IP(dst=dhost)  # Scapy IP packet with the server IP in it
        self.dport = dport  # Destination port
        self.sport = sport  # If none specified, defaults to unassigned 1009 port
        self.seq = 0  # Sequence number
        self.ack = 0  # Acknowledge number
        self.connected = False  # Flag for connection established
        self.timeout = 3  # Timeout window for retransmission (in seconds)
        self.secret_payload = secret  # Steganogram
        self.secret_sent = False  # Flag for secret delivered
        self.window_size = None
        self.stego_key = 'WRONG_GENESIS'  # Shared SK
        self.signal_retrans = False  # Flag for signaled retransmission
        self.retrans_prob = rprob  # Retrans probability
        self.last_chksum = None  # Checksum from the last signal packet payload

        self.timer_flag = True
        self.start_time = None
        self.end_time = None

    def acknowledge(self, pkt):
        """Crafts and sends the ACK for the parameter-supplied packet.
        :param pkt: Received Scapy packet
        """
        # Calculate the new acknowledged seq number
        self.ack = pkt[TCP].seq + len(pkt[Raw])
        # Craft the packet and send it
        ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        send(ack, verbose=0)

    def connect(self):
        """Performs the TCP 3-way handshake.
        - Random ISN
        SYN ->
        SYN/ACK <-
        ACK ->
        TODO: Additional verification for SYN/ACK
        """
        # Random seq number
        self.seq = random.randrange(0, (2 ** 32) - 1)
        # Craft SYN packet
        syn = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='S')
        # Send SYN and wait timeout for SYN_ACK
        syn_ack = self.s.sr1(syn, timeout=self.timeout, verbose=0)  # sr1 = send & receive layer 3
        # Update ACK and SEQ fields
        self.ack = syn_ack[TCP].seq + 1
        self.seq = syn_ack[TCP].ack
        # Get Window Size
        self.window_size = syn_ack[TCP].window
        # Craft ACK for the SYN_ACK and send it
        ack = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='A', ack=self.ack)
        self.s.send(ack)
        logger.debug('3-way handshake completed')
        # Connection established
        self.connected = True

    def close(self):
        """Close the session with the 3-way termination."""
        self.connected = False
        # Craft and send the FIN/ACK
        logger.debug('SND -> FIN')
        fin = self.ip / TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        # fin_ack = self.s.sr1(fin, timeout=self.timeout, retry=5, filter='tcp[tcpflags] & tcp-fin != 0', verbose=0)
        fin_ack = self.s.sr1(fin, timeout=self.timeout, retry=5, verbose=0)
        logger.debug('RCV -> FIN/ACK')
        # Update ACK and SEQ fields
        self.ack = fin_ack[TCP].seq + 1
        self.seq = fin_ack[TCP].ack
        # Send final ACK
        ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        logger.debug('SND -> FINAL_ACK')
        self.s.send(ack)

        logger.debug('Session terminated.')
        logger.debug('RSTEG TIME: ' + str(self.end_time))

    def build(self, payload):
        """Creates an IP/TCP package with the supplied payload.
        The id sequence is added at the end of the payload:
                    IS = H(SK + SEQ NUM + BIT)
            If BIT = 1 we're signaling the listener for a retrans
            If BIT = 0 we're just sending a normal packet
        :param payload: Content for the tcp payload
        :return: Returns the crafted Scapy IP/TCP package.
        """
        if self.signal_retrans:
            id_seq = hashlib.sha256((self.stego_key + str(self.seq) + str(1)).encode()).digest()
            payload = payload + id_seq
            self.last_chksum = hex(checksum(payload))  # store checksum

        else:
            id_seq = hashlib.sha256((self.stego_key + str(self.seq) + str(0)).encode()).digest()
            payload = payload + id_seq

        psh = self.ip / TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack) / payload

        return psh

    def build_secret(self):
        """Creates an IP/TCP package with a chunk secret as payload.
        It also adds padding to fill all the payload in case the chunk takes less than the MTU
        """

        if len(self.secret_payload) == 1:  # Last secret chunk
            self.secret_sent = True
            secret_payload = self.secret_payload.pop(0)
            self.end_time = time.time() - self.start_time

        else:
            secret_payload = self.secret_payload.pop(0)

        secret_payload = secret_payload.ljust(1444, b'/')  # Add padding to the secret for obfuscation
        compensation_value = find_chk_collision(self.last_chksum, secret_payload)
        compensation_value = struct.pack('H', compensation_value)  # Transform integer to unsigned 16b
        secret_payload = secret_payload + compensation_value
        secret_psh = self.ip / TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq,
                                   ack=self.ack) / secret_payload

        return secret_psh

    def send(self, payload):
        """Crafts and sends a packet with the desired payload.
        If ack times out, it will craft and sent the secret.
        If secret has already been sent it will retransmit the packet.
        :param payload: Received Scapy packet
        TODO: Refactor and make it more readable
        """
        # Invoke retransmission
        if self.signal_retrans:
            logger.debug('SND -> RETRANS SIGNAL')
            psh = self.build(payload)  # Signal added
            ack = self.s.sr1(psh, timeout=0.01, retry=0, verbose=0)
            if ack is None:  # Ack not rcv
                logger.debug('ACK TIMEOUT')
                logger.debug('SND -> SCRT')
                self.signal_retrans = False

                if self.timer_flag:
                    self.start_time = time.time()
                    self.timer_flag = False

                secret_psh = self.build_secret()
                ack = self.s.sr1(secret_psh, timeout=self.timeout, verbose=0)
                if ack is not None:  # Response for secret
                    logger.debug('ACK SCRT')
                    # self.secret_sent = True
                    self.seq += len(psh[Raw])
                else:  # Secret lost
                    logger.debug('OH SHIT')
                    psh = self.build(payload)
                    logger.debug('EDGE CASE')
                    ack = self.s.sr1(psh, timeout=1, retry=0, verbose=0)
        # Normal data transfer
        else:
            psh = self.build(payload)
            logger.debug('SND -> PSH')
            ack = self.s.sr1(psh, timeout=1, retry=0, verbose=0)
            if ack is None:  # Ack not rcv, normal retrans
                logger.debug('SND -> PSH | RETRANS')
                ack = self.s.sr1(psh, timeout=2, retry=3, verbose=0)
                if ack is not None:  # ACK for RETRANS
                    logger.debug('RCV -> ACK')
                    self.seq += len(psh[Raw])
            else:
                logger.debug('RCV -> ACK')
                self.seq += len(psh[Raw])

        if not self.secret_sent:
            self.signal_retrans = retrans_prob(self.retrans_prob)
        else:
            self.signal_retrans = False


def send_over_http(DHOST, DPORT, SPORT, COVER, SECRET, rprob):
    """
    Opens a TCP connection with DHOST from SPORT to DPORT and sends
    the COVER as an HTTP POST request. While doing the data transfer
    the SECRET will be sent following the RSTEG method.
    :param DHOST: ip addr of the host
    :param DPORT: host port number
    :param SPORT: source port number
    :param COVER: file path for cover data
    :param SECRET: file path for secret data
    :return:
    """
    # Read the data and save as a binary
    data = open(COVER, 'rb').read()
    secret = open(SECRET, 'rb').read()

    print("Sending data as an HTTP POST request.")
    window.refresh()

    # HTTP Post request with data payload
    header = "POST /upload HTTP/1.1\r\n"
    header += "Host: foo.example\r\n"
    header += "Content-Type: application/octet-stream\r\n"
    header += "Content-Length: " + str(len(data)) + "\r\n\n"

    payload = header.encode('utf-8') + data

    payload_chunks = []
    interval = 1414  # payload chunk length
    # Slice the binary data in chunks the size of the payload length
    for n in range(0, len(payload), interval):
        payload_chunks.append(payload[n:n + interval])

    secret_chunks = []
    interval = 1444
    for n in range(0, len(secret), interval):
        secret_chunks.append(secret[n:n + interval])

    print("Data chunks: " + str(len(payload_chunks)))
    print("Secret chunks: " + str(len(secret_chunks)))
    window.refresh()

    # Connect to the server, send the payload (+ rsteg the secret) and close connection
    logger.debug('Creating TCP Session at %s:%s', DHOST, DPORT)
    print('Opening TCP Session at ' + DHOST + ':' + SPORT)
    window.refresh()

    client = RstegTcpClient(DHOST, int(DPORT), secret_chunks, int(SPORT), float(rprob))

    client.connect()

    print('3-way handshake completed.')
    window.refresh()
    start_time = time.time()

    for chunk in payload_chunks:
        client.send(chunk)

    print('Data transfer ended.')
    end_time = time.time() - start_time
    print('Transfer time: %.2f seconds ...' % end_time)
    print('Cover speed: %.2f' % (len(payload)/end_time) + ' bytes')
    print('Secret speed: %.2f' % (len(secret)/end_time) + ' bytes')
    window.refresh()
    client.close()

    logger.debug('TCP Session closed.')
    print('TCP Session closed')

    window.refresh()


# Start point
if __name__ == '__main__':
    # Logger configuration
    logging.basicConfig(filename='sender.log',
                        filemode='w',
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p',
                        level=logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    # port = random.randint(49152, 65535)
    # Application Layout
    sg.theme('Default')
    layout = [[sg.Text("Please enter the following parameters:")],
              [sg.Text('Destination Host IP', size=(15, 1)), sg.InputText(enable_events=True, key='dhost')],
              [sg.Text('Destination Port ', size=(15, 1)), sg.InputText(enable_events=True, key='dport',
                                                                        default_text='80')],
              [sg.Text('Source Port', size=(15, 1)), sg.InputText(enable_events=True, key='sport',
                                                                  default_text='49152')],
              [sg.Text('Cover data', size=(8, 1)), sg.Input(key='cover'), sg.FileBrowse()],
              [sg.Text('Secret data', size=(8, 1)), sg.Input(key='secret'), sg.FileBrowse()],
              [sg.HorizontalSeparator("grey")],
              [sg.Text('Send as:'), sg.Combo(values=['HTTP', 'TCP Only'], default_value='HTTP', readonly=True,
                                             auto_size_text=True)],
              [sg.Text('Retransmission probability'),
               sg.InputText(default_text='0.07', enable_events=True, key='prob')],
              [sg.HorizontalSeparator("grey")],
              [sg.Text('STATUS')],
              [sg.Output(size=(40, 10), key='-OUTPUT-')],
              [sg.HorizontalSeparator()],
              [sg.Button('Submit'), sg.Button('Clear log')]]

    # Create the window
    window = sg.Window('RSTEG TCP', layout)

    # Window Event Loop
    while True:
        event, values = window.read()
        # Quit event
        if event == sg.WINDOW_CLOSED:
            break
        # Submit form event
        if event == 'Submit' and values['dhost'] and values['dport'] and values['sport'] \
                and values['cover'] and values['secret']:
            # Let's validate the form input
            if is_ipv4(values['dhost']):
                if 1 <= int(values['dport']) <= 65535:
                    if 1 <= int(values['sport']) <= 65535:
                        print('Parameters are valid!')
                        print('Starting RSTEG TCP')
                        window.refresh()
                        send_over_http(values['dhost'], values['dport'], values['sport'],
                                       values['cover'], values['secret'], values['prob'])
                    else:
                        print('Source Port is not valid.')
                else:
                    print('Destination Port is not valid.')
            else:
                print('Destination Host IP is not valid.')

        # Clear log event
        if event == 'Clear log':
            window['-OUTPUT-'].update('')

    # Remove window from screen
    window.close()
