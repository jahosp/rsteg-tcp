#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

"""ATTENTION: linux sends an RST for crafted SYN packets. Execute the following to disable this behaviour
for the selected SPORT:
# iptables -A OUTPUT -p tcp --sport <SPORT> --tcp-flags RST RST -j DROP

"""

from scapy.all import *
from scapy.layers.inet import IP, TCP
import PySimpleGUIQt as sg
import logging
from utils import is_ipv4

logger = logging.getLogger(__name__)


class RstegTcpClient:
    """This class creates a RSTEG TCP client with Scapy as a packet crafting method.
    - Connect to a HOST:PORT from a desired port and establish a 3-way handshake.
    - Build and send PSH packets for sending the payload.
    - Build and send a secret packet as a retransmission
    - ACK received packets.
    - Close session with the 3-way termination.

    """

    def __init__(self, dhost, dport, secret, sport=1009, ):
        """Class constructor.
        :param dhost: String with the destination IP addr.
        :param dport: Integer with the destination port number.
        :param secret: Steganogram to be delivered during.
        :param sport: Optional parameter for the source port number. Defaults to 1009.
        """
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
        syn_ack = sr1(syn, timeout=self.timeout, verbose=0)  # sr1 = send & receive layer 3
        # Update ACK and SEQ fields
        self.ack = syn_ack[TCP].seq + 1
        self.seq = syn_ack[TCP].ack
        # Get Window Size
        self.window_size = syn_ack[TCP].window
        # Craft ACK for the SYN_ACK and send it
        ack = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='A', ack=self.ack)
        send(ack, verbose=0)
        logger.debug('3-way handshake completed')
        # Connection established
        self.connected = True

    def close(self):
        """Close the session with the 3-way termination."""
        self.connected = False
        # Craft and send the FIN/ACK
        logger.debug('SND -> FIN')
        fin = self.ip / TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        fin_ack = sr1(fin, timeout=self.timeout, retry=5, filter='tcp[tcpflags] & tcp-fin != 0', verbose=0)
        logger.debug('RCV -> FIN/ACK')
        # Update ACK and SEQ fields
        self.ack = fin_ack[TCP].seq + 1
        self.seq = fin_ack[TCP].ack
        # Send final ACK
        ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        logger.debug('SND -> FINAL_ACK')
        send(ack, verbose=0)

        logger.debug('Session terminated.')

    def build(self, payload):
        """Creates an IP/TCP package with the supplied payload.
        :param payload: Content for the tcp payload
        :return: Returns the crafted Scapy IP/TCP package.
        """
        psh = self.ip / TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack) / Raw(load = payload)
        return psh

    def build_secret(self):
        """Creates an IP/TCP package with the secret as payload.
        It also adds padding to fill all the payload
        """
        secret_payload = str.encode(self.secret_payload)
        secret_payload = secret_payload.ljust(1440, b'\0')  # Add padding to the secret for obfuscation
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
        psh = self.build(payload)
        logger.debug('SND -> PSH')
        ack = sr1(psh, timeout=1, retry=0, verbose=0)

        if ack is None and not self.secret_sent:  # No response and secret not sent yet
            logger.debug('ACK TIMEOUT')
            logger.debug('SND -> SCRT')
            secret_psh = self.build_secret()
            ack = sr1(secret_psh, timeout=self.timeout, verbose=0)
            if ack is not None:  # Response for secret
                logger.debug('ACK SCRT')
                self.secret_sent = True
                self.seq += len(psh[Raw])
            else:  # Secret lost
                logger.debug('OH SHIT')

        elif ack is None and self.secret_sent:  # No response, secret already sent.
            logger.debug('SND -> PSH | RETRANS')
            ack = sr1(psh, timeout=2, retry=3, verbose=0)
            if ack is not None:  # ACK for RETRANS
                logger.debug('RCV -> ACK')
                self.seq += len(psh[Raw])

        else:  # Response, got ACK
            logger.debug('RCV -> ACK')
            self.seq += len(psh[Raw])


def send_over_http(DHOST, DPORT, SPORT, COVER, SECRET):
    # Read the data and save as a binary
    data = open(COVER, 'rb').read()

    # HTTP Post request with data payload
    header = "POST /test HTTP/1.1\r\n"
    header += "Host: foo.example\r\n"
    header += "Content-Type: application/octet-stream\r\n"
    header += "Content-Length: " + str(len(data)) + "\r\n\n"

    payload = header.encode('utf-8') + data

    chunks = []
    interval = 1440  # packet payload length
    # Slice the binary data in chunks the size of the payload length
    for n in range(0, len(payload), interval):
        chunks.append(payload[n:n + interval])

    # Connect to the server, send the payload (+ rsteg the secret) and close connection
    logger.debug('Creating TCP Session at %s:%s', DHOST, DPORT)
    print('Opening TCP Session at ' + DHOST + ':' + SPORT)
    window.refresh()
    client = RstegTcpClient(DHOST, int(DPORT), SECRET, int(SPORT))
    client.connect()
    window.refresh()
    print('3-way handshake completed.')
    window.refresh()
    for chunk in chunks:
        client.send(chunk)
    print('Cover sent as an HTTP POST request.')
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

    # Application Layout
    sg.theme('Default')
    layout = [[sg.Text("Please enter the following parameters:")],
              [sg.Text('Destination Host IP', size=(15, 1)), sg.InputText(enable_events=True, key='dhost')],
              [sg.Text('Destination Port ', size=(15, 1)), sg.InputText(enable_events=True, key='dport')],
              [sg.Text('Source Port', size=(15, 1)), sg.InputText(enable_events=True, key='sport')],
              [sg.Text('Cover data', size=(8, 1)), sg.Input(key='cover'), sg.FileBrowse()],
              [sg.Text('Secret data', size=(8, 1)), sg.Input(key='secret'), sg.FileBrowse()],
              [sg.Text('STATUS')],
              [sg.Output(size=(40, 10), key='-OUTPUT-')],
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
                        send_over_http(values['dhost'], values['dport'], values['sport'], values['cover'], values['secret'])
                        sg.popup_ok('Data and secret delivered!', title="Success", line_width=35, keep_on_top=True)
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


