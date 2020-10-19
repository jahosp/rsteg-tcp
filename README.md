# RSTEG-TCP

## Introduction
This project is a Proof-Of-Concept of a steganographic method called retransmission steganography (RSTEG), proposed
by W. Mazurczyk, M. Smolarczyk and K. Szczypiorski in the [following article.]( https://doi.org/10.1007/s00500-009-0530-1 )
It's written in Python 3.8 and uses the [Scapy](https://scapy.readthedocs.io/en/latest/) library to forge packets, as well to manage the layer 3 RawSockets. 
In addition, the client uses the [PySimpleGUI](https://pysimplegui.readthedocs.io/en/latest/) wrapper for its UI.

This is being developed as part of my final project to obtain my BD in Computer Engineering with a specialization in Information Technologies by the UAB. 

## Description 
In general, RSTEG can be applied to any network protocol that utilises a retransmission mechanism. For this project the TCP
 was selected due to its predominance over the Internet. 
 
 Summarizing, the method consists in *"...to not acknowledge a successfully received packet in order to intentionally invoke a retransmission. 
 The retransmitted packet carries a steganogram instead of user data in the payload field."*
 
 In order to have this functionality, a TCP implementation had to be made and customized so both client and server are able to 
 manage this situation.

## Installation & Usage
TBD

## Contributing
TBD

## Credits
TBD

## License 
GNU GPLv3