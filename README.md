# RSTEG-TCP

## Introduction
This project is a proof of concept of a steganographic method called retransmission steganography (RSTEG), proposed
by W. Mazurczyk, M. Smolarczyk and K. Szczypiorski in the [following article.]( https://doi.org/10.1007/s00500-009-0530-1 )
It's written in Python 3.8 and uses the [Scapy](https://scapy.readthedocs.io/en/latest/) library to forge packets, as well to manage the layer 3 RawSockets. 
In addition, the client application uses the [PySimpleGUI](https://pysimplegui.readthedocs.io/en/latest/) wrapper for its UI and [Matplotlib](https://github.com/matplotlib/matplotlib) for generating graphics.

This is being developed as part of my final project to obtain a BD in Computer Engineering with a specialization in Information Technologies by the UAB. 

## Description 
In general, RSTEG can be applied to any network protocol that utilises a retransmission mechanism. For this project the TCP was selected due to its predominance over the Internet. Summarizing, the method consists in:

  *"...to not acknowledge a successfully received packet in order to intentionally invoke a retransmission. 
 The retransmitted packet carries a steganogram instead of user data in the payload field."* [1]

 In order to have this functionality, a simple TCP implementation had to be made and customized so both client and server are able to 
 manage this situation. Scapy was very helpful as it already has the data structures for IP datagrams and TCP segments and also gives us 
 access to the layer 3 with the L3RawSocket class. The TCP created here only implements its basic logic, so features like Window Scaling, SAck or 
 other features related to congestion avoidance are not present here. These would be a very interesting addition.
 
 The following scenario was designed to prove RSTEG in a more real environment using a client and server application:
 <p align="center">
  <img src="https://user-images.githubusercontent.com/15250664/98651652-d1ced300-233a-11eb-8ec7-b743df3d216b.png">
</p>

From the bottom up: ```rsteg_tcp.py``` handles the TCP logic as well as the modifications for RSTEG. Meanwhile ```rsteg_socket.py``` offers 
similar methods to Python sockets (bind, listen, accept, etc.) but using the RstegTcp class. Note that this Socket offers
two methods for data transfer(send() and rsend()). One would be the usual socket send() and the other accepts two data
parameters, the cover data and the secret data. Finally, ```http_server.py``` and ```http_client.py``` utilise the RstegSocket methods
to send and receive HTTP requests and responses. 

**NOTE: This are not full implementations of TCP or HTTP and they're far from it.**

## Usage
First of all, the ```client.py``` script contains the client application and its GUI. You can use ```http_server.py``` 
or ```tcp_server.py``` to start the server, depending on which layer do you want to communicate. Both servers listen on
port 80, but this can be changed. 

The client application let's you select which protocol do you want to use and then it displays the according parameter form.

#### HTTP
For HTTP you have to input a valid URL (http://ip:port/path) and then select the desired request type. You'll have to input
an IPv4 address as the application does not support DNS (that would be an interesting feature). If you selected a POST 
request, a new form will be displayed. Here you can browse your filesystem for the cover and secret data to be sent. There's 
also a checkbox to enable or disable the RSTEG method and an input box where you can specify the retransmission probability 
for RSTEG (defaults to 7%).


<p>
 <img align="right" height="400" src="https://user-images.githubusercontent.com/15250664/98659556-83becd00-2344-11eb-8dac-88ca5e6419e1.png">
 <img align="left" height="400" src="https://user-images.githubusercontent.com/15250664/98659584-8e796200-2344-11eb-96b8-19bb0f2c22c3.png">
</p>
<br>

#### TCP
For TCP you'll have to input the server IP, the server port, and the source port. In the same way as in the POST request,
here you can browse for the cover and secret data. Also you can edit the retransmission probability. 

<p>
 <img align="center" height="400" src="https://user-images.githubusercontent.com/15250664/98659748-bf599700-2344-11eb-8775-8334b9bffdb2.png">
</p>

Both client and servers generate logs in the same folder as you execute them.

**NOTE: Unix automatically sends RST packages for Scapy crafted SYN packages. To disable this execute the ```iptables.sh``` 
script followed by the port number you'll be using (do this for the server and the client).**


## Installation
TBD
## Contributing
TBD

## Credits
TBD

## License 
GNU GPLv3
