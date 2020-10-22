#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

import ipaddress
from scapy.all import *
import random


def is_ipv4(string):
    """Checks string for a valid IPv4 address"""
    try:
        ipaddress.IPv4Network(string)
        return True
    except ValueError:
        return False


def retrans_prob(prob):
    """Returns True or False as prob parameter"""
    return random.random() < prob


def find_chk_collision(old_chk, payload):
    """Finds the 16 bit compensation code to make the packet checksum equal
    to another packet checksum with the same IP and TCP header (but different payload)
    :param old_chk: checksum from the other packet
    :param payload: binary payload we want to compensate with the code
    :return: 16 bit unsigned integer with the compensation code
    """
    chk_tmp = hex(checksum(payload))  # initialize to actual checksum
    integer = 0  # initialize value
    while old_chk != chk_tmp and integer < 65535:  # search until both chksums match
        integer += 1
        compensation = struct.pack('H', integer)  # convert to unsigned 16b int
        tmp_payload = payload + compensation  # add code to payload
        chk_tmp = hex(checksum(tmp_payload))  # calculate new checksum
    return integer  # return the found value
