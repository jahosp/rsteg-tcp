#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

import ipaddress
from scapy.all import *
import random
from multiprocessing import Pool
from enum import Enum


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


search = False


def find_chk_collision_parallel(old_chk, start, end, payload):
    global search
    chk_tmp = hex(checksum(payload))  # initialize to actual checksum
    integer = start  # initialize value
    while old_chk != chk_tmp and integer < end and search is False:  # search until both chksums match
        integer += 1
        compensation = struct.pack('H', integer)  # convert to unsigned 16b int
        tmp_payload = payload + compensation  # add code to payload
        chk_tmp = hex(checksum(tmp_payload))  # calculate new checksum

    compensation = struct.pack('H', integer)  # convert to unsigned 16b int
    tmp_payload = payload + compensation  # add code to payload
    if hex(checksum(tmp_payload)) == old_chk:
        search = True
        return integer
    else:
        return -1


def find_compensation(old_chk, payload):
    global search
    search = False
    p = Pool(8)
    data = [
        (old_chk, 0, 8191, payload), (old_chk, 8192, 16383, payload), (old_chk, 16384, 24580, payload),
        (old_chk, 24581, 32771, payload), (old_chk, 32772, 40962, payload), (old_chk, 40963, 49153, payload),
        (old_chk, 49154, 57344, payload), (old_chk, 57345, 65535, payload)
    ]
    ret = p.starmap(find_chk_collision_parallel, data)

    for r in ret:
        if r != -1:
            return r
