#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: Javier Hospital <jahos@protonmail.com>

import ipaddress
import random
import array
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


def find_compensation(payload, secret):
    """Finds the u16bit word to append in the secret in order to obtain the same checksum as in the payload."""
    if len(payload) % 2 == 1:
        payload += b"\0"
    if len(secret) % 2 == 1:
        secret += b"\0"
    sp = sum(array.array("H", payload))  # sum payload 16bit words
    ss = sum(array.array("H", secret))  # sum secret 16bit words
    val = sp - ss  # subtract sums
    val = (val >> 16) + (val & 0xffff)  # shift and mask 16bit for carry
    val += val >> 16  # make it unsigned

    return val
