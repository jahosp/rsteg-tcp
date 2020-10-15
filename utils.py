#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

import ipaddress
import random


def is_ipv4(string):
    """Checks string for a valid IPv4 address"""
    try:
        ipaddress.IPv4Network(string)
        return True
    except ValueError:
        return False


def retrans_prob(prob):
    return random.random() < prob
