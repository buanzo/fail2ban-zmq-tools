#!/usr/bin/env python3
"""Some general purpose utilities."""

import socket
import re


class f2bcUtils:
    """Utility functions for fail2ban-cluster."""
    # valid IPv4 IP address?
    def valid_ipv4(address):
        try:
            socket.inet_aton(address)
            return True
        except Exception:
            return False

    # valid jailname? must only contain a-z,A-Z,0-9 and _-
    # TODO: verify fail2ban jailname constraints, including length
    def valid_jailname(jailname):
        match = re.match("^[a-zA-Z0-9_-]*$", jailname)
        return match is not None

    def is_valid_hostname(hostname):
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            # strip exactly one dot from the right, if present
            hostname = hostname[:-1]
        allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))

    def is_valid_action(action):
        if not action.lower() in ['ban', 'unban']:
            return False
        return True
