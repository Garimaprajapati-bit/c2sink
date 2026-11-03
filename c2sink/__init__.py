"""c2sink: a passive sinkhole for blackholed C2 traffic.

An ISP that blackholes command-and-control (C2) prefixes stops the traffic but
learns nothing about which of its own customers are infected. c2sink redirects
that traffic to one host that completes the TCP handshake, records connection
metadata (who, which C2, when, TLS SNI/fingerprint, HTTP host) and never sends
a byte of application data back, so infected devices receive no commands and
the operator gets a per-customer report.
"""

__version__ = "0.1.0"
