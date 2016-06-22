#!/usr/bin/env python

import ipaddr
import struct
import socket
import hmac
import md5

RIP_COMMAND_RESPONSE  = 2
RIP_VERSION_2         = 2
RIP_DEFAULT_PORT      = 520
RIP_AUTH_MD5          = 3
RIP_MD5_AUTH_LEN      = 16
RIP_AUTH_TYPE_ID_MD5  = 0x0100
RIP_ENTRY_MAX_RECORDS = 25
RIP_METRIC_POISON     = 15

def byte2hex(byteStr):
    return ''.join( [ "%02x" % ord( x ) for x in byteStr ] ).strip()


def rip_packet(cmd, ver, rtes, seqno, passwd, auth_type):
    HDR_FORMAT = ">BBH"
    hdr = struct.pack(HDR_FORMAT, cmd, ver, 0)

    if auth_type not in ("md5", "plain"):
        raise ValueError("auth_type must be either 'md5' or 'plain'")

    pkt_len = 0x2c

    auth = None

    if auth_type == 'md5':
        AUTH_FORMAT = ">HHHBBIII"
        auth = struct.pack(AUTH_FORMAT,
                           0xffff, # address family
                           RIP_AUTH_MD5, # auth type
                           pkt_len, # length of RIP packet
                           0x01, # key_id
                           RIP_MD5_AUTH_LEN, # length of auth packet
                           seqno, # sequence number
                           0x0000, # reserved
                           0x0000) # reserved
    else:
        auth = None

    RTE_FORMAT=">HHIIII"
    rte_buf=b""
    for rte in rtes:
        network = ipaddr.IPv4Network(rte['cidr'])
        next_hop = ipaddr.IPv4Address(rte['next_hop'])
        if type(rte['route_tag']) is not int:
            raise ValueError("route_tag must be int")
        if type(rte['metric']) is not int:
            raise ValueError("metric must be int")


        rte_buf += struct.pack(RTE_FORMAT,
                               socket.AF_INET,
                               rte['route_tag'],
                               network.network._ip,
                               network.netmask._ip,
                               next_hop._ip,
                               socket.htonl(rte['metric']))

    if auth_type == 'md5':
        MD5_AUTH_FORMAT=">HH16s"
        passwd_footer = struct.pack(MD5_AUTH_FORMAT,
                                    0xffff,
                                    RIP_AUTH_TYPE_ID_MD5,
                                    passwd)

        pwd_digest = md5.new(hdr+auth+rte_buf+passwd_footer).digest()

        md5_footer = struct.pack(MD5_AUTH_FORMAT,
                                 0xffff,
                                 RIP_AUTH_TYPE_ID_MD5,
                                 pwd_digest)

    result = hdr

    if auth:
        result += auth

    result += rte_buf

    if md5_footer:
        result += md5_footer

    return result

class RIPHeader(object):
    FORMAT = ">BBH"
    SIZE = struct.calcsize(FORMAT)
    TYPE_REQUEST = 1
    TYPE_RESPONSE = 2

    def __init__(self, cmd=None, ver=None):
        self.packed = None

        if cmd != 1 and cmd != 2:
            raise(ValueError)
        else:
            self.cmd = cmd

        if ver != 1 and ver != 2:
            raise(ValueError)
        else:
            self.ver = ver

    def __repr__(self):
        return "RIPHeader(cmd=%d, ver=%d)" % (self.cmd, self.ver)

    def serialize(self):
        return struct.pack(self.FORMAT, self.cmd, self.ver, 0)

class RIPSimpleAuthEntry(object):
    """Simple plain text password authentication as defined in RFC 1723
    section 3.1."""
    FORMAT = ">HH16s"
    SIZE = struct.calcsize(FORMAT)

    def __init__(self, password=None):
        """password should be the plain text password to use and must not
        be longer than 16 bytes."""
        if password != None:
            self.afi = 0xffff
            self.auth_type = 0x0002
            self.password = password
        else:
            raise(ValueError("password must be provided."))

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, password):
        if len(password) > 16:
            raise(ValueError("Password too long (>16 bytes)."))
        self._password = password

    def serialize(self):
        return struct.pack(self.FORMAT, self.afi, self.auth_type,
                           self.password)

class RIPRouteEntry(object):
    FORMAT = ">HHIIII"
    SIZE = struct.calcsize(FORMAT)
    MIN_METRIC = 0
    MAX_METRIC = 16

    def __init__(self, address=None, mask=None, nexthop=None,
                 metric=None, tag=0, src_ip=None, imported=False, afi=2):
        self.packed = None
        self.changed = False
        self.imported = imported
        self.init_timeout()
        self.garbage = False
        self.marked_for_deletion = False

        if address and \
           nexthop and \
           mask   != None and \
           metric != None and \
           tag    != None:
            self._init_from_host(address, mask, nexthop, metric, tag, afi)
        else:
            raise(ValueError)

    def _init_from_host(self, address, mask, nexthop, metric, tag, afi):
        """Init from data provided by the application."""
        self.afi = afi
        self.set_network(address, mask)
        self.set_nexthop(nexthop)
        self.metric = metric
        self.tag = tag

    def set_network(self, address, mask):
        # If the given address and mask is not a network ID, make it one by
        # ANDing the addr and mask.
        network = ipaddr.IPv4Network(address + "/" + str(mask))
        self.network = ipaddr.IPv4Network(network.network.exploded + "/" +
                                          str(network.prefixlen))

    def set_nexthop(self, nexthop):
        self.nexthop = ipaddr.IPv4Address(nexthop)

    def __repr__(self):
        return "RIPRouteEntry(address=%s, mask=%s, nexthop=%s, metric=%d, " \
               "tag=%d)" % (self.network.ip.exploded, self.network.netmask.exploded, self.nexthop, self.metric, self.tag)

    def __eq__(self, other):
        if self.afi     == other.afi      and \
           self.network == other.network  and \
           self.nexthop == other.nexthop  and \
           self.metric  == other.metric   and \
           self.tag     == other.tag:
            return True
        else:
            return False

    def serialize(self):
        """Format into typical RIPv2 header format suitable to be sent
        over the network. This is the updated header from RFC 2453
        section 4."""

        # Always re-pack
        return struct.pack(self.FORMAT, self.afi, self.tag,
                                      self.network.network._ip,
                                      self.network.netmask._ip,
                                      self.nexthop._ip, self.metric)

class RIPPacket(object):
    def __init__(self, hdr=None, rtes=None):
        """Create a RIP packet either from the binary data received from the
        network, or from a RIP header and RTE list."""
        if hdr and rtes:
            self._init_from_host(hdr, rtes)
        else:
            raise(ValueError)

    def __repr__(self):
        return "RIPPacket: Command %d, Version %d, number of RTEs %d." % \
                (self.hdr.cmd, self.hdr.ver, len(self.rtes))

    def _init_from_host(self, hdr, rtes):
        """Init using a header and rte list provided by the application."""
        if hdr.ver != 2:
            raise(ValueError("Only version 2 is supported."))
        self.hdr = hdr
        self.rtes = rtes

    def serialize(self):
        """Return a bytestring representing this packet in a form that
        can be transmitted across the network."""

        # Always re-pack in case the header or rtes have changed.
        packed = self.hdr.serialize()
        for rte in self.rtes:
            packed += rte.serialize()
        return packed

def send_request():
    """Send a multicast request message out of each active interface."""
    hdr = RIPHeader(cmd=RIPHeader.TYPE_REQUEST, ver=2)
    rte = [ RIPRouteEntry(afi=0, address="0.0.0.0", mask=0, tag=0,
                          metric=RIPRouteEntry.MAX_METRIC, nexthop="0.0.0.0") ]
    request = RIPPacket(hdr=hdr, rtes=rte).serialize()
