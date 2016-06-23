#!/usr/bin/env python

import struct
import socket
import md5

RIP_COMMAND_RESPONSE = 2
RIP_VERSION_2 = 2
RIP_DEFAULT_PORT = 520
RIP_AUTH_MD5 = 3
RIP_AUTH_PLAIN = 2
RIP_MD5_AUTH_LEN = 16
RIP_AUTH_TYPE_ID_MD5 = 0x0100
RIP_ENTRY_MAX_RECORDS = 25
RIP_METRIC_POISON = 15
RIP_HEADER_LEN = 4
RIP_RTE_LEN = 20


def rip_packet(rtes, seqno, passwd, auth_type="plain"):
    """ Creates and returns a RIP packet in binary form
    """
    cmd = RIP_COMMAND_RESPONSE
    ver = RIP_VERSION_2

    header_format = ">BBH"
    hdr = struct.pack(header_format, cmd, ver, 0)

    if passwd is not None and auth_type not in ("md5", "plain"):
        raise ValueError("auth_type must be either 'md5' or 'plain'")

    auth = None

    permitted_entries = RIP_ENTRY_MAX_RECORDS

    if passwd is not None and auth_type == 'md5':
        permitted_entries -= 2
        auth_format = ">HHHBBIII"
        # offset is calculated including the md5 header itself
        pkt_offset = RIP_HEADER_LEN + (len(rtes)+1) * RIP_RTE_LEN
        auth = struct.pack(auth_format,
                           0xffff, # address family
                           RIP_AUTH_MD5, # auth type
                           pkt_offset, # offset to MD5 auth data
                           0x01, # key_id
                           RIP_MD5_AUTH_LEN, # length of auth packet
                           seqno, # sequence number
                           0x0000, # reserved
                           0x0000) # reserved

    if passwd is not None and auth_type == 'plain':
        permitted_entries -= 1
        auth_format = ">HH16s"
        auth = struct.pack(auth_format,
                           0xffff,
                           RIP_AUTH_PLAIN,
                           passwd)

    if len(rtes) > permitted_entries:
        raise ValueError("Too many route entries: %d" % len(rtes))

    rte_format=">HHIIII"
    rte_buf=b""
    for rte in rtes:
        ip = struct.unpack(">L", socket.inet_aton(rte['ip']))[0]
        mask = struct.unpack(">L", socket.inet_aton(rte['mask']))[0]
        next_hop = struct.unpack(">L", socket.inet_aton(rte['next_hop']))[0]

        if type(rte['route_tag']) is not int:
            raise ValueError("route_tag must be int")
        if type(rte['metric']) is not int:
            raise ValueError("metric must be int")

        rte_buf += struct.pack(rte_format,
                               socket.AF_INET,
                               rte['route_tag'],
                               ip,
                               mask,
                               next_hop,
                               socket.htonl(rte['metric']))

    md5_footer = None

    if passwd is not None and auth_type == 'md5':
        md5_auth_format=">HH16s"
        passwd_footer = struct.pack(md5_auth_format,
                                    0xffff,
                                    RIP_AUTH_TYPE_ID_MD5,
                                    passwd)

        pwd_digest = md5.new(hdr+auth+rte_buf+passwd_footer).digest()

        md5_footer = struct.pack(md5_auth_format,
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
