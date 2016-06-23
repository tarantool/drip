#!/usr/bin/env python

import unittest
import ripnotify

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

class RIPTest(unittest.TestCase):
    def test_header(self):

        cmd = 1
        ver = 1

        h = ripnotify.RIPHeader(cmd=cmd, ver=ver)
        p = h.serialize()
        self.assertEquals(byte2hex(p), "01010000")

        cmd = 1
        ver = 2

        h = ripnotify.RIPHeader(cmd=cmd, ver=ver)
        p = h.serialize()
        self.assertEquals(byte2hex(p), "01020000")

    def test_without_auth(self):
        cmd = RIP_COMMAND_RESPONSE
        version = RIP_VERSION_2

        rtes = [{'route_tag': 1337,
                 'cidr': "222.173.190.239/32", # 0xdeadbeef
                 'next_hop': "27.173.202.254", # 0x1badcafe
                 'metric': 123456}]

        password = None
        auth_type = None
        seqno = 56789

        pkt = ripnotify.rip_packet(cmd, version, rtes,
                                   seqno, password, auth_type)

        b = []
        for i in range(len(pkt)/4):
            b.append(byte2hex(pkt[i*4:i*4+4]))

        # header
        self.assertEquals(b[0], "02020000")
        # RTE entry
        self.assertEquals(b[1], "00020539")
        self.assertEquals(b[2], "deadbeef")
        self.assertEquals(b[3], "ffffffff")
        self.assertEquals(b[4], "1badcafe")
        self.assertEquals(b[5], "40e20100")


    def test_plain_auth(self):
        cmd = RIP_COMMAND_RESPONSE
        version = RIP_VERSION_2

        rtes = [{'route_tag': 1337,
                 'cidr': "222.173.190.239/32", # 0xdeadbeef
                 'next_hop': "27.173.202.254", # 0x1badcafe
                 'metric': 123456}]

        password = "mypasswd"
        auth_type = "plain"
        seqno = 56789

        pkt = ripnotify.rip_packet(cmd, version, rtes,
                                   seqno, password, auth_type)

        b = []
        for i in range(len(pkt)/4):
            b.append(byte2hex(pkt[i*4:i*4+4]))

        # header
        self.assertEquals(b[0],  "02020000")
        # Plain auth packet
        self.assertEquals(b[1],  "ffff0002")
        self.assertEquals(b[2],  "6d797061")
        self.assertEquals(b[3],  "73737764")
        self.assertEquals(b[4],  "00000000")
        self.assertEquals(b[5],  "00000000")
        # RTE entry
        self.assertEquals(b[6],  "00020539")
        self.assertEquals(b[7],  "deadbeef")
        self.assertEquals(b[8],  "ffffffff")
        self.assertEquals(b[9],  "1badcafe")
        self.assertEquals(b[10], "40e20100")


    def test_md5_auth(self):

        cmd = RIP_COMMAND_RESPONSE
        version = RIP_VERSION_2

        rtes = [{'route_tag': 1337,
                 'cidr': "222.173.190.239/32", # 0xdeadbeef
                 'next_hop': "27.173.202.254", # 0x1badcafe
                 'metric': 123456}]

        password = "mypasswd"
        auth_type = "md5"
        seqno = 56789

        pkt = ripnotify.rip_packet(cmd, version, rtes,
                                   seqno, password, auth_type)

        b = []
        for i in range(len(pkt)/4):
            b.append(byte2hex(pkt[i*4:i*4+4]))

        # header
        self.assertEquals(b[0],  "02020000")
        # MD5 auth header
        self.assertEquals(b[1],  "ffff0003")
        self.assertEquals(b[2],  "002c0110")
        self.assertEquals(b[3],  "0000ddd5")
        self.assertEquals(b[4],  "00000000")
        self.assertEquals(b[5],  "00000000")
        # RTE entry
        self.assertEquals(b[6],  "00020539")
        self.assertEquals(b[7],  "deadbeef")
        self.assertEquals(b[8],  "ffffffff")
        self.assertEquals(b[9],  "1badcafe")
        self.assertEquals(b[10], "40e20100")
        # MD5 hash of packet + password
        self.assertEquals(b[11], "ffff0100")
        self.assertEquals(b[12], "17bbc7e5")
        self.assertEquals(b[13], "4e55d34a")
        self.assertEquals(b[14], "2b58ab85")
        self.assertEquals(b[15], "8ae6580e")


if __name__ == '__main__':
    unittest.main()
