#!/usr/bin/env python

import unittest
import drip

def byte2hex(byteStr):
    return ''.join( [ "%02x" % ord( x ) for x in byteStr ] ).strip()

class RIPTest(unittest.TestCase):
    def test_without_auth(self):
        rtes = [{'route_tag': 1337,
                 'ip': "222.173.190.239", # 0xdeadbeef
                 'mask': "255.255.255.255", #0xffffffff
                 'next_hop': "27.173.202.254", # 0x1badcafe
                 'metric': 123456}]

        password = None
        auth_type = None
        seqno = 56789

        pkt = drip.rip_packet(rtes, seqno, password, auth_type)

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
        self.assertEquals(b[5], "0001e240")

        # should not raise error
        drip.rip_packet(rtes*25, seqno, password, auth_type)

        with self.assertRaises(ValueError):
            drip.rip_packet(rtes*26, seqno, password, auth_type)

    def test_without_auth_md5(self):
        rtes = [{'route_tag': 1337,
                 'ip': "222.173.190.239", # 0xdeadbeef
                 'mask': "255.255.255.255", #0xffffffff
                 'next_hop': "27.173.202.254", # 0x1badcafe
                 'metric': 123456}]

        password = None
        auth_type = "md5"
        seqno = 56789

        pkt = drip.rip_packet(rtes, seqno, password, auth_type)

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
        self.assertEquals(b[5], "0001e240")


    def test_plain_auth(self):
        rtes = [{'route_tag': 1337,
                 'ip': "222.173.190.239", # 0xdeadbeef
                 'mask': "255.255.255.255", #0xffffffff
                 'next_hop': "27.173.202.254", # 0x1badcafe
                 'metric': 123456}]

        password = "mypasswd"
        auth_type = "plain"
        seqno = 56789

        pkt = drip.rip_packet(rtes, seqno, password, auth_type)

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
        self.assertEquals(b[10], "0001e240")


        # should not raise error
        drip.rip_packet(rtes*24, seqno, password, auth_type)

        with self.assertRaises(ValueError):
            drip.rip_packet(rtes*25, seqno, password, auth_type)


    def test_md5_auth(self):
        rtes = [{'route_tag': 1337,
                 'ip': "222.173.190.239", # 0xdeadbeef
                 'mask': "255.255.255.255", #0xffffffff
                 'next_hop': "27.173.202.254", # 0x1badcafe
                 'metric': 123456}]

        password = "mypasswd"
        auth_type = "md5"
        seqno = 56789

        pkt = drip.rip_packet(rtes, seqno, password, auth_type)

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
        self.assertEquals(b[10], "0001e240")
        # MD5 hash of packet + password
        self.assertEquals(b[11], "ffff0100")
        self.assertEquals(b[12], "81b20579")
        self.assertEquals(b[13], "cc3ec992")
        self.assertEquals(b[14], "4383badd")
        self.assertEquals(b[15], "3f111569")

        # should not raise error
        drip.rip_packet(rtes*23, seqno, password, auth_type)

        with self.assertRaises(ValueError):
            drip.rip_packet(rtes*24, seqno, password, auth_type)


    def test_poison(self):
        rtes = [{'route_tag': 1337,
                 'ip': "222.173.190.239", # 0xdeadbeef
                 'mask': "255.255.255.255", #0xffffffff
                 'next_hop': "27.173.202.254", # 0x1badcafe
                 'metric': drip.RIP_METRIC_POISON}]

        password = None
        auth_type = None
        seqno = 56789

        pkt = drip.rip_packet(rtes, seqno, password, auth_type)

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
        self.assertEquals(b[5], "0000000f")


if __name__ == '__main__':
    unittest.main()
