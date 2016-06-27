#!/usr/bin/env python

from gevent import monkey
import gevent
monkey.patch_all()

import os
import struct
import socket
import md5
import docker
import argparse
import json
import logging
import requests
import time

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

DOCKER_EVENT_RETRY_INTERVAL = 10
DOCKER_TIMER_INTERVAL = 10
RIP_TIMER_DEFAULT_INTERVAL = 10

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
                               rte['metric'])

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


def get_container_ips(client, container_id, scanned_networks):
    container = client.inspect_container(container_id)
    networks = container['NetworkSettings']['Networks']

    result = []
    for network in networks:
        if network in scanned_networks:
            ip = networks[network]['IPAddress']
            result += [ip]

    return result

def notify_rip(ip_lists, neighbor, route_tag,
               next_hop, metric, passwd, auth_type):

    ip_set = set()
    for ip_list in ip_lists:
        for ip in ip_list:
            ip_set.add(ip)

    ip_list = list(ip_set)
    # 2 records may be consumed by md5 auth
    chunk_size = RIP_ENTRY_MAX_RECORDS - 2
    chunks = [ip_list[i:i+chunk_size]
              for i in xrange(0, len(ip_list), chunk_size)]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    for chunk in chunks:
        rtes = []
        for ip in chunk:
            rte = {'route_tag': route_tag,
                   'ip': ip,
                   'mask': "255.255.255.255",
                   'next_hop': next_hop, # 0x1badcafe
                   'metric': metric}

            rtes.append(rte)

        # seconds since epoch
        # the seqno should be non-decreasing
        seqno = int(time.time())
        packet = rip_packet(rtes, seqno, passwd, auth_type)

        sock.sendto(packet, (neighbor, RIP_DEFAULT_PORT))


def docker_event_loop(args, container_table):
    client = docker.Client(base_url='unix:/' + args.socket)

    try:
        logging.info("Sending initial notifications")
        ip_lists = []
        container_ids = [container['Id'] for container in client.containers()]

        for container_id in container_ids:
            ips = get_container_ips(client, container_id, args.networks)
            if not ips:
                logging.info("Not notifying about '%s', because it" +
                             "doesn't belong to networks we scan",
                             container_id)
            else:
                logging.info("Initial notification about '%s'",
                             container_id)

                container_table[container_id] = ips
                ip_lists.append(ips)
        notify_rip(ip_lists, args.neighbor, args.route_tag, args.next_hop,
                   args.metric, args.password, args.auth_type)
    except requests.ConnectionError:
        logging.error("Not sending initial notifications, because connection" +
                      "to Docker failed")
    except Exception as ex:
        logging.error("Not sending initial notifications, because of unknown" +
                      "exception: '%s'" % str(ex))


    while(True):
        try:
            for event_str in client.events():
                event = json.loads(event_str)

                if event['Type'] != 'container':
                    continue

                container_id = event['id']

                if event['Action'] == 'start':
                    if container_id not in container_table:
                        ips = get_container_ips(client, container_id, args.networks)

                        if not ips:
                            logging.info("Not notifying about '%s', because it" +
                                         "doesn't belong to networks we scan",
                                     container_id)
                        else:
                            logging.info("Notifying about '%s'",
                                         container_id)

                            container_table[container_id] = ips
                            notify_rip([ips], args.neighbor, args.route_tag,
                                       args.next_hop, args.metric,
                                       args.password, args.auth_type)

                if event['Action'] == 'die':
                    if container_id in container_table:
                        ips = container_table[container_id]

                        logging.info("Notifying about disappearance of '%s'",
                                     container_id)

                        del container_table[container_id]
                        notify_rip([ips], args.neighbor, args.route_tag,
                                   args.next_hop, RIP_METRIC_POISON,
                                   args.password, args.auth_type)


            gevent.sleep(1)
        except requests.ConnectionError:
            logging.error("Connection to docker failed while trying to " +
                          "listen for events")
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as ex:
            logging.error("Unknown error: '%s'" % str(ex))

        logging.error("Will retry event polling in a few seconds")
        gevent.sleep(DOCKER_EVENT_RETRY_INTERVAL)


def docker_timer_loop(args, container_table):
    client = docker.Client(base_url='unix:/' + args.socket)

    # To not interfere with initial check performed by
    # docker event loop
    gevent.sleep(DOCKER_TIMER_INTERVAL)

    while(True):
        try:
            ip_lists = []
            container_ids = [container['Id'] for container in client.containers()]
            for container_id in container_ids:
                if container_id not in container_table:
                    ips = get_container_ips(client, container_id, args.networks)
                    if not ips:
                        logging.info("Not notifying about '%s', because it" +
                                     "doesn't belong to networks we scan",
                                     container_id)
                    else:
                        logging.info("Notifying about '%s'",
                                     container_id)

                        container_table[container_id] = ips
                        ip_lists.append(ips)
            notify_rip(ip_lists, args.neighbor, args.route_tag,
                       args.next_hop, args.metric,
                       args.password, args.auth_type)

            ip_lists = []
            for container_id in container_table.copy():
                if container_id not in container_ids:
                    ips = container_table[container_id]

                    logging.info("Notifying about disappearance of '%s'",
                                 container_id)

                    del container_table[container_id]
                    ip_lists.append(ips)

            notify_rip(ip_lists, args.neighbor, args.route_tag,
                       args.next_hop, RIP_METRIC_POISON,
                       args.password, args.auth_type)

        except requests.ConnectionError:
            logging.error("Connection to docker failed while trying to " +
                          "scan for containers")
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as ex:
            logging.error("Unknown error: '%s'" % str(ex))

        gevent.sleep(DOCKER_TIMER_INTERVAL)


def rip_timer_loop(args, container_table):
    while(True):
        try:
            ip_lists = []
            for container_id, ips in container_table.items():
                logging.info("Sending periodic notification about '%s'",
                         container_id)
                ip_lists.append(ips)
            notify_rip(ip_lists, args.neighbor, args.route_tag,
                       args.next_hop, args.metric,
                       args.password, args.auth_type)

        except requests.ConnectionError:
            logging.error("Connection to docker failed while trying to " +
                          "send periodic notifications")
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as ex:
            logging.error("Unknown error: '%s'", str(ex))

        gevent.sleep(args.interval)


def main():
    logging.basicConfig(format='%(levelname)s: %(message)s',
                        level=logging.INFO)

    default_password = os.getenv('DOCKER_RIPNOTIFY_PASSWORD', None)

    parser = argparse.ArgumentParser()

    parser.add_argument('-s', '--socket', default='/var/run/docker.sock')
    parser.add_argument('-i', '--interval', type=int,
                        default=RIP_TIMER_DEFAULT_INTERVAL)
    parser.add_argument('-r', '--route-tag', type=int, default=1)
    parser.add_argument('-m', '--metric', type=int, default=1)
    parser.add_argument('-x', '--next-hop', default="")
    parser.add_argument('-p', '--password', default=default_password)
    parser.add_argument('-a', '--auth-type',
                        choices=['md5', 'plain'], default="md5")
    parser.add_argument('-n', '--neighbor', default="127.0.0.1")

    parser.add_argument('networks', nargs='*', default=['bridge'])

    args = parser.parse_args()

    container_table = {}

    try:
        gevent.joinall([
            gevent.spawn(docker_event_loop, args, container_table),
            gevent.spawn(docker_timer_loop, args, container_table),
            gevent.spawn(rip_timer_loop, args, container_table),
        ])
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
