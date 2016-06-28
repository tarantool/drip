#!/usr/bin/env python

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
import pyroute2
import threading
import signal

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
                           0xffff,            # address family
                           RIP_AUTH_MD5,      # auth type
                           pkt_offset,        # offset to MD5 auth data
                           0x01,              # key_id
                           RIP_MD5_AUTH_LEN,  # length of auth packet
                           seqno,             # sequence number
                           0x0000,            # reserved
                           0x0000)            # reserved

    if passwd is not None and auth_type == 'plain':
        permitted_entries -= 1
        auth_format = ">HH16s"
        auth = struct.pack(auth_format,
                           0xffff,
                           RIP_AUTH_PLAIN,
                           passwd)

    if len(rtes) > permitted_entries:
        raise ValueError("Too many route entries: %d" % len(rtes))

    rte_format = ">HHIIII"
    rte_buf = b""
    for rte in rtes:
        ipaddr = struct.unpack(">L", socket.inet_aton(rte['ip']))[0]
        mask = struct.unpack(">L", socket.inet_aton(rte['mask']))[0]
        next_hop = struct.unpack(">L", socket.inet_aton(rte['next_hop']))[0]

        if not isinstance(rte['route_tag'], int):
            raise ValueError("route_tag must be int")
        if not isinstance(rte['metric'], int):
            raise ValueError("metric must be int")

        rte_buf += struct.pack(rte_format,
                               socket.AF_INET,
                               rte['route_tag'],
                               ipaddr,
                               mask,
                               next_hop,
                               rte['metric'])

    md5_footer = None

    if passwd is not None and auth_type == 'md5':
        md5_auth_format = ">HH16s"
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


def is_ipv4(address):
    try:
        socket.inet_aton(address)
    except socket.error:
        return False

    return True


def get_network_settings(client, network_names):
    networks = client.networks()

    result = {}
    for network in networks:
        if network['Name'] not in network_names:
            continue

        try:
            bridge = network['Options']['com.docker.network.bridge.name']
        except KeyError:
            logging.error(
                "Network '%s' doesn't have com.docker.network.bridge.name",
                network['Name'])
            continue

        try:
            gateway = network['IPAM']['Config'][0]['Gateway']
        except KeyError:
            logging.error(
                "Network '%s' doesn't specify Gateway IP",
                network['Name'])
            continue

        result[network['Name']] = {
            'bridge': bridge,
            'gateway': gateway
        }

    return result


def get_ipdb_by_pid(pid):
    if not os.path.exists('/var/run/netns'):
        os.mkdir('/var/run/netns')

    nspath = '/var/run/netns/%s' % str(pid)

    nstarget = None

    try:
        nstarget = os.readlink(nspath)
    except OSError:
        pass

    expected_nstarget = '/proc/%s/ns/net' % str(pid)

    if nstarget != expected_nstarget:
        if os.path.exists(nspath):
            os.remove(nspath)
        os.symlink(expected_nstarget, nspath)

    netns = pyroute2.NetNS(str(pid))
    ipdb = pyroute2.IPDB(nl=netns)
    return ipdb, netns


def get_container_ips(client, container_id, scanned_networks):
    container = client.inspect_container(container_id)
    networks = container['NetworkSettings']['Networks']

    result = []
    for network in networks:
        if network in scanned_networks:
            ipaddr = networks[network]['IPAddress']
            result += [ipaddr]

    return result


def notify_rip(ip_lists, neighbor, route_tag,
               next_hop, metric, passwd, auth_type):

    ip_set = set()
    for ip_list in ip_lists:
        for ipaddr in ip_list:
            ip_set.add(ipaddr)

    ip_list = list(ip_set)
    # 2 records may be consumed by md5 auth
    chunk_size = RIP_ENTRY_MAX_RECORDS - 2
    chunks = [ip_list[i:i+chunk_size]
              for i in xrange(0, len(ip_list), chunk_size)]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    for chunk in chunks:
        rtes = []
        for ipaddr in chunk:
            rte = {'route_tag': route_tag,
                   'ip': ipaddr,
                   'mask': "255.255.255.255",
                   'next_hop': next_hop,
                   'metric': metric}

            rtes.append(rte)

        # seconds since epoch
        # the seqno should be non-decreasing
        seqno = int(time.time())
        packet = rip_packet(rtes, seqno, passwd, auth_type)

        sock.sendto(packet, (neighbor, RIP_DEFAULT_PORT))


def docker_rip_event_loop(args, container_table, lock):
    client = docker.Client(base_url='unix:/' + args.socket)

    try:
        with lock:
            logging.info("Sending initial notifications")
            ip_lists = []
            container_ids = [container['Id']
                             for container in client.containers()]

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
        logging.error("Not sending initial notifications, because of " +
                      "unknown exception: '%s'" % str(ex))

    while True:
        try:
            for event_str in client.events():
                with lock:
                    event = json.loads(event_str)

                    if event['Type'] != 'container':
                        continue

                    container_id = event['id']

                    if event['Action'] == 'start':
                        if container_id not in container_table:
                            ips = get_container_ips(client, container_id,
                                                    args.networks)

                            if not ips:
                                logging.info(
                                    "Not notifying about '%s', because it" +
                                    "doesn't belong to networks we scan",
                                    container_id)
                            else:
                                logging.info("Notifying about '%s'",
                                             container_id)

                                container_table[container_id] = ips
                                notify_rip([ips], args.neighbor,
                                           args.route_tag, args.next_hop,
                                           args.metric, args.password,
                                           args.auth_type)

                    if event['Action'] == 'die':
                        if container_id in container_table:
                            ips = container_table[container_id]

                            logging.info(
                                "Notifying about disappearance of '%s'",
                                container_id)

                            del container_table[container_id]
                            notify_rip([ips], args.neighbor, args.route_tag,
                                       args.next_hop, RIP_METRIC_POISON,
                                       args.password, args.auth_type)
            time.sleep(1)
        except requests.ConnectionError:
            logging.error("Connection to docker failed while trying to " +
                          "listen for events")
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as ex:
            logging.error("Unknown error: '%s'", str(ex))

        logging.error("Will retry event polling in a few seconds")
        time.sleep(DOCKER_EVENT_RETRY_INTERVAL)


def docker_rip_timer_loop(args, container_table, lock):
    client = docker.Client(base_url='unix:/' + args.socket)

    # To not interfere with initial check performed by
    # docker event loop
    time.sleep(DOCKER_TIMER_INTERVAL)

    while True:
        try:
            with lock:
                ip_lists = []
                container_ids = [container['Id']
                                 for container in client.containers()]
                for container_id in container_ids:
                    if container_id not in container_table:
                        ips = get_container_ips(client, container_id,
                                                args.networks)
                        if not ips:
                            logging.info(
                                "Not notifying about '%s', because it" +
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
            logging.error("Unknown error: '%s'", str(ex))

        time.sleep(DOCKER_TIMER_INTERVAL)


def periodic_rip_notification_loop(args, container_table, lock):
    while(True):
        try:
            with lock:
                ip_lists = []
                for container_id, ips in container_table.items():
                    logging.debug("Sending periodic notification about '%s'",
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

        time.sleep(args.interval)


def patch_bridge_ips(network_settings):
    bridge_names = [r['bridge'] for r in network_settings.values()]

    with pyroute2.IPDB() as ipdb:
        # Filter out only relevant interfaces
        interfaces = {}
        for interface_id in ipdb.interfaces:
            interface = ipdb.interfaces[interface_id]
            if interface.ifname in bridge_names:
                interfaces[interface['index']] = interface

        # All relevant interfaces should have netmask /32
        # so that there is no 'directly connected route'
        for interface in interfaces.values():
            ipaddr_set = False
            for ipaddr in interface.ipaddr:
                addr = ipaddr[0]
                mask = ipaddr[1]

                if is_ipv4(addr):
                    if mask != 32:
                        logging.info('Replacing %s/%d with %s/%d on %s',
                                     addr, mask,
                                     addr, 32,
                                     interface.ifname)
                        interface.del_ip(addr+'/'+str(mask))
                        interface.add_ip(addr+'/32')
                        ipaddr_set = True
                    else:
                        ipaddr_set = True

            if not ipaddr_set:
                bridges = {n['bridge']: n['gateway']
                           for n in network_settings.values()}
                addr = bridges[interface.ifname]
                mask = 32
                logging.info('Setting %s/%d on %s',
                             addr, mask,
                             interface.ifname)

                interface.add_ip(addr+'/'+str(mask))

        ipdb.commit()


def patch_container_ip(network_settings, container, ipdb):
    network_names = list(network_settings.keys())

    addrs_to_patch = []
    networks = container['NetworkSettings']['Networks']
    for network_name, network in networks.items():
        addr = network['IPAddress']

        if network_name in network_names:
            addrs_to_patch.append(addr)

    interfaces = {}
    for interface_id in ipdb.interfaces:
        interface = ipdb.interfaces[interface_id]
        interfaces[interface['index']] = interface

    for interface in interfaces.values():
        for ipaddr in interface.ipaddr:
            addr = ipaddr[0]
            mask = ipaddr[1]

            if addr not in addrs_to_patch:
                continue

            if is_ipv4(addr):
                if mask != 32:
                    logging.info('Replacing %s/%d with %s/%d on %s in %s',
                                 addr, mask,
                                 addr, 32,
                                 interface.ifname,
                                 container['Id'])
                    interface.del_ip(addr+'/'+str(mask))
                    interface.add_ip(addr+'/32')

    ipdb.commit()


def patch_container_route(network_settings, container, ipdb):
    network_names = list(network_settings.keys())

    routes_to_add = set()
    gateway = None
    gateway_iface_ip = None

    container_networks = container['NetworkSettings']['Networks']
    for network_name, network in container_networks.items():
        addr = network['IPAddress']
        if network['Gateway']:
            gateway = network['Gateway']
            gateway_iface_ip = addr

        if network_name in network_names:
            routes_to_add.add(addr)

    ip_to_if = {}
    if_to_ip = {}
    interfaces = ipdb.interfaces
    for interface_id in interfaces:
        interface = interfaces[interface_id]
        for ipaddr in interface.ipaddr:
            addr = ipaddr[0]
            if is_ipv4(addr):
                ip_to_if[addr] = interface.ifname
                if_to_ip[interface.ifname] = addr

    gateway_ifname = ip_to_if[gateway_iface_ip]

    gateway_set_up = False
    default_route_set_up = False
    for route in ipdb.routes:
        if route['family'] != socket.AF_INET:
            continue

        ifname = ipdb.interfaces[route['oif']].ifname
        try:
            dst_addr, dst_mask = route['dst'].split('/')
        except ValueError:
            dst_addr = route['dst']
            dst_mask = None

        if ifname == gateway_ifname and route['dst'] == 'default' and \
           route['gateway'] == gateway:
            logging.debug("Keeping default route via %s in %s",
                          gateway,
                          container['Id'])
            default_route_set_up = True
        elif (ifname in if_to_ip and dst_addr == gateway and
              dst_mask == '32' and ifname == gateway_ifname):
            logging.debug("Keeping route to %s via %s in %s",
                          gateway,
                          ifname,
                          container['Id'])
            gateway_set_up = True
        else:
            logging.info("Removing route '%s' via '%s' in %s",
                         route['dst'], ifname, container['Id'])
            del ipdb.routes[{'dst': route['dst'],
                             'oif': interfaces[ifname].index}]

    if not gateway_set_up:
        logging.info("Adding route to '%s' via '%s' in %s",
                     gateway+'/32',
                     gateway_ifname,
                     container['Id'])

        ipdb.routes.add({'dst': gateway+'/32',
                         'oif': interfaces[gateway_ifname].index,
                         'scope': 253})  # link-local

    if not default_route_set_up:
        logging.info("Adding default route via '%s' in %s",
                     gateway,
                     container['Id'])

        ipdb.routes.add({'dst': 'default',
                         'gateway': gateway,
                         'oif': interfaces[gateway_ifname].index})

    ipdb.commit()


def patch_container_networks(client, network_settings):
    network_names = list(network_settings.keys())

    for container in client.containers():
        container_network_names = \
            container['NetworkSettings']['Networks'].keys()

        if not set(network_names).intersection(container_network_names):
            continue

        inspect = client.inspect_container(container['Id'])

        if not inspect['State']['Running']:
            continue

        pid = inspect['State']['Pid']

        ipdb, netns = get_ipdb_by_pid(pid)

        try:
            patch_container_ip(network_settings, container, ipdb)
        finally:
            ipdb.release()
            netns.close()

        # Re-initializing IPDB is required for IPDB to 'see' routes removed
        # on the previous step

        ipdb, netns = get_ipdb_by_pid(pid)

        try:
            patch_container_route(network_settings, container, ipdb)
        finally:
            ipdb.release()
            netns.close()


def patch_host_routes(client, network_settings):
    network_names = list(network_settings.keys())
    bridge_names = [r['bridge'] for r in network_settings.values()]

    routes_to_add = {}
    for container in client.containers():
        container_networks = container['NetworkSettings']['Networks']
        for network_name, network in container_networks.items():
            addr = network['IPAddress']

            if network_name in network_names:
                routes_to_add[addr] = network_name


    with pyroute2.IPDB() as ipdb:
        for route in ipdb.routes:
            if route['family'] != socket.AF_INET:
                continue

            dst = route['dst']
            ifname = ipdb.interfaces[route['oif']].ifname

            if ifname in bridge_names:
                dst_addr, dst_mask = dst.split('/')

                if dst_addr in list(routes_to_add.keys()) and \
                   dst_mask == '32' and \
                   ifname == network_settings[
                       routes_to_add[dst_addr]]['bridge']:
                    logging.debug("Keeping existing route '%s' via '%s'",
                                  dst, ifname)
                    del routes_to_add[dst_addr]
                elif dst_mask == '32' and ifname in bridge_names:
                    logging.info("Removing dangling route '%s' via '%s'",
                                 dst, ifname)
                    del ipdb.routes[{'dst': dst_addr+'/32'}]

        for addr, network_name in routes_to_add.items():
            bridge_name = network_settings[network_name]['bridge']
            interface_id = ipdb.interfaces[bridge_name]['index']
            logging.info("Adding route to '%s/32' via '%s'", addr, bridge_name)
            ipdb.routes.add({'dst': addr+'/32',
                             'oif': interface_id})
        ipdb.commit()


def docker_network_event_loop(args, lock):
    client = docker.Client(base_url='unix:/' + args.socket)

    try:
        with lock:
            network_settings = get_network_settings(client, args.networks)
            patch_bridge_ips(network_settings)
            patch_host_routes(client, network_settings)
            patch_container_networks(client, network_settings)
    except requests.ConnectionError:
        logging.error("Not doing initial network configuration, " +
                      "because connectionto Docker failed")
    except Exception as ex:
        logging.error("Not doing initial network configuration, "
                      "because of unknown exception: '%s'", str(ex))

    while True:
        try:
            network_settings = get_network_settings(client, args.networks)
            for event_str in client.events():
                with lock:
                    event = json.loads(event_str)
                    if event['Action'] in ['start', 'die']:
                        patch_host_routes(client, network_settings)
                        patch_container_networks(client, network_settings)
        except requests.ConnectionError:
            logging.error("Connection to docker failed while trying to " +
                          "listen for events")
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as ex:
            logging.error("Unknown error: '%s'", str(ex))

        logging.error("Will retry event polling in a few seconds")
        time.sleep(DOCKER_EVENT_RETRY_INTERVAL)


def periodic_docker_network_loop(args, lock):
    client = docker.Client(base_url='unix:/' + args.socket)

    # To not interfere with initial check performed by
    # docker event loop
    time.sleep(DOCKER_TIMER_INTERVAL)

    while True:
        try:
            with lock:
                network_settings = get_network_settings(client, args.networks)
                patch_bridge_ips(network_settings)
                patch_host_routes(client, network_settings)
                patch_container_networks(client, network_settings)
        except requests.ConnectionError:
            logging.error("Connection to docker failed while trying to " +
                          "scan for containers")
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as ex:
            logging.error("Unknown error: '%s'", str(ex))

        time.sleep(DOCKER_TIMER_INTERVAL)


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
    parser.add_argument('-x', '--next-hop', default="127.0.0.1")
    parser.add_argument('-p', '--password', default=default_password)
    parser.add_argument('-a', '--auth-type',
                        choices=['md5', 'plain'], default="md5")
    parser.add_argument('-n', '--neighbor', default="127.0.0.1")

    parser.add_argument('networks', nargs='*', default=['bridge'])

    args = parser.parse_args()

    # Keep track of running containers.
    # Required to detect when containers disappear, so that
    # we can send RIP 'poisoning' notifications.
    container_table = {}

    rip_lock = threading.Lock()
    network_lock = threading.Lock()

    threads = [
        # RIP notification threads
        threading.Thread(target=docker_rip_event_loop,
                         args=(args, container_table, rip_lock)),
        threading.Thread(target=docker_rip_timer_loop,
                         args=[args, container_table, rip_lock]),
        threading.Thread(target=periodic_rip_notification_loop,
                         args=[args, container_table, rip_lock]),
        # Network patching threads
        threading.Thread(target=docker_network_event_loop,
                         args=[args, network_lock]),
        threading.Thread(target=periodic_docker_network_loop,
                         args=[args, network_lock])]

    # 'Daemonize' threads so that it's possible to interrupt
    # the program with ^C
    for thread in threads:
        thread.daemon = True
        thread.start()

    try:
        while True:
            signal.pause()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
