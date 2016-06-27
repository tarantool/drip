#!/usr/bin/env python

import docker
import logging
import gevent
import json
from pyroute2 import IPRoute, IPDB, NetNS
import socket
import os

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


def patch_bridge_ips(network_settings):
    network_names = list(network_settings.keys())
    bridge_names = [r['bridge'] for r in network_settings.values()]

    ipdb = IPDB()

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
                    logging.error('Replacing %s/%d with %s/%d on %s',
                                  addr, mask,
                                  addr, 32,
                                  interface.ifname)
                    interface.del_ip(addr+'/'+str(mask))
                    interface.add_ip(addr+'/32')
                    ipaddr_set = True
                else:
                    ipaddr_set = True

        if not ipaddr_set:
            bridges = {n['bridge']: n['gateway'] for n in network_settings.values()}
            addr = bridges[interface.ifname]
            mask = 32
            logging.error('Setting %s/%d on %s',
                          addr, mask,
                          interface.ifname)

            interface.add_ip(addr+'/'+str(mask))

    ipdb.commit()

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

    ipdb = IPDB(nl=NetNS(str(pid)))
    return ipdb

def patch_container_ip(client, network_settings, container, ipdb):
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
                    logging.error('Replacing %s/%d with %s/%d on %s in %s',
                                  addr, mask,
                                  addr, 32,
                                  interface.ifname,
                                  container['Id'])
                    interface.del_ip(addr+'/'+str(mask))
                    interface.add_ip(addr+'/32')

    ipdb.commit()

def patch_container_route(client, network_settings, container, ipdb):
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
        except Exception:
            dst_addr = route['dst']
            dst_mask = None

        if ifname == gateway_ifname and route['dst'] == 'default' and \
           route['gateway'] == gateway:
            logging.error("Keeping default route via %s in %s",
                          gateway,
                          container['Id'])
            default_route_set_up = True
        elif ifname in if_to_ip and dst_addr == gateway and \
             dst_mask == '32' and ifname == gateway_ifname:
            logging.error("Keeping route to %s via %s in %s",
                          gateway,
                          ifname,
                          container['Id'])
            gateway_set_up = True
        else:
            logging.error("Removing route '%s' via '%s' in %s",
                              route['dst'], ifname, container['Id'])
            del ipdb.routes[{'dst': route['dst'], 'oif': interfaces[ifname].index}]

    if not gateway_set_up:
        logging.error("Adding route to '%s' via '%s' in %s",
                      gateway+'/32',
                      gateway_ifname,
                      container['Id'])

        ipdb.routes.add({'dst': gateway+'/32',
                         'oif': interfaces[gateway_ifname].index,
                         'scope':253 # link-local
        })

    ipdb.commit()

    if not default_route_set_up:
        logging.error("Adding default route via '%s' in %s",
                      gateway,
                      container['Id'])

        ipdb.routes.add({'dst': 'default',
                         'gateway': gateway,
                         'oif': interfaces[gateway_ifname].index})


    ipdb.commit()



def patch_container_networks(client, network_settings):
    network_names = list(network_settings.keys())

    for container in client.containers():
        container_network_names = container['NetworkSettings']['Networks'].keys()

        if not set(network_names).intersection(container_network_names):
            continue

        inspect = client.inspect_container(container['Id'])

        if not inspect['State']['Running']:
            continue

        pid = inspect['State']['Pid']


        ipdb = get_ipdb_by_pid(pid)

        try:
            patch_container_ip(client, network_settings, container, ipdb)
        finally:
            ipdb.release()

        # Re-initializing IPDB is required for IPDB to 'see' routes removed
        # on the previous step

        ipdb = get_ipdb_by_pid(pid)

        try:
            patch_container_route(client, network_settings, container, ipdb)
        finally:
            ipdb.release()



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


    ips = list(routes_to_add.keys())
    #print routes_to_add

    ipdb = IPDB()

    for route in ipdb.routes:
        if route['family'] != socket.AF_INET:
            continue

        dst = route['dst']
        ifname = ipdb.interfaces[route['oif']].ifname
        #print "dst: ", dst, " if: ", ifname, "route: ", route

        if ifname in bridge_names:
            dst_addr, dst_mask = dst.split('/')

            if dst_addr in list(routes_to_add.keys()) and \
               dst_mask == '32' and \
               ifname == network_settings[routes_to_add[dst_addr]]['bridge']:
                logging.debug("Keeping existing route '%s' via '%s'",
                              dst, ifname)
                del routes_to_add[dst_addr]
            elif dst_mask == '32' and ifname in bridge_names:
                logging.error("Removing dangling route '%s' via '%s'",
                              dst, ifname)
                del ipdb.routes[{'dst': dst_addr+'/32'}]

    for addr, network_name in routes_to_add.items():
        bridge_name = network_settings[network_name]['bridge']
        interface_id = ipdb.interfaces[bridge_name]['index']
        logging.error("Adding route to '%s/32' via '%s'", addr, bridge_name)
        ipdb.routes.add({'dst': addr+'/32',
                         'oif': interface_id})
    ipdb.commit()
    #print ip.route("get",
    #     dst="10.211.55.0")
#    for route in routes:
#        dst = route.get_attr('RTA_DST')
#        iface_id = route.get_attr('RTA_OIF')
#        print "DST: ",


def container_scan_loop(client, network_settings):
    patch_host_routes(client, network_settings)
    patch_container_networks(client, network_settings)

    while(True):
        for event_str in client.events():
            event = json.loads(event_str)
            if event['Action'] in ['start', 'die']:
                patch_host_routes(client, network_settings)
                patch_container_networks(client, network_settings)

        gevent.sleep(10)


def main():
    docker_sock = '/var/run/docker.sock'
    client = docker.Client(base_url='unix:/' + docker_sock)

    network_settings = get_network_settings(client, ["bridge", "foo"])

    patch_bridge_ips(network_settings)
    try:
        gevent.joinall([
            gevent.spawn(container_scan_loop, client, network_settings)
        ])
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
