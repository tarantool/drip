# RIP-based routing for Docker containers

This utility is an all-in-one method to integrate docker infrastructure
to networks using RIP-based routing.

## Motivation

There are many ways to achieve arbitrary network configuration with Docker, but
most of them make using Docker API impossible, as they require pre- and
post-actions, which must be done locally. The main goals of this utility is to
be as transparent as possible, require minimum configuration allow users to
work with standard Docker API.

## Dependencies

- docker-py
- pyroute2
- requests

To install the dependencies, you can do:

``` bash
sudo pip install -r requirements.txt
```

## Getting started

As the utility will modify routing, root access is required.

```bash
sudo ./drip.py --next-hop <this-hosts-ip-address> --neighbor <rip-server>
```

* --next-hop is usually the current host's external IP address, visible to the router
* --neighbor is the address of server with RIP daemon

If you now try to start a docker container, you will see that the utility sends
notifications and patches network routes to achieve desired configuration.

## Running drip in Docker

To make it easier, you can run drip itself in Docker in privileged mode.

First, build an image:

```bash
docker build -t drip .
```

Then run it:

```bash
docker run --rm -t -i --net=host --pid=host --privileged -v /var/run/docker.sock:/var/run/docker.sock -e DRIP_NETWORKS=bridge drip
```

Note:

* It is important to set --net=host as otherwise drip won't be able to patch host network
* Also, --pid=host is used so that drip will see host's /proc to access network namespaces
* --privileged is used to gain effective root on host
