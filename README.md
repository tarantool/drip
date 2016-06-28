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

## Getting started

As the utility will modify routing, root access is required.

```bash
sudo ./drip.py --next-hop <this-hosts-ip-address> --neighbor <rip-server>
```

* --next-hop is usually the current host's external IP address, visible to the router
* --neighbor is the address of server with RIP daemon

If you now try to start a docker container, you will see that the utility sends
notifications and patches network routes to achieve desired configuration.
