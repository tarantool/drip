# drip daemon puppet manifest

This manifest helps you deploy 'drip' daemon to production machines.
It will announce new containers via RIP protocol.

*NB:* It runs 'drip' damon itself in a privileged Docker container.
If you need to run it as a regular systemd service, pull requests are welcome.

## Dependencies

* [docker](https://forge.puppet.com/garethr/docker) from puppet forge

## Platforms

* Centos 7
* Ubuntu 16.04
* Ubuntu 14.04


## Usage

The module declares a single role:

``` puppet
include roles::drip
```

It requires that you define one fact:

``` puppet
next_hop_address: <ip address>
```

The `next_hop_address` is IP address that will be sent in RIP packets as
"next hop". Usually it's the address of current physical node.

Also, it needs 2 variables defined in hiera:

``` yaml
---
private::drip::docker_networks: <networks>
private::drip::rip_server: <IP address>
```

* `docker_networks` is a comma-separated list of docker network names
(*NB:* not interface names!) that will be scanned for containers by 'drip'
daemon.

* `rip_server` is an address where 'drip' daemon will send RIP announces.

## Testing

This manifest has no integration tests, but there is a test-kitchen definition
that you can use to check that it converges.

``` bash
cd puppet
kitchen converge
```

To run it you will need:

* [test-kitchen](http://kitchen.ci) itself
* [vagrant](http://vagrantup.com)
* [puppet](https://puppet.com)
* [hiera](https://github.com/puppetlabs/hiera)
* [puppet plugin for test-kitchen](https://github.com/neillturner/kitchen-puppet)
* [librarian-puppet](http://librarian-puppet.com) to fetch dependencies

## Authors

* Konstantin Nazarov <mail@kn.am>
