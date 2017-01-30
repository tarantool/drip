# == Class: profiles::drip
#
# Profile class to install drip daemon as Docker container
#
class drip(
  $docker_networks = $drip::params::docker_networks,
  $rip_server      = $drip::params::rip_server,
  $advertise_addr  = $drip::params::advertise_addr,
  $rip_metric      = $drip::params::rip_metric
) inherits drip::params {
  validate_array($docker_networks)
  validate_ip_address($rip_server)
  validate_ip_address($advertise_addr)
  validate_integer($rip_metric)

  $docker_networks_string = join($docker_networks, ' ')

  ::docker::image { 'tarantool/drip':
    ensure  => 'present',
    require => Service['docker']
  }

  ::docker::run { 'drip':
    require          => Service['docker'],
    image            => 'tarantool/drip',
    privileged       => true,
    net              => 'host',
    volumes          => '/var/run/docker.sock:/var/run/docker.sock',
    extra_parameters => '--pid=host --restart=always',
    env              => [
      "DRIP_NETWORKS=${docker_networks_string}",
      "DRIP_NEIGHBOR=${rip_server}",
      "DRIP_NEXT_HOP=${advertise_addr}"]
  }
}
