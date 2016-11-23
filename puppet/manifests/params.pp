# == Class: drip::params
#
# Default parameter values for the drip module
#
class drip::params {
  $docker_networks = ['bridge']
  $rip_server      = undef
  $advertise_addr  = undef
  $rip_metric      = undef
}
