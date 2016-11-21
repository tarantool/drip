class profiles::drip {
  include 'docker'

  $docker_networks = hiera('private::drip::docker_networks')
  $rip_server = hiera('private::drip::rip_server')

  $advertise_addr = "${::next_hop_address}"


  docker::image { 'tarantool/drip':
    ensure    => 'present'
  }

  docker::run { 'drip':
    image      => 'tarantool/drip',
    privileged => true,
    net        => 'host',
    volumes    => '/var/run/docker.sock:/var/run/docker.sock',
    extra_parameters => '--pid=host --restart=always',
    env        => ["DRIP_NETWORKS=${docker_networks}",
                   "DRIP_NEIGHBOR=${rip_server}"]
  }
}
