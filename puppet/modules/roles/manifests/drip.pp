# == Class: roles::drip
#
# Role class to install drip daemon as Docker container
#
class roles::drip {
  include profiles::drip
}
