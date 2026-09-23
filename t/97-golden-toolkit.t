use strict;
use warnings;
use Test::More;

use FindBin qw( $Bin );
use lib "$Bin/lib";

# -----------------------------------------------------------------------------
# CHARACTERIZATION ("golden") tests for install_container_toolkit (karr #29,
# T0 of epic #25).
#
# CLAIM: on each OS, install_container_toolkit() hands Rex exactly the host
# interactions recorded in t/golden/toolkit/<os>.txt, in order. Recorded from
# HEAD 3cba655; the refactor tickets must reproduce them byte for byte.
#
# NOT covered: whether the NVIDIA repo URLs resolve, whether the package
# installs, or what the shell does with the curl | gpg / curl | tee pipelines
# -- recorded verbatim, never run. See t/96-golden-driver.t for the rest.
# -----------------------------------------------------------------------------

use Test::RexGPU::Golden qw( record_host golden_is host_names host_profile );
use Rex::GPU::NVIDIA;

sub toolkit_on {
  my ( $host ) = @_;
  return record_host(
    host => $host,
    code => sub { Rex::GPU::NVIDIA::install_container_toolkit() }
  );
}

golden_is(toolkit_on(host_profile($_)), "toolkit/$_") for host_names();

# The verify seam: package not installed after the install command.
golden_is(
  toolkit_on(host_profile('debian-12', responses => [
    [ q{dpkg -l nvidia-container-toolkit 2>/dev/null | grep -q '^ii'} => '', 1 ]
  ])),
  'toolkit/debian-12--not-installed'
);

golden_is(
  toolkit_on(host_profile('rocky-9', responses => [
    [ 'rpm -q nvidia-container-toolkit 2>&1' => 'package nvidia-container-toolkit is not installed', 1 ]
  ])),
  'toolkit/rocky-9--not-installed'
);

# openSUSE has no verification today: a failed zypper install is not noticed.
golden_is(
  toolkit_on(host_profile('leap-15.6', responses => [
    [ 'zypper install -y nvidia-container-toolkit' => 'No provider of nvidia-container-toolkit found.', 104 ]
  ])),
  'toolkit/leap-15.6--install-failed'
);

done_testing;
