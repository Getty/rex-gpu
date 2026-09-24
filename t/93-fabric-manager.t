use strict;
use warnings;
use Test::More;

use FindBin qw( $Bin );
use lib "$Bin/lib";

# -----------------------------------------------------------------------------
# NVSwitch detection and NVIDIA Fabric Manager (karr #23).
#
# CLAIMS:
#   * detect() reports NVIDIA [0680] bridges as nvswitch only by a known
#     NVSwitch ID (1ac2/1af1/22a3) or an "NVSwitch" name; another NVIDIA
#     bridge is skipped; the extra lspci runs only when an NVIDIA GPU was
#     found; nvidia/amd are unchanged;
#   * an HGX B200 (8x B200, its NVSwitches are not PCI devices) yields no
#     nvswitch -- the install is exactly the one without it;
#   * gpu_setup passes nvswitches to install_driver only when there is one;
#   * with nvswitches the driver source must name a Fabric Manager: Debian
#     non-free is skipped for the CUDA repo, Debian 11 / openSUSE die with
#     read-only probes only; on apt a missing Fabric Manager candidate dies
#     after apt-get update and before any install;
#   * Fabric Manager is installed AFTER the driver is verified, at exactly
#     the installed driver's upstream version (apt: PKG=<madison version>,
#     rpm: PKG-<version>), verified with dpkg/rpm, and the unit is enabled,
#     not started, before post_install; install_driver starts it after
#     modprobe and checks is-active (warns only);
#   * no version match / a mismatched result dies, naming both versions,
#     with no install of another version;
#   * an already-installed driver gets no Fabric Manager install, only the
#     is-active check (warn).
#
# NOT covered -- none of it runs without a real HGX host: that the package
# names exist in the repos at those versions, that the lspci -nn line of a
# real NVSwitch looks like the hand-built fixture (NVIDIA's docs only show
# plain lspci), that Fabric Manager starts and the GPUs reach Fabric State
# "Completed", or anything on HGX B200/B300 (NVLSM, CX7 bridges).
# -----------------------------------------------------------------------------

use Test::RexGPU::Golden qw(
  record_host golden_is host_profile gpu_fixture mutating_lines working_driver
);
use Rex::GPU;
use Rex::GPU::Detect;
use Rex::GPU::NVIDIA;

my $H100_LINE = '18:00.0 3D controller [0302]: NVIDIA Corporation GH100 [H100 SXM5 80GB] [10de:2330] (rev a1)';
my @NVSWITCH_LINES = map {
  sprintf('%02x:00.0 Bridge [0680]: NVIDIA Corporation GH100 [H100 NVSwitch] [10de:22a3] (rev a1)', $_)
} 5 .. 8;

my $LSPCI_PROBE   = 'command -v lspci >/dev/null 2>&1';
my $DISPLAY_READ  = q{lspci -nn 2>&1 | grep -E '\[03(00|02)\]'};
my $NVSWITCH_READ = q{lspci -nn -d 10de: 2>/dev/null | grep -F '[0680]'};

# detect() with run() answering per command; records the commands. lspci is
# on the PATH (karr #46's probe exits 0), so nothing is installed.
sub detect_on {
  my ( %answer ) = @_;
  my @cmds;
  no warnings 'redefine';
  local *Rex::GPU::Detect::is_installed = sub { 1 };
  local *Rex::GPU::Detect::run = sub {
    my ( $cmd ) = @_;
    push @cmds, $cmd;
    $? = 0;
    return $cmd eq $LSPCI_PROBE ? ''
      : $cmd =~ /\[0680\]/ ? $answer{nvswitch}
      : $answer{display};
  };
  local *Rex::Logger::info = sub { };
  return ( Rex::GPU::Detect::detect(), \@cmds );
}

#### Detection

subtest 'HGX H100: 8 GPUs + 4 NVSwitches' => sub {
  my ( $r, $cmds ) = detect_on(
    display  => join("\n", ($H100_LINE) x 8),
    nvswitch => join("\n", @NVSWITCH_LINES)
  );
  is(scalar @{ $r->{nvidia} }, 8, '8 GPUs');
  is(scalar @{ $r->{nvswitch} }, 4, '4 NVSwitches');
  is_deeply($r->{nvswitch}[0], { name => 'GH100 [H100 NVSwitch]', vendor => 'nvidia',
    pci_class => '0680', device_id => '22a3' }, 'NVSwitch element');
  is_deeply($cmds, [ $LSPCI_PROBE, $DISPLAY_READ, $NVSWITCH_READ ],
    'probe, display lspci, then the second, read-only lspci');
};

subtest 'NVSwitch recognised by ID with a stale pci.ids, and by name' => sub {
  my $sw = Rex::GPU::Detect::_parse_nvswitch_line(
    '07:00.0 Bridge [0680]: NVIDIA Corporation Device [10de:1af1] (rev a1)');
  is($sw->{device_id}, '1af1', 'A100 NVSwitch by ID, name "Device"');
  $sw = Rex::GPU::Detect::_parse_nvswitch_line(
    '07:00.0 Bridge [0680]: NVIDIA Corporation GXXX [Future NVSwitch] [10de:ffff] (rev a1)');
  is($sw->{device_id}, 'ffff', 'unknown ID named NVSwitch');
};

subtest 'other NVIDIA bridges and other classes are not NVSwitches' => sub {
  my @log;
  no warnings 'redefine';
  local *Rex::Logger::info = sub { push @log, $_[0] };
  is(Rex::GPU::Detect::_parse_nvswitch_line(
    '00:08.0 Bridge [0680]: NVIDIA Corporation MCP55 Ethernet [10de:0373] (rev a3)'), undef,
    'nForce bridge (10de:0373) skipped');
  like($log[0], qr/not known as an NVSwitch/, '... and logged');
  is(Rex::GPU::Detect::_parse_nvswitch_line($H100_LINE), undef, 'a GPU line is not an NVSwitch');
  is(Rex::GPU::Detect::_parse_nvswitch_line(
    '07:00.0 Bridge [0680]: Mellanox Technologies Device [15b3:1021]'), undef, 'non-NVIDIA bridge');
};

subtest 'no NVIDIA GPU => no NVSwitch probe' => sub {
  my ( $r, $cmds ) = detect_on(
    display  => '0a:00.0 VGA compatible controller [0300]: Advanced Micro Devices, Inc. [AMD/ATI] Navi 31 [Radeon RX 7900 XTX] [1002:744c] (rev c8)',
    nvswitch => join("\n", @NVSWITCH_LINES)
  );
  is_deeply($cmds, [ $LSPCI_PROBE, $DISPLAY_READ ], 'only the probe and the display lspci ran');
  is_deeply($r->{nvswitch}, [], 'nvswitch => []');
  ( $r ) = detect_on(display => '', nvswitch => '');
  is_deeply($r->{nvswitch}, [], 'empty lspci => nvswitch => []');
};

subtest 'HGX B200: no NVSwitch on the host PCI bus' => sub {
  # Per NVIDIA's Fabric Manager guide the gen4 NVSwitches are behind CX-7
  # bridge functions; the host's lspci shows those (15b3), not a 10de [0680].
  my ( $r ) = detect_on(
    display  => join("\n", ('18:00.0 3D controller [0302]: NVIDIA Corporation GB100 [B200] [10de:2901] (rev a1)') x 8),
    nvswitch => ''
  );
  is(scalar @{ $r->{nvidia} }, 8, '8 B200');
  is_deeply($r->{nvswitch}, [], 'no NVSwitch detected -- no Fabric Manager (documented gap)');
};

#### gpu_setup passes nvswitches only when there is one

subtest 'gpu_setup -> install_driver' => sub {
  my @calls;
  no warnings 'redefine';
  local *Rex::GPU::_check_connection = sub { };
  local *Rex::GPU::NVIDIA::install_driver = sub { push @calls, { @_ } };
  local *Rex::GPU::NVIDIA::install_container_toolkit = sub { };
  local *Rex::GPU::NVIDIA::generate_cdi_specs = sub { };
  local *Rex::GPU::NVIDIA::configure_containerd = sub { };
  local *Rex::GPU::NVIDIA::verify_nvidia = sub { };
  local *Rex::Logger::info = sub { };
  my $switches = [ { name => 'GH100 [H100 NVSwitch]', device_id => '22a3' } ];
  my $gpu = gpu_fixture('h100');
  local *Rex::GPU::gpu_detect = sub { { nvidia => [ $gpu ], amd => [], nvswitch => $switches } };
  Rex::GPU::gpu_setup();
  is($calls[0]{nvswitches}, $switches, 'NVSwitch host: nvswitches passed');
  local *Rex::GPU::gpu_detect = sub { { nvidia => [ $gpu ], amd => [], nvswitch => [] } };
  Rex::GPU::gpu_setup();
  ok(!exists $calls[1]{nvswitches}, 'no NVSwitch: the call is what it was before');
};

#### install_driver with nvswitches

my $NVSW = [ { name => 'GH100 [H100 NVSwitch]', device_id => '22a3', pci_class => '0680', vendor => 'nvidia' } ];

sub hgx_on {
  my ( $host, %opt ) = @_;
  return record_host(host => $host, code => sub {
    Rex::GPU::NVIDIA::install_driver(gpus => [ gpu_fixture('h100') ], nvswitches => $NVSW, %opt) });
}

my @UBUNTU_FM = (
  [ q{dpkg-query -W -f='${Version}' nvidia-driver-590-server 2>/dev/null} => '590.48.01-0ubuntu0.24.04.1', 0 ],
  [ q{dpkg-query -W -f='${Version}' nvidia-fabricmanager-590 2>/dev/null} => '590.48.01-0ubuntu0.24.04.1', 0 ],
  [ 'apt-cache madison nvidia-fabricmanager-590 2>/dev/null' =>
      " nvidia-fabricmanager-590 | 590.48.02-0ubuntu0.24.04.1 | http://archive.ubuntu.com/ubuntu noble-updates/multiverse amd64 Packages\n"
    . " nvidia-fabricmanager-590 | 590.48.01-0ubuntu0.24.04.1 | http://archive.ubuntu.com/ubuntu noble-updates/multiverse amd64 Packages", 0 ]
);
my @RHEL_FM = (
  [ q{rpm -q --qf '%{VERSION}' nvidia-fabricmanager 2>&1} => '580.95.05', 0 ]
);
my @DEBIAN_FM = (
  [ 'LC_ALL=C apt-cache policy nvidia-fabricmanager 2>/dev/null' =>
      "nvidia-fabricmanager:\n  Installed: (none)\n  Candidate: 615.71.09-1\n", 0 ],
  [ q{dpkg-query -W -f='${Version}' nvidia-kernel-open-dkms 2>/dev/null} => '615.71.09-1', 0 ],
  [ q{dpkg-query -W -f='${Version}' nvidia-fabricmanager 2>/dev/null} => '615.71.09-1', 0 ],
  [ 'apt-cache madison nvidia-fabricmanager 2>/dev/null' =>
      " nvidia-fabricmanager | 615.71.09-1 | https://developer.download.nvidia.com/compute/cuda/repos/debian12/x86_64  Packages", 0 ]
);

{
  my $rec = hgx_on(host_profile('ubuntu-24.04', responses => [ @UBUNTU_FM ]));
  is($rec->{error}, undef, 'ubuntu-24.04 HGX H100: lives');
  golden_is($rec, 'driver/ubuntu-24.04--hgx-h100');
  my @l = @{ $rec->{lines} };
  my ( $drv ) = grep { $l[$_] =~ /install -y linux-headers/ } 0 .. $#l;
  my ( $fm )  = grep { $l[$_] =~ /install -y nvidia-fabricmanager-590=590\.48\.01-0ubuntu0\.24\.04\.1$/ } 0 .. $#l;
  my ( $nou ) = grep { $l[$_] =~ /blacklist-nouveau/ } 0 .. $#l;
  ok(defined $drv && defined $fm && $drv < $fm && $fm < $nou,
    '... Fabric Manager pinned to the driver\'s upstream version, after the driver, before nouveau');
}

golden_is(hgx_on(host_profile('rocky-9', responses => [ @RHEL_FM ])), 'driver/rocky-9--hgx-h100');
golden_is(hgx_on(host_profile('rocky-10', responses => [ @RHEL_FM ])), 'driver/rocky-10--hgx-h100');

{
  my $rec = hgx_on(host_profile('debian-12', responses => [ @DEBIAN_FM ]));
  is($rec->{error}, undef, 'debian-12 HGX H100: lives');
  ok(!(grep { /nvidia-driver nvidia-smi libcuda1/ } @{ $rec->{lines} }), '... non-free is not used');
  golden_is($rec, 'driver/debian-12--hgx-h100');
}

# No source with a Fabric Manager: dies in plan, read-only probes only.
for my $case ([ 'debian-12', release => '11.11' ], [ 'leap-15.6' ], [ 'leap-16.0' ]) {
  my ( $os, @over ) = @$case;
  my $rec = hgx_on(host_profile($os, @over));
  like($rec->{error}, qr/no NVIDIA Fabric Manager package for the NVSwitch on this host.*Nothing was changed/,
    "$os @over HGX H100: dies naming the missing Fabric Manager");
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... only read-only probes');
}

# Without nvswitches the same GPU on the same host is the plain install.
{
  my $with_empty = record_host(host => host_profile('debian-12'), code => sub {
    Rex::GPU::NVIDIA::install_driver(gpus => [ gpu_fixture('h100') ], nvswitches => []) });
  my $without = record_host(host => host_profile('debian-12'), code => sub {
    Rex::GPU::NVIDIA::install_driver(gpus => [ gpu_fixture('h100') ]) });
  is_deeply($with_empty->{lines}, $without->{lines}, 'nvswitches => [] changes nothing');
  ok(!(grep { /fabricmanager/ } @{ $without->{lines} }), '... and emits no Fabric Manager command');
}

# apt: no candidate for the Fabric Manager after apt-get update -> dies
# before any install.
{
  my $rec = hgx_on(host_profile('ubuntu-24.04', responses => [
    [ 'LC_ALL=C apt-cache policy nvidia-fabricmanager-590 2>/dev/null' => '', 0 ], @UBUNTU_FM ]));
  like($rec->{error}, qr/has no Fabric Manager for the NVSwitch.*nvidia-fabricmanager-590 has no installation candidate.*No driver package was installed/,
    'ubuntu: no Fabric Manager candidate dies');
  is_deeply([ grep { / install / } @{ $rec->{lines} } ], [], '... before any install');
}

# apt: madison has no Fabric Manager of the driver's version -> dies after
# the driver, installs no other version.
{
  my $rec = hgx_on(host_profile('ubuntu-24.04', responses => [
    [ 'apt-cache madison nvidia-fabricmanager-590 2>/dev/null' =>
        " nvidia-fabricmanager-590 | 590.48.02-0ubuntu0.24.04.1 | http://archive.ubuntu.com/ubuntu noble-updates/multiverse amd64 Packages", 0 ],
    @UBUNTU_FM ]));
  like($rec->{error}, qr/apt has no nvidia-fabricmanager-590 of driver version 590\.48\.01/,
    'ubuntu: no matching Fabric Manager version dies');
  ok(!(grep { /install -y nvidia-fabricmanager/ } @{ $rec->{lines} }), '... no Fabric Manager install');
  ok(!(grep { /blacklist-nouveau/ } @{ $rec->{lines} }), '... before post_install');
}

# rpm: dnf installed some other version -> dies naming both.
{
  my $rec = hgx_on(host_profile('rocky-9', responses => [
    [ q{rpm -q --qf '%{VERSION}' nvidia-fabricmanager 2>&1} => '615.71.09', 0 ] ]));
  like($rec->{error}, qr/nvidia-fabricmanager is 615\.71\.09 after dnf install, not the driver's 580\.95\.05/,
    'rocky-9: mismatched Fabric Manager dies');
}

# rpm: the driver version cannot be read -> dies, no Fabric Manager install.
{
  my $rec = hgx_on(host_profile('rocky-9', responses => [
    [ q{rpm -q --qf '%{VERSION}' nvidia-driver 2>&1} => 'package nvidia-driver is not installed', 1 ],
    [ 'rpm -q nvidia-driver 2>&1' => 'nvidia-driver-580.95.05', 0 ] ]));
  like($rec->{error}, qr/Cannot read the installed NVIDIA driver version/, 'rocky-9: unreadable driver version dies');
  ok(!(grep { /install -y nvidia-fabricmanager/ } @{ $rec->{lines} }), '... no Fabric Manager install');
}

# The unit cannot be enabled -> dies.
{
  my $rec = hgx_on(host_profile('rocky-9', responses => [
    [ 'systemctl enable nvidia-fabricmanager.service' => 'Failed to enable unit', 1 ], @RHEL_FM ]));
  like($rec->{error}, qr/systemctl enable nvidia-fabricmanager\.service failed/, 'enable failure dies');
}

# Fabric Manager not active after modprobe: warns, does not die.
{
  my $rec = hgx_on(host_profile('rocky-9', responses => [
    [ 'systemctl is-active --quiet nvidia-fabricmanager.service' => '', 3 ], @RHEL_FM ]));
  is($rec->{error}, undef, 'inactive Fabric Manager after install: no die');
  ok((grep { $_->[0] eq 'warn' && $_->[1] =~ /NVSwitch present but nvidia-fabricmanager\.service is not active/ } @{ $rec->{logs} }),
    '... warns');
}

# Already-installed driver: no Fabric Manager install, only the check.
{
  my $rec = hgx_on(host_profile('ubuntu-24.04', responses => [
    working_driver(), [ 'systemctl is-active --quiet nvidia-fabricmanager.service' => '', 3 ] ]));
  is($rec->{error}, undef, 'already installed + NVSwitch: no die');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... nothing installed');
  ok((grep { $_->[0] eq 'warn' && $_->[1] =~ /is not active/ } @{ $rec->{logs} }), '... warns');
}

#### Setup unit bits

is(Rex::GPU::NVIDIA::Setup::Apt->_dpkg_upstream_version('1:580.95.05-0ubuntu1'), '580.95.05', 'epoch + revision stripped');
is(Rex::GPU::NVIDIA::Setup::Apt->_dpkg_upstream_version(''), undef, 'empty => undef');
is(Rex::GPU::NVIDIA::Setup->_is_driver_version('580.95.05'), 1, '580.95.05 is a driver version');
is(Rex::GPU::NVIDIA::Setup->_is_driver_version('package nvidia-driver is not installed'), 0, 'rpm error is not');
is(Rex::GPU::NVIDIA::Setup->fabric_manager_package({ fabric_manager => 'nvidia-fabricmanager-%s', branch_at_least => 580 }),
  undef, 'no exact branch => no package name');

{
  my $setup = Rex::GPU::NVIDIA::Setup::Ubuntu->new;
  $setup->adopt(nvswitches => $NVSW);
  ok($setup->fabric_manager_needed, 'adopt hands NVSwitches to an object without any');
  eval { Rex::GPU::NVIDIA::Setup->new(nvswitches => {}) };
  like($@, qr/nvswitches must be an arrayref/, 'new: nvswitches must be an arrayref');
}

done_testing;
