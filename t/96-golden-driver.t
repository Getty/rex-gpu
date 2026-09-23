use strict;
use warnings;
use Test::More;

use FindBin qw( $Bin );
use lib "$Bin/lib";

# -----------------------------------------------------------------------------
# CHARACTERIZATION ("golden") tests for install_driver (karr #29, T0 of epic
# #25).
#
# CLAIM: for each GPU x OS below, install_driver(gpu => ...) hands Rex exactly
# the host interactions recorded in t/golden/driver/<os>--<gpu>.txt, in that
# order -- every run/pkg/file/can_run call with its full command string. The
# goldens record what the code does TODAY (HEAD 3cba655), not what it should
# do: the T2-T4 refactors of epic #25 must reproduce them byte for byte. A
# diff is a behaviour change -- read it before regenerating (see
# t/lib/Test/RexGPU/Golden.pm for the switch).
#
# Kepler (K80) is asserted inline on every OS: it must die with the "Nothing
# was changed" message after the nvidia-smi probe and before any other host
# interaction.
#
# NOT covered -- none of this runs without a real GPU host, and a green prove
# is NOT evidence that a driver installs:
#   * what the remote shell does with a command string (pipes, sed, awk,
#     `|| true`, `$(...)` are recorded verbatim, never evaluated);
#   * whether a recorded package exists / installs / DKMS-builds on the real
#     release, or the module binds after the nouveau reboot;
#   * install_driver(reboot => 1) (_reboot_and_wait sleeps and reconnects);
#   * the host outputs are hand-written stand-ins (uname -r, apt-cache search,
#     rpm -q ...), not captures from real hosts.
# -----------------------------------------------------------------------------

use Test::RexGPU::Golden qw(
  record_host golden_is host_names host_profile gpu_fixture mutating_lines
);
use Rex::GPU::NVIDIA;

my @GPUS = qw( ada blackwell volta none );

sub driver_on {
  my ( $host, $gpu ) = @_;
  return record_host(
    host => $host,
    code => sub { Rex::GPU::NVIDIA::install_driver(gpu => $gpu) }
  );
}

subtest 'fixtures come from the real lspci parser' => sub {
  for my $name (qw( ada blackwell volta kepler )) {
    my $gpu = gpu_fixture($name);
    is($gpu->{compute}, 1, "$name is compute");
    like($gpu->{device_id}, qr/^[0-9a-f]{4}$/, "$name has a device id");
  }
  is(gpu_fixture('none'), undef, 'none => undef (install_driver without gpu =>)');
};

#### The matrix

for my $os (host_names()) {
  for my $g (@GPUS) {
    my $rec = driver_on(host_profile($os), gpu_fixture($g));
    golden_is($rec, "driver/$os--$g");
  }
}

#### Kepler: dies before touching the host, on every OS

for my $os (host_names()) {
  my $rec = driver_on(host_profile($os), gpu_fixture('kepler'));
  like($rec->{error}, qr/Kepler or older.*Nothing was changed on the host/,
    "$os + K80 dies with the Kepler message");
  is_deeply($rec->{lines}, [ 'run: nvidia-smi -L 2>&1' ],
    "$os + K80: only the nvidia-smi probe ran");
}

#### Already-installed short-circuit

for my $os (host_names()) {
  my $rec = driver_on(
    host_profile($os, responses => [
      [ 'nvidia-smi -L 2>&1' => 'GPU 0: NVIDIA RTX 4000 SFF Ada Generation (UUID: GPU-0)', 0 ]
    ]),
    gpu_fixture('kepler')
  );
  is($rec->{error}, undef, "$os + working driver: no die, even for a K80");
  is_deeply($rec->{lines}, [ 'run: nvidia-smi -L 2>&1' ],
    "$os + working driver: nothing but the probe");
}

#### Failure variants on the install-verify seam and the selection guards

# Driver package not ii after apt-get install (e.g. DKMS build failed in
# postinst): dies after the install, before nouveau is touched.
golden_is(
  driver_on(host_profile('debian-12', responses => [
    [ q{dpkg -l nvidia-driver 2>/dev/null | grep -q '^ii'} => '', 1 ]
  ]), gpu_fixture('ada')),
  'driver/debian-12--ada--not-installed'
);

golden_is(
  driver_on(host_profile('rocky-9', responses => [
    [ 'rpm -q nvidia-driver 2>&1' => 'package nvidia-driver is not installed', 1 ]
  ]), gpu_fixture('ada')),
  'driver/rocky-9--ada--not-installed'
);

# Pre-Turing on RHEL 10 gets a newer branch than 580: dies after install.
golden_is(
  driver_on(host_profile('rocky-10', responses => [
    [ q{rpm -q --qf '%{VERSION}' nvidia-driver 2>&1} => '590.44.01', 0 ]
  ]), gpu_fixture('volta')),
  'driver/rocky-10--volta--wrong-branch'
);

# Ubuntu, V100, no candidate for nvidia-driver-580-server: dies after
# apt-get update and before any install.
{
  my $rec = driver_on(host_profile('ubuntu-24.04', responses => [
    [ qr{^LC_ALL=C apt-cache policy } => "nvidia-driver-580-server:\n  Installed: (none)\n  Candidate: (none)\n", 0 ]
  ]), gpu_fixture('volta'));
  golden_is($rec, 'driver/ubuntu-24.04--volta--no-candidate');
  is_deeply([ grep { / install / } @{ $rec->{lines} } ], [],
    'ubuntu-24.04 + V100 without candidate: no install command emitted');
}

# Ubuntu, apt-cache search finds nothing: the hard-coded 570 fallback.
golden_is(
  driver_on(host_profile('ubuntu-24.04', responses => [
    [ qr{^apt-cache search } => '', 0 ]
  ]), gpu_fixture('ada')),
  'driver/ubuntu-24.04--ada--empty-search'
);

# deb822 (karr #36): debian.sources already carries every component -- read,
# not rewritten (no file: line).
golden_is(
  driver_on(host_profile('debian-13', responses => [
    [ 'cat /etc/apt/sources.list.d/debian.sources 2>/dev/null' =>
        "Types: deb\nURIs: http://deb.debian.org/debian/\nSuites: trixie trixie-updates\n"
      . "Components: main contrib non-free non-free-firmware\n"
      . "Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp", 0 ]
  ]), gpu_fixture('ada')),
  'driver/debian-13--ada--nonfree-enabled'
);

# Both formats on one host: sources.list is rewritten first, then the deb822
# file (Hetzner mirror); a third-party .sources file is read but
# not written, and a name apt ignores is not even read.
golden_is(
  driver_on(host_profile('debian-12', responses => [
    [ 'ls -1 /etc/apt/sources.list.d/ 2>/dev/null' =>
        "debian.sources\nhashicorp.sources\nnvidia-container-toolkit.list\nold.sources.bak", 0 ],
    [ 'cat /etc/apt/sources.list.d/debian.sources 2>/dev/null' =>
        "Types: deb\nURIs: http://mirror.hetzner.com/debian/packages\nSuites: bookworm bookworm-updates\n"
      . "Components: main\n", 0 ],
    [ 'cat /etc/apt/sources.list.d/hashicorp.sources 2>/dev/null' =>
        "Types: deb\nURIs: https://apt.releases.hashicorp.com\nSuites: bookworm\nComponents: main\n"
      . "Signed-By: /usr/share/keyrings/hashicorp-archive-keyring.gpg", 0 ]
  ]), gpu_fixture('ada')),
  'driver/debian-12--ada--both-formats'
);

# Classic sources.list as the bookworm installer writes it (karr #40): "main
# non-free-firmware" must not pass for non-free -- contrib non-free are
# appended to the deb lines; deb-src, the commented cdrom line and a
# third-party line are written back unchanged.
golden_is(
  driver_on(host_profile('debian-12', responses => [
    [ 'cat /etc/apt/sources.list 2>/dev/null' =>
        "#deb cdrom:[Debian GNU/Linux 12.11.0 _Bookworm_]/ bookworm contrib main non-free-firmware\n"
      . "deb http://deb.debian.org/debian/ bookworm main non-free-firmware\n"
      . "deb-src http://deb.debian.org/debian/ bookworm main non-free-firmware\n"
      . "deb http://security.debian.org/debian-security bookworm-security main non-free-firmware\n"
      . "deb http://deb.debian.org/debian/ bookworm-updates main non-free-firmware\n"
      . "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com bookworm main", 0 ]
  ]), gpu_fixture('ada')),
  'driver/debian-12--ada--installer-sources'
);

# Classic sources.list already complete: read, not rewritten (no file: line).
golden_is(
  driver_on(host_profile('debian-12', responses => [
    [ 'cat /etc/apt/sources.list 2>/dev/null' =>
        "deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware", 0 ]
  ]), gpu_fixture('ada')),
  'driver/debian-12--ada--nonfree-enabled'
);

# Blackwell on a Debian release NVIDIA has no CUDA repo for: dies before any
# host change.
{
  my $rec = driver_on(host_profile('debian-12', release => '11.11'), gpu_fixture('blackwell'));
  like($rec->{error}, qr/NVIDIA's CUDA repo only covers Debian 12 and 13/,
    'debian-11 + RTX 5090 dies naming the supported releases');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [],
    'debian-11 + RTX 5090: only read-only probes before the die');
  golden_is($rec, 'driver/debian-11--blackwell');
}

#### The harness itself

subtest 'mocks are restored after every recording' => sub {
  my $orig_run = \&Rex::GPU::NVIDIA::run;
  my $orig_log = \&Rex::Logger::info;
  driver_on(host_profile('debian-12'), gpu_fixture('ada'));
  driver_on(host_profile('debian-12'), gpu_fixture('kepler'));   # dies inside
  is(\&Rex::GPU::NVIDIA::run, $orig_run, 'Rex::GPU::NVIDIA::run is the real one again');
  is(\&Rex::Logger::info,     $orig_log, 'Rex::Logger::info is the real one again');
};

subtest 'an unmocked Rex call is trapped, not executed' => sub {
  my $rec = record_host(
    host => host_profile('debian-12'),
    code => sub { Rex::Commands::Run::i_run('true') }
  );
  ok($rec->{trapped}, 'trap fired');
  like($rec->{error}, qr/unmocked Rex::Commands::Run::i_run/, 'and names the function');
};

done_testing;
