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
# Several GPUs (karr #33): install_driver(gpus => [...]) must emit exactly
# what the most constrained GPU gets alone, and a V100 next to a B200 or a K80
# anywhere must die after the probe only. Every "no driver source fits" case
# must die with only read-only probes before it.
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
  for my $name (qw( ada blackwell volta kepler b200 b300 )) {
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
# host change. Since karr #33 the message is the no-source-fits one, listing
# each candidate; the CUDA-repo reason still names the supported releases.
{
  my $rec = driver_on(host_profile('debian-12', release => '11.11'), gpu_fixture('blackwell'));
  like($rec->{error}, qr/NVIDIA's CUDA repo only covers Debian 12 and 13/,
    'debian-11 + RTX 5090 dies naming the supported releases');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [],
    'debian-11 + RTX 5090: only read-only probes before the die');
  golden_is($rec, 'driver/debian-11--blackwell');
}

#### Several GPUs on one host (karr #33)
#
# install_driver(gpus => [...]) chooses for the intersection of all GPUs'
# requirements. A mixed host gets exactly what its most constrained GPU gets
# alone -- same transcript, command for command -- and GPUs that cannot share
# a driver die after the nvidia-smi probe, before anything else.

sub driver_for {
  my ( $host, @names ) = @_;
  return record_host(
    host => $host,
    code => sub { Rex::GPU::NVIDIA::install_driver(gpus => [ map { gpu_fixture($_) } @names ]) }
  );
}

for my $os (host_names()) {
  my %single = map { $_ => driver_on(host_profile($os), gpu_fixture($_)) } qw( ada blackwell volta );
  for my $case ([ [qw( ada ada )], 'ada' ], [ [qw( ada blackwell )], 'blackwell' ],
                [ [qw( blackwell ada )], 'blackwell' ], [ [qw( ada volta )], 'volta' ]) {
    my ( $pair, $as ) = @$case;
    my $rec = driver_for(host_profile($os), @$pair);
    is($rec->{error}, $single{$as}{error}, "$os + ".join('+', @$pair).": dies/lives like $as alone");
    is_deeply($rec->{lines}, $single{$as}{lines}, "$os + ".join('+', @$pair).": same commands as $as alone");
  }

  my $rec = driver_for(host_profile($os), qw( volta b200 ));
  like($rec->{error}, qr/^No single NVIDIA driver supports all GPUs on this host: GB100 \[B200\] \(Blackwell, 10de:2901\) needs the open kernel module, but GV100GL \[Tesla V100 PCIe 16GB\] \(Maxwell\/Pascal\/Volta, 10de:1db4\) needs the proprietary one\. Nothing was changed on the host/,
    "$os + V100+B200 dies naming both GPUs");
  is_deeply($rec->{lines}, [ 'run: nvidia-smi -L 2>&1' ], "$os + V100+B200: only the nvidia-smi probe ran");

  $rec = driver_for(host_profile($os), qw( ada kepler ));
  like($rec->{error}, qr/GK210GL \[Tesla K80\].*Kepler or older.*Nothing was changed on the host/,
    "$os + Ada+K80: a Kepler anywhere in the list is rejected");
  is_deeply($rec->{lines}, [ 'run: nvidia-smi -L 2>&1' ], "$os + Ada+K80: only the nvidia-smi probe ran");
}

golden_is(driver_for(host_profile('ubuntu-24.04'), qw( ada blackwell )),
  'driver/ubuntu-24.04--ada+blackwell');
golden_is(driver_for(host_profile('ubuntu-24.04'), qw( ada volta )),
  'driver/ubuntu-24.04--ada+volta');
golden_is(driver_for(host_profile('ubuntu-24.04'), qw( volta b200 )),
  'driver/ubuntu-24.04--volta+b200');

# gpu => stays an alias of a one-element gpus =>; both at once die untouched
is_deeply(driver_for(host_profile('debian-12'), 'ada')->{lines},
  driver_on(host_profile('debian-12'), gpu_fixture('ada'))->{lines}, 'gpus => [ada] is gpu => ada');
is_deeply(driver_for(host_profile('debian-12'))->{lines},
  driver_on(host_profile('debian-12'), undef)->{lines}, 'gpus => [] is no GPU');
{
  my $rec = record_host(host => host_profile('debian-12'), code => sub {
    Rex::GPU::NVIDIA::install_driver(gpu => gpu_fixture('ada'), gpus => [ gpu_fixture('ada') ]) });
  like($rec->{error}, qr/^install_driver: pass gpu or gpus, not both$/, 'gpu and gpus together die');
  is_deeply($rec->{lines}, [], '... before any host interaction');
}

#### No source fits: dies before any host change, listing every candidate

{
  # Debian without a CUDA repo, Blackwell and V100 (non-free branch unknown)
  my $rec = driver_on(host_profile('debian-13', release => '14.0'), gpu_fixture('blackwell'));
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], 'debian-14 + RTX 5090: only read-only probes');
  golden_is($rec, 'driver/debian-14--blackwell');

  $rec = driver_on(host_profile('debian-13', release => '14.0'), gpu_fixture('volta'));
  like($rec->{error}, qr/debian-nonfree: driver branch not known, 580 or older is needed/,
    'debian-14 + V100: non-free has no known branch there');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... only read-only probes');
  golden_is($rec, 'driver/debian-14--volta');

  # Ubuntu, B300 (580 or newer), apt-cache search empty: the 570 fallback of
  # -server-open is resolved and rejected, the pinned 580 is proprietary.
  $rec = driver_on(host_profile('ubuntu-24.04', responses => [
    [ qr{^apt-cache search } => '', 0 ]
  ]), gpu_fixture('b300'));
  like($rec->{error}, qr/ubuntu-server-open: branch 570 is older than 580/,
    'ubuntu-24.04 + B300, empty search: the resolved fallback is rejected');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... only read-only probes');
  golden_is($rec, 'driver/ubuntu-24.04--b300--empty-search');
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
