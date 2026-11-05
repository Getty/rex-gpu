#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use FindBin qw( $Bin );
use lib "$Bin/lib";

# -----------------------------------------------------------------------------
# Rex::GPU::AMD::install_rocm (karr k1), against a scripted host. ROCm is the
# optional host userspace; gpu_setup never calls it.
#
# CLAIMS:
#   * the install on Ubuntu 24.04 and Debian 13 emits exactly the commands in
#     t/golden/amd/<os>--rocm-10.1--gfx1151.txt: the repository key checked
#     against AMD's pinned fingerprint before apt trusts it, the repository
#     file (printf + mv), apt-get update, ONE direct `apt-get install` of the
#     extra packages and amdrocm10.1-<gfx target>, verified by `dpkg -l` and a
#     version check -- never Rex::Pkg (no `pkg:` line);
#   * the targets come from `targets =>`, from each of `gpus =>` (their
#     gfx_target) or from the KFD nodes of the running driver; duplicates
#     collapse; `present` (nothing changed beyond reads) when every package is
#     installed at the release;
#   * an older ROCm line on the host (rocm-core 7.2.4) is REFUSED: dies, the
#     transcript has no mutating command, nothing is uninstalled;
#   * these die before anything is changed and, but for the OS/arch/ROCm-line
#     checks, before any command: a missing or unknown release, gpus together
#     with targets, gpus => [], a GPU without a gfx_target, a target AMD ships
#     no package for (gfx906), no target at all, an unknown option; and, after
#     only read-only commands: a non-apt OS (RHEL), an unsupported OS, a
#     foreign repository file, a non-amd64 host;
#   * Proxmox VE (k88; Debian 13 + pve-firmware on disk, kernel 7.0.14-20-pve)
#     is NOT refused: install_rocm runs the same commands as on plain Debian
#     13 (golden amd/debian-13--rocm-10.1--gfx1151--proxmox), installs only
#     libatomic1 libquadmath0 amdrocm10.1-<gfx>, no firmware-* package, no
#     `pkg:` line, never asks for pve-firmware, result `installed`. This pins
#     EXISTING behavior (green against the code before k88 too);
#   * a signing key that is not the pinned one dies; a package installed at
#     another version than the release dies after the install;
#   * the dpkg state counts (k89), by maintainer decision:
#       - rocm-core in ANY state but not-installed and config-files is the old
#         line and dies before any change: held (`hold ok installed`),
#         `install ok unpacked`, `install ok half-configured`, `install
#         reinstreq half-installed`; `deinstall ok config-files` (rc) and
#         `unknown ok not-installed` do not die (the install runs);
#       - `present` needs every target package installed AND configured at the
#         release, held (`hold ok installed`) or not: only read-only commands;
#         an unpacked, half-configured or half-installed one is not present
#         (the install runs);
#       - after the install a held package (`hi` in dpkg -l) passes
#         verify_packages and the version check; a half-configured one (`iF`)
#         dies. The host answers `grep -q '^ii'` and `grep -q '^[hi]i'` as the
#         real grep would (dpkg_l), so these fail against the code before k89
#         for the rating, not for a missing mock line.
#
# NOT covered -- scripted host, hand-written output:
#   * whether stable.repo.amd.com serves those package names and versions
#     (amdrocm10.1-gfx1151 at "10.1.0-..."; the version strings are invented
#     in shape), whether the key it serves is the pinned one, whether ROCm
#     then runs on the GPU;
#   * the shell behaviour of the key pipeline, printf quoting and dpkg-query
#     format string (recorded, never evaluated);
#   * Proxmox: that apt resolves those packages on a real PVE 9.2 (the Hub
#     read `apt-get -s`: 0 Remv, no firmware-* package -- a live finding, not
#     reproduced here), that ROCm then runs on the -pve kernel; the host
#     answers (pve-firmware `install ok installed`, kernel 7.0.14-20-pve) are
#     hand-written in the shape of t/17's pve_status;
#   * RHEL: install_rocm is refused there; no rpm path exists to test.
#   * the k89 states: the dpkg-query / `dpkg -l` answers for held, unpacked,
#     half-configured and half-installed packages are hand-written in dpkg's
#     documented format, not captured; the `grep` in `dpkg -l PKG | grep -q
#     '^[hi]i'` is never evaluated by a shell here (dpkg_l scripts what it
#     would answer); the cases `un`, `ri`, `hF` etc. beyond those named above
#     are not each tested; not a real dpkg on a held or interrupted host.
# -----------------------------------------------------------------------------

use Test::RexGPU::Golden qw( record_host golden_is mutating_lines );
use Test::RexGPU::AMD qw( amd_host amd_state gpu_synapse gpu_mi300x sequence dpkg_l );
use Rex::GPU::AMD;

my $STATE_CMD = Rex::GPU::AMD->state_script;
my $ROCM_KEY  = 'D0F004A0025A1145C7807FCD0701EAC4D5E02107';
my $QUERY     = qr{^dpkg-query -W -f='};

sub masked {
  my ( $rec ) = @_;
  return { %$rec, lines => [ map { $_ eq 'run: '.$STATE_CMD ? 'run: <AMD state script>' : $_ } @{ $rec->{lines} } ] };
}
sub no_pkg { my ( $rec ) = @_; return !grep { /^pkg:/ } @{ $rec->{lines} } }

sub rocm {
  my ( $host, %args ) = @_;
  my $how;
  my $rec = record_host(host => $host, code => sub { $how = Rex::GPU::AMD::install_rocm(%args) });
  return ( $rec, $how );
}

# the dpkg-query answers: nothing installed before, the packages at $version after
sub rocm_host {
  my ( $os, %o ) = @_;
  my @pkgs = @{ $o{packages} // [ 'amdrocm10.1-gfx1151' ] };
  my $after = join "\n", map { "$_ install ok installed ".( $o{version} // '10.1.0-35' ) } @pkgs;
  return amd_host($os, key => $ROCM_KEY, state => $o{state}, %{ $o{host} // {} },
    responses => [ @{ $o{responses} // [] },
      [ $QUERY => sequence([ $o{before} // '', 0 ], [ $after, 0 ]), 0 ] ]);
}

#### installs (goldens)

subtest 'install on Ubuntu 24.04 and Debian 13 (goldens)' => sub {
  for my $c ([ 'ubuntu-24.04', 'ubuntu2404' ], [ 'debian-13', 'debian13' ]) {
    my ( $os, $dir ) = @$c;
    my ( $rec, $how ) = rocm(rocm_host($os), release => '10.1', targets => [ 'gfx1151' ]);
    is($rec->{error}, undef, "$os: lives");
    is($how, 'installed', '... installed');
    ok(no_pkg($rec), '... no Rex::Pkg call');
    my ( $install ) = grep { /apt-get .* install / } @{ $rec->{lines} };
    like($install, qr/ install -y libatomic1 libquadmath0 amdrocm10\.1-gfx1151\z/, '... one direct install: the extras, then the target package');
    ok(( grep { /> \/etc\/apt\/sources\.list\.d\/amdrocm-stable\.sources\.tmp/ && /URIs: https:\/\/stable\.repo\.amd\.com\/rocm\/core\/packages\/\Q$dir\E\// } @{ $rec->{lines} }),
      "... the repository file points at the $dir directory");
    my ( $key ) = grep { /^run: mkdir .*curl -fsSL --proto =https https:\/\/stable\.repo\.amd\.com\/rocm\/gpg\/packages\.gpg / } @{ $rec->{lines} };
    ok($key, '... the key is fetched over https');
    my ( $at_key ) = grep { $rec->{lines}[$_] =~ /gpg --batch --with-colons --show-keys/ } 0 .. $#{ $rec->{lines} };
    my ( $at_install ) = grep { $rec->{lines}[$_] =~ /apt-get .* install / } 0 .. $#{ $rec->{lines} };
    ok($at_key < $at_install, '... and its fingerprint is read before anything is installed');
    golden_is(masked($rec), "amd/$os--rocm-10.1--gfx1151");
  }
};

subtest 'Proxmox VE is not refused: the Debian 13 commands, no firmware package (k88, golden)' => sub {
  my $pve = [ qr{^dpkg-query -W -f='\$\{Status\}\\n' pve-firmware 2>/dev/null$} => 'install ok installed', 0 ];
  my ( $rec, $how ) = rocm(rocm_host('debian-13', host => { kernel => '7.0.14-20-pve', responses => [ $pve ] }),
    release => '10.1', targets => [ 'gfx1151' ]);
  is($rec->{error}, undef, 'lives (no Proxmox refusal)');
  is($how, 'installed', '... installed');
  ok(no_pkg($rec), '... no Rex::Pkg call');
  ok(!$rec->{trapped}, '... no unmocked Rex function reached');
  my @install = grep { /apt-get .* install / } @{ $rec->{lines} };
  is(scalar @install, 1, '... one apt-get install');
  like($install[0], qr/ install -y libatomic1 libquadmath0 amdrocm10\.1-gfx1151\z/, '... exactly the extras and the target package');
  ok(!( grep { /firmware-/ } @{ $rec->{lines} } ), '... no firmware-* package anywhere in the transcript');
  ok(!( grep { /pve-firmware/ } @{ $rec->{lines} } ), '... pve-firmware is not even asked');
  # the Debian 13 transcript with the Proxmox answers is the plain one, byte for byte
  my ( $plain ) = rocm(rocm_host('debian-13'), release => '10.1', targets => [ 'gfx1151' ]);
  is_deeply($rec->{lines}, $plain->{lines}, '... identical to plain Debian 13');
  golden_is(masked($rec), 'amd/debian-13--rocm-10.1--gfx1151--proxmox');
};

subtest 'targets from gpus, from the running driver, deduplicated' => sub {
  my $os = 'ubuntu-24.04';
  my ( $rec, $how ) = rocm(rocm_host($os), release => '10.1', gpus => [ gpu_synapse() ]);
  is($how, 'installed', 'gpus => [gfx1151 GPU]');
  like(( grep { /apt-get .* install / } @{ $rec->{lines} } )[0], qr/amdrocm10\.1-gfx1151\z/, '... its package');

  ( $rec, $how ) = rocm(rocm_host($os, packages => [ 'amdrocm10.1-gfx942', 'amdrocm10.1-gfx1151' ]),
    release => '10.1', gpus => [ gpu_mi300x(), gpu_synapse(), gpu_mi300x() ]);
  is($how, 'installed', 'two GPUs, one repeated');
  like(( grep { /apt-get .* install / } @{ $rec->{lines} } )[0], qr/ install -y libatomic1 libquadmath0 amdrocm10\.1-gfx942 amdrocm10\.1-gfx1151\z/,
    '... each package once, in the order given');

  ( $rec, $how ) = rocm(rocm_host($os, state => amd_state(gpus => [
      { slot => '0000:95:00.0', class => '0380', device_id => '1586', kfd => 110501 } ])),
    release => '10.1');
  is($how, 'installed', 'neither: the KFD nodes of the running driver');
  ok(( grep { $_ eq 'run: '.$STATE_CMD } @{ $rec->{lines} } ), '... via the state read');
  like(( grep { /apt-get .* install / } @{ $rec->{lines} } )[0], qr/amdrocm10\.1-gfx1151\z/, '... gfx1151 from node 110501');

  ( $rec, $how ) = rocm(rocm_host($os), release => '10.1', targets => [ 'GFX1151', 'gfx1151' ]);
  like(( grep { /apt-get .* install / } @{ $rec->{lines} } )[0], qr/ amdrocm10\.1-gfx1151\z/, 'targets are lower-cased and deduplicated');
};

subtest 'present: every package at the release, nothing changed' => sub {
  my $host = amd_host('ubuntu-24.04', responses => [
    [ $QUERY => 'amdrocm10.1-gfx1151 install ok installed 10.1.0-35', 0 ] ]);
  my ( $rec, $how ) = rocm($host, release => '10.1', targets => [ 'gfx1151' ]);
  is($rec->{error}, undef, 'lives');
  is($how, 'present', 'present');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], 'only read-only commands ran');
  ok(!( grep { /apt-get|curl|\.sources/ } @{ $rec->{lines} } ), '... no apt-get, no download, no repository file');

  # one package at the release, one not: that is not present
  $host = amd_host('ubuntu-24.04', key => $ROCM_KEY, responses => [
    [ $QUERY => sequence(
        [ 'amdrocm10.1-gfx942 install ok installed 10.1.0-35', 0 ],
        [ "amdrocm10.1-gfx942 install ok installed 10.1.0-35\namdrocm10.1-gfx1151 install ok installed 10.1.0-35", 0 ]), 0 ] ]);
  ( $rec, $how ) = rocm($host, release => '10.1', targets => [ 'gfx942', 'gfx1151' ]);
  is($how, 'installed', 'one of two packages missing: installed');
};

subtest 'present: held target packages count as installed (k89)' => sub {
  my $host = amd_host('ubuntu-24.04', responses => [
    [ $QUERY => 'amdrocm10.1-gfx1151 hold ok installed 10.1.0-35', 0 ] ]);
  my ( $rec, $how ) = rocm($host, release => '10.1', targets => [ 'gfx1151' ]);
  is($rec->{error}, undef, 'lives');
  is($how, 'present', 'a held package at the release: present');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... only read-only commands ran');
  ok(!( grep { /apt-get|curl|\.sources/ } @{ $rec->{lines} } ), '... no apt-get, no download, no repository file');

  # held and not held, both at the release
  $host = amd_host('ubuntu-24.04', responses => [
    [ $QUERY => "amdrocm10.1-gfx942 install ok installed 10.1.0-35\namdrocm10.1-gfx1151 hold ok installed 10.1.0-35", 0 ] ]);
  ( $rec, $how ) = rocm($host, release => '10.1', targets => [ 'gfx942', 'gfx1151' ]);
  is($how, 'present', 'one held, one not: present');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... only read-only commands ran');

  # held, but at another release: not present
  $host = rocm_host('ubuntu-24.04', before => 'amdrocm10.1-gfx1151 hold ok installed 9.0.0-1');
  ( $rec, $how ) = rocm($host, release => '10.1', targets => [ 'gfx1151' ]);
  is($how, 'installed', 'held at another version: not present, installed');
};

subtest 'present: a half-installed target package is not present (k89)' => sub {
  for my $c ([ 'install ok unpacked', 'unpacked' ], [ 'install ok half-configured', 'half-configured' ],
             [ 'install reinstreq half-installed', 'half-installed' ], [ 'hold ok half-configured', 'held half-configured' ]) {
    my ( $status, $label ) = @$c;
    my ( $rec, $how ) = rocm(rocm_host('ubuntu-24.04', before => "amdrocm10.1-gfx1151 $status 10.1.0-35"),
      release => '10.1', targets => [ 'gfx1151' ]);
    is($rec->{error}, undef, "$label: lives");
    is($how, 'installed', '... not present: the install runs');
    ok(( grep { /apt-get .* install -y .*amdrocm10\.1-gfx1151\z/ } @{ $rec->{lines} } ), '... with apt-get install of the target');
  }

  # one held, one half-configured: not present
  my ( $rec, $how ) = rocm(rocm_host('ubuntu-24.04', packages => [ 'amdrocm10.1-gfx942', 'amdrocm10.1-gfx1151' ],
      before => "amdrocm10.1-gfx942 hold ok installed 10.1.0-35\namdrocm10.1-gfx1151 install ok half-configured 10.1.0-35"),
    release => '10.1', targets => [ 'gfx942', 'gfx1151' ]);
  is($how, 'installed', 'one held, one half-configured: not present');
};

subtest 'after the install: a held package passes verify, a half-configured one dies (k89)' => sub {
  # held before and after the install: dpkg -l says hi
  my ( $rec, $how ) = rocm(rocm_host('ubuntu-24.04', responses => [
      dpkg_l('amdrocm10.1-gfx1151' => 'hi'),
      [ $QUERY => sequence([ '', 0 ], [ 'amdrocm10.1-gfx1151 hold ok installed 10.1.0-35', 0 ]), 0 ] ]),
    release => '10.1', targets => [ 'gfx1151' ]);
  is($rec->{error}, undef, 'a held target package after the install: lives');
  is($how, 'installed', '... installed');
  ok(no_pkg($rec), '... verified by dpkg, not Rex::Pkg');
  ok(( grep { m{^run: dpkg -l amdrocm10\.1-gfx1151 2>/dev/null \| grep -q '\^\[hi\]i'$} } @{ $rec->{lines} } ), '... via the held-aware check');

  # a plain ii package still passes
  ( $rec, $how ) = rocm(rocm_host('ubuntu-24.04', responses => [ dpkg_l('amdrocm10.1-gfx1151' => 'ii') ]),
    release => '10.1', targets => [ 'gfx1151' ]);
  is($rec->{error}, undef, 'ii: lives');

  # half-configured (iF) after the install: both checks say no
  for my $state (qw( iF hF iU )) {
    ( $rec ) = rocm(rocm_host('ubuntu-24.04', responses => [ dpkg_l('amdrocm10.1-gfx1151' => $state) ]),
      release => '10.1', targets => [ 'gfx1151' ]);
    like($rec->{error}, qr/\Aamdrocm10\.1-gfx1151 not installed after apt-get install/, "$state: dies, naming the package");
  }

  # an extra package (libatomic1) held is fine too
  ( $rec ) = rocm(rocm_host('ubuntu-24.04', responses => [ dpkg_l('libatomic1' => 'hi') ]),
    release => '10.1', targets => [ 'gfx1151' ]);
  is($rec->{error}, undef, 'a held extra package: lives');
};

#### refusals

subtest 'an older ROCm line (rocm-core 7.2.4) is refused; nothing is changed (golden)' => sub {
  my $host = amd_host('ubuntu-24.04', responses => [
    [ $QUERY => "rocm-core install ok installed 7.2.4.70204-1\namdrocm10.1-gfx1151 install ok installed 10.1.0-35", 0 ] ]);
  my ( $rec, $how ) = rocm($host, release => '10.1', targets => [ 'gfx1151' ]);
  like($rec->{error}, qr/\Ainstall_rocm: ROCm 7\.2\.4\.70204-1 \(rocm-core\) is installed; AMD requires removing ROCm 7\.2\.4 or older before installing ROCm 10\.1, and install_rocm does not uninstall\. Nothing was changed on the host\n?\z/,
    'dies, naming the installed version');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], 'no command that changes the host');
  ok(!( grep { /remove|purge|apt-get/ } @{ $rec->{lines} } ), '... nothing removed, no apt-get at all');
  golden_is(masked($rec), 'amd/ubuntu-24.04--rocm-10.1--old-rocm-core');
};

subtest 'rocm-core in any dpkg state but not-installed / config-files is the old line: refused (k89)' => sub {
  my $VER = '7.2.4.70204-1';
  for my $c ([ 'hold ok installed', 'installed', 'held' ], [ 'install ok unpacked', 'unpacked', 'unpacked' ],
             [ 'install ok half-configured', 'half-configured', 'half-configured' ],
             [ 'install reinstreq half-installed', 'half-installed', 'half-installed' ],
             [ 'hold ok half-configured', 'half-configured', 'held and half-configured' ]) {
    my ( $status, $state, $label ) = @$c;
    my $host = amd_host('ubuntu-24.04', responses => [
      [ $QUERY => "rocm-core $status $VER\namdrocm10.1-gfx1151 install ok installed 10.1.0-35", 0 ] ]);
    my ( $rec, $how ) = rocm($host, release => '10.1', targets => [ 'gfx1151' ]);
    like($rec->{error}, qr/\Ainstall_rocm: ROCm \Q$VER\E \(rocm-core\) is \Q$state\E; AMD requires removing ROCm 7\.2\.4 or older before installing ROCm 10\.1, and install_rocm does not uninstall\. Nothing was changed on the host\n?\z/,
      "$label: dies, naming version and state");
    is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... no command that changes the host');
    ok(!( grep { /remove|purge|apt-get/ } @{ $rec->{lines} } ), '... nothing removed, no apt-get at all');
  }

  # dies before the present check, whatever the target packages say
  my $host = amd_host('ubuntu-24.04', responses => [
    [ $QUERY => "rocm-core hold ok installed $VER", 0 ] ]);
  my ( $rec ) = rocm($host, release => '10.1', targets => [ 'gfx1151' ]);
  like($rec->{error}, qr/\(rocm-core\) is installed; AMD requires removing/, 'held rocm-core with no target package: dies');

  # rc (config files left) and never-installed are not the old line: the install runs
  for my $c ([ 'deinstall ok config-files', 'config-files, rc' ], [ 'unknown ok not-installed', 'not-installed' ]) {
    my ( $status, $label ) = @$c;
    my ( $rec2, $how ) = rocm(rocm_host('ubuntu-24.04', before => "rocm-core $status $VER"),
      release => '10.1', targets => [ 'gfx1151' ]);
    is($rec2->{error}, undef, "$label: lives");
    is($how, 'installed', '... the install runs');
  }
  my ( $rec3, $how3 ) = rocm(rocm_host('ubuntu-24.04', before => "rocm-core unknown ok not-installed "),
    release => '10.1', targets => [ 'gfx1151' ]);
  is($how3, 'installed', 'not-installed with an empty version column (dpkg-query for a known-but-removed name): installed');
};

subtest 'arguments that die before any command' => sub {
  my @case = (
    [ 'no release',          [ targets => [ 'gfx1151' ] ],
      qr/\Ainstall_rocm: release => '\.\.\.' is required \(known: 10\.1\)\. Nothing was changed on the host\n?\z/ ],
    [ 'unknown release',     [ release => '9.9', targets => [ 'gfx1151' ] ],
      qr/\Ainstall_rocm: unknown ROCm release '9\.9' \(known: 10\.1\)\. Nothing was changed on the host\n?\z/ ],
    [ 'the old line is no release', [ release => '7.2.4', targets => [ 'gfx1151' ] ], qr/unknown ROCm release '7\.2\.4'/ ],
    [ 'unknown option',      [ release => '10.1', speed => 1 ],
      qr/\Ainstall_rocm: unknown option speed \(known: release, gpus, targets\)/ ],
    [ 'gpus and targets',    [ release => '10.1', gpus => [ gpu_synapse() ], targets => [ 'gfx1151' ] ],
      qr/pass gpus or targets, not both/ ],
    [ 'gpus => []',          [ release => '10.1', gpus => [] ],
      qr/\Ainstall_rocm: gpus is empty; omit gpus for every AMD GPU of the host\. Nothing was changed on the host\n?\z/ ],
    [ 'targets not an array', [ release => '10.1', targets => 'gfx1151' ], qr/targets must be an arrayref of gfx target names/ ],
    [ 'a GPU without a gfx_target', [ release => '10.1', gpus => [ { name => 'AMD GPU [1002:1902]', device_id => '1902', gfx_target => undef } ] ],
      qr/AMD GPU 0000:\?\?|AMD GPU \[1002:1902\] has no gfx_target; pass targets => \[\.\.\.\]/ ],
    [ 'a target AMD ships no package for', [ release => '10.1', targets => [ 'gfx906' ] ],
      qr/ROCm 10\.1 has no package for gfx906 \(it ships: gfx908 gfx90a gfx942 gfx950 / ],
    [ 'targets => []',       [ release => '10.1', targets => [] ], qr/no gfx target/ ],
  );
  for my $c (@case) {
    my ( $label, $args, $re ) = @$c;
    my ( $rec ) = rocm(amd_host('ubuntu-24.04'), @$args);
    like($rec->{error}, $re, "$label: dies");
    like($rec->{error}, qr/Nothing was changed on the host/, '... "Nothing was changed"');
    is_deeply($rec->{lines}, [], '... before any command');
  }
};

subtest 'no gfx target anywhere: dies after the one state read' => sub {
  my ( $rec ) = rocm(amd_host('ubuntu-24.04', state => amd_state(amdgpu => 0, kfd => 0, gpus => [])), release => '10.1');
  like($rec->{error}, qr/\Ainstall_rocm: no gfx target -- no AMD GPU with a running driver \(KFD\) found; pass targets => \[\.\.\.\]\. Nothing was changed on the host/,
    'dies');
  is_deeply($rec->{lines}, [ 'run: '.$STATE_CMD ], '... after the one read');
};

subtest 'OS, architecture, repository file: die after read-only commands only' => sub {
  my @case = (
    [ 'RHEL (apt hosts only)', amd_host('rhel-9'), qr/\Ainstall_rocm: supported on apt hosts only \(Ubuntu 22\.04, 24\.04, 26\.04; Debian 12, 13\), not Red Hat Enterprise Linux 9\.6 \(Plow\)\. Nothing was changed/ ],
    [ 'Fedora', amd_host('ubuntu-24.04', responses => [ [ 'cat /etc/os-release 2>/dev/null' => qq{NAME="Fedora Linux"\nID=fedora\nVERSION_ID="42"}, 0 ] ]),
      qr/Unsupported OS for the AMD driver: fedora/ ],
    [ 'arm64', amd_host('ubuntu-24.04', arch => 'arm64'), qr/ROCm 10\.1 is built for amd64 only; this host is arm64\. Nothing was changed/ ],
    [ 'a foreign repository file', amd_host('ubuntu-24.04', responses => [
        [ 'cat /etc/apt/sources.list.d/amdrocm-stable.sources 2>/dev/null' => "Types: deb\nURIs: https://mirror.example.com/rocm/\n", 0 ] ]),
      qr{/etc/apt/sources\.list\.d/amdrocm-stable\.sources exists with other content than ROCm 10\.1 needs; install_rocm does not replace a repository it did not write\. Nothing was changed} ],
  );
  for my $c (@case) {
    my ( $label, $host, $re ) = @$c;
    my ( $rec ) = rocm($host, release => '10.1', targets => [ 'gfx1151' ]);
    like($rec->{error}, $re, "$label: dies");
    is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... no command that changes the host');
    ok(!$rec->{trapped}, '... no unmocked Rex function');
  }
};

subtest 'unsupported release of an apt OS: no ROCm repository' => sub {
  my ( $rec ) = rocm(amd_host('ubuntu-24.04', responses => [
      [ 'cat /etc/os-release 2>/dev/null' => qq{NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="20.04"\nPRETTY_NAME="Ubuntu 20.04.6 LTS"}, 0 ] ]),
    release => '10.1', targets => [ 'gfx1151' ]);
  like($rec->{error}, qr/\Ainstall_rocm: AMD has no ROCm 10\.1 repository for Ubuntu 20\.04\.6 LTS\. Nothing was changed/, 'Ubuntu 20.04: dies');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... no command that changes the host');
};

#### dies after a change

subtest 'a signing key that is not the pinned one: dies, nothing installed' => sub {
  my ( $rec ) = rocm(rocm_host('ubuntu-24.04', host => { key => 'DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF' }),
    release => '10.1', targets => [ 'gfx1151' ]);
  like($rec->{error}, qr/The key from https:\/\/stable\.repo\.amd\.com\/rocm\/gpg\/packages\.gpg is not the AMD signing key expected \(fingerprint \Q$ROCM_KEY\E; got DEADBEEF/, 'dies');
  ok(!( grep { /apt-get .* install |> \/etc\/apt\/sources\.list\.d\/amdrocm-stable/ } @{ $rec->{lines} } ), 'no install, no repository file');
};

subtest 'a package installed at another version than the release: dies after the install' => sub {
  my ( $rec ) = rocm(rocm_host('ubuntu-24.04', version => '7.9.0-1'), release => '10.1', targets => [ 'gfx1151' ]);
  like($rec->{error}, qr/\Ainstall_rocm: amdrocm10\.1-gfx1151 is installed at 7\.9\.0-1, not ROCm 10\.1\n?\z/, 'dies naming both');

  ( $rec ) = rocm(rocm_host('ubuntu-24.04', responses => [ [ qr{^dpkg -l amdrocm10\.1-gfx1151 2>/dev/null \| grep -q '\^\[hi\]i'$} => '', 1 ] ]),
    release => '10.1', targets => [ 'gfx1151' ]);
  like($rec->{error}, qr/\Aamdrocm10\.1-gfx1151 not installed after apt-get install/, 'a package dpkg does not show as installed: dies');
  ok(no_pkg($rec), '... verified by dpkg, not Rex::Pkg');
};

done_testing;
