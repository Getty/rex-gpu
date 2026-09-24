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
# HEAD 3cba655; re-recorded on purpose for karr #37/#38/#42 and the toolkit
# half of #27 (apt timers + lock timeout for curl/gnupg, keyring replaced via
# a temp file, already-present skip, rpm -q on openSUSE).
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

# karr #44: the .repo download fails (HTTP error: curl -f exits 22) or the
# file has no [nvidia-container-toolkit] section (e.g. a captive portal page
# served with 200): dies before dnf, the temp file removed, the .repo left.
golden_is(
  toolkit_on(host_profile('rocky-9', responses => [
    [ qr{^curl -fsSL https://nvidia\.github\.io/libnvidia-container/stable/rpm/nvidia-container-toolkit\.repo } => 'curl: (22) The requested URL returned error: 404', 22 ]
  ])),
  'toolkit/rocky-9--repo-download-failed'
);
golden_is(
  toolkit_on(host_profile('rocky-9', responses => [
    [ qr{^grep -q '\^\\\[nvidia-container-toolkit\\\]' } => '', 1 ]
  ])),
  'toolkit/rocky-9--repo-without-section'
);
for my $os (qw( rocky-9 rhel-9 rocky-9-lsb alma-9-lsb )) {
  my @lines = @{ toolkit_on(host_profile($os))->{lines} };
  is((grep { /curl / && !/curl -fsSL / } @lines), 0, $os.': the .repo is fetched with curl -f');
  is((grep { /\| tee / } @lines), 0, $os.': nothing is piped into /etc/yum.repos.d');
}

# openSUSE (karr #27): a failed zypper install dies on rpm -q, as on RHEL.
golden_is(
  toolkit_on(host_profile('leap-15.6', responses => [
    [ 'zypper install -y nvidia-container-toolkit' => 'No provider of nvidia-container-toolkit found.', 104 ],
    [ 'rpm -q nvidia-container-toolkit 2>&1' => 'package nvidia-container-toolkit is not installed', 1 ]
  ])),
  'toolkit/leap-15.6--install-failed'
);

# ... and zypper's exit code is not the evidence: a non-zero exit with the
# package installed (the harness's rpm -q default) passes.
{
  my $rec = toolkit_on(host_profile('leap-15.6', responses => [
    [ 'zypper install -y nvidia-container-toolkit' => '', 107 ]
  ]));
  is($rec->{error}, undef, 'leap-15.6: zypper exits 107, rpm -q finds the package => no die');
}

# karr #42: toolkit already present -- nvidia-ctk runs AND the package manager
# has the package (a re-run, or a DGX OS image). Nothing but read-only probes.
my $CTK_VERSION = "NVIDIA Container Toolkit CLI version 1.17.8\ncommit: f202b80a9b9d0db00d9b1d73c0128c8962c55f4d";
for my $os (qw( debian-12 ubuntu-24.04 rocky-9 leap-16.0 )) {
  my $rec = toolkit_on(host_profile($os,
    can_run   => { 'nvidia-ctk' => 1 },
    responses => [ [ 'nvidia-ctk --version 2>&1' => $CTK_VERSION, 0 ] ]
  ));
  golden_is($rec, "toolkit/$os--already-present");
  is_deeply([ Test::RexGPU::Golden::mutating_lines(@{ $rec->{lines} }) ], [],
    $os.': already-present toolkit => nothing on the host is changed');
  ok((grep { $_->[1] =~ /already present .*skipping/ } @{ $rec->{logs} }),
    $os.': the skip is logged');
}

# nvidia-ctk on PATH but not from the package manager (e.g. copied in by hand):
# the package is installed as on a fresh host.
golden_is(
  toolkit_on(host_profile('debian-12',
    can_run   => { 'nvidia-ctk' => 1 },
    responses => [
      [ 'nvidia-ctk --version 2>&1' => $CTK_VERSION, 0 ],
      [ q{dpkg -l nvidia-container-toolkit 2>/dev/null | grep -q '^[hi]i'} => '', 1 ]
    ]
  )),
  'toolkit/debian-12--ctk-without-package'
);
golden_is(
  toolkit_on(host_profile('rocky-9',
    can_run   => { 'nvidia-ctk' => 1 },
    responses => [
      [ 'nvidia-ctk --version 2>&1' => $CTK_VERSION, 0 ],
      [ 'rpm -q nvidia-container-toolkit 2>&1' => 'package nvidia-container-toolkit is not installed', 1 ]
    ]
  )),
  'toolkit/rocky-9--ctk-without-package'
);

# nvidia-ctk on PATH but broken (exit non-zero): not present, full install.
golden_is(
  toolkit_on(host_profile('ubuntu-24.04',
    can_run   => { 'nvidia-ctk' => 1 },
    responses => [ [ 'nvidia-ctk --version 2>&1' => 'error while loading shared libraries', 127 ] ]
  )),
  'toolkit/ubuntu-24.04--ctk-broken'
);

# karr #38: a re-run where the first run left the keyring behind but no
# toolkit (install failed). The transcript is the fresh-host one byte for byte:
# nothing probes the old keyring, gpg --batch --yes overwrites the temp file,
# mv -f replaces the keyring, so a rotated key is picked up.
{
  my $fresh = toolkit_on(host_profile('debian-12'));
  my $rerun = toolkit_on(host_profile('debian-12', responses => [
    [ 'test -s /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg' => '', 0 ]
  ]));
  is_deeply($rerun->{lines}, $fresh->{lines}, 'debian-12 re-run with keyring present: same commands as a fresh host');
  ok((grep { /gpg --batch --yes --dearmor -o \S+\.tmp / } @{ $fresh->{lines} }),
    'keyring is dearmored with --yes into a temp file');
}

# karr #38: every keyring failure dies instead of being swallowed.
golden_is(
  toolkit_on(host_profile('debian-12', responses => [
    [ qr{^curl -fsSL https://nvidia\.github\.io/libnvidia-container/gpgkey -o } => 'curl: (22) The requested URL returned error: 404', 22 ]
  ])),
  'toolkit/debian-12--key-download-failed'
);
golden_is(
  toolkit_on(host_profile('debian-12', responses => [
    [ qr{^gpg --batch --yes --dearmor } => 'gpg: no valid OpenPGP data found.', 2 ]
  ])),
  'toolkit/debian-12--key-dearmor-failed'
);
golden_is(
  toolkit_on(host_profile('debian-12', responses => [
    [ 'test -s /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg' => '', 1 ]
  ])),
  'toolkit/debian-12--keyring-empty'
);

# karr #37: curl/gnupg go through apt-get with the lock timeout, after the apt
# timers are stopped, never through Rex::Pkg -- on every apt host.
for my $os (qw( debian-12 debian-13 ubuntu-22.04 ubuntu-24.04 )) {
  my @lines = @{ toolkit_on(host_profile($os))->{lines} };
  is((grep { /^pkg: / } @lines), 0, $os.': no Rex::Pkg call');
  my ($stop) = grep { $lines[$_] =~ /systemctl stop unattended-upgrades apt-daily/ } 0..$#lines;
  my ($first_apt) = grep { $lines[$_] =~ /apt-get / } 0..$#lines;
  ok(defined $stop && defined $first_apt && $stop < $first_apt, $os.': apt timers stopped before the first apt-get');
  is((grep { /apt-get / && !/DPkg::Lock::Timeout=120/ } @lines), 0, $os.': every apt-get has the lock timeout');
}

# curl/gnupg could not be installed (e.g. lock never released): dies on dpkg.
golden_is(
  toolkit_on(host_profile('ubuntu-24.04', responses => [
    [ q{dpkg -l gnupg 2>/dev/null | grep -q '^ii'} => '', 1 ]
  ])),
  'toolkit/ubuntu-24.04--helpers-not-installed'
);

done_testing;
