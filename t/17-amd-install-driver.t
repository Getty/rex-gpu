#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# sleep() is a builtin: only a CORE::GLOBAL override installed before
# Rex::GPU::AMD is compiled reaches the `sleep 20` / `sleep 5` in
# reboot_and_wait (same trick as t/41-reboot.t).
our @SLEPT;
BEGIN { *CORE::GLOBAL::sleep = sub (;$) { push @SLEPT, $_[0]; return $_[0] // 0 } }

use FindBin qw( $Bin );
use lib "$Bin/lib";

# -----------------------------------------------------------------------------
# Rex::GPU::AMD::install_driver: the install paths and the dies (karr k1),
# against a scripted host, as goldens under t/golden/amd/.
#
# CLAIMS:
#   * the install emits, per OS, exactly the commands in t/golden/amd/<name>.txt:
#       dkms   Ubuntu 22.04 / 24.04 / 26.04, Debian 12 / 13, RHEL 9, Rocky 10
#              (headers of the RUNNING kernel only, the pinned repo.radeon.com
#              key checked before apt/dnf trusts it, the repository file
#              written with printf + mv, amdgpu-dkms, then the module and
#              `dkms status` checked), where a package without a candidate
#              (linux-modules-extra on kernel 7.0) is left out;
#       inbox  Ubuntu 24.04: the firmware package alone for an APU whose
#              kernel has amdgpu.ko; linux-modules-extra when the kernel has
#              none; Debian 12 / 13 with the release's own kernel: the
#              pve-firmware read first, then firmware-amd-graphics (k81);
#   * the driver packages are installed with a direct `apt-get install` /
#     `dnf install` and verified by `dpkg -l` / `rpm -q` -- never through
#     Rex::Pkg (no `pkg:` line in any transcript, asserted for all of them);
#   * after the install `modprobe amdgpu` and a second state read decide:
#     usable -> the method is returned, no reboot even with reboot => 1; not
#     usable -> reboot => 0 warns and returns, reboot => 1 runs the reboot path
#     (boot_id, ONE shutdown -r, reconnect probe, state read) and dies if the
#     driver is still unusable; an amdgpu that was already loaded is never
#     modprobed;
#   * these die BEFORE any change (no mutating command, golden or assertion):
#     Secure Boot on (dkms), non-amd64, an existing repo file with other
#     content, an unsupported kernel (dkms; an APU on 24.04 kernel 6.8; an APU
#     on Debian), `nomodeset` on the kernel command line, an amdgpu blacklist,
#     a GPU bound to vfio-pci, an unsupported OS; and on Debian (k81): inbox
#     on Debian 11 or testing/sid, inbox on a kernel that is not the release's
#     own (a -pve one), and -- for inbox AND dkms, whatever kernel -- a host
#     with pve-firmware on disk (Proxmox VE): `hold ok installed`, `install ok
#     unpacked` and `install reinstreq half-installed` count, `deinstall ok
#     config-files` (rc) does not; the Proxmox message wins over the kernel
#     message; none of these runs apt-get or `systemctl stop`;
#   * a working driver is answered with `present` before any Debian check: a
#     Proxmox host with a working amdgpu gets only the state read (no
#     pve-firmware query, no change);
#   * these die with the first change already made but no driver installed:
#     a key that is not the pinned one (a key directory is made and removed),
#     a required package without a candidate (after apt-get update), and these
#     die AFTER the install: a package not installed afterwards (a half-built
#     DKMS), dkms status without the module for the running kernel.
#
# NOT covered -- scripted host, hand-written output (see Test::RexGPU::AMD for
# the real host each canned answer imitates and the strings that are guesses):
#   * whether amdgpu-dkms 31.60 builds on the kernel, whether the packages and
#     the repository exist at those names today, whether the key AMD serves is
#     the pinned one, whether apt/dnf accept the repository file;
#   * the dpkg-query answers for pve-firmware (`install ok installed`, `hold ok
#     installed`, ...) are the documented ${Status} format, not captured on a
#     Proxmox VE host; 7.0.14-20-pve is the kernel string k81 read on a live
#     PVE 9.2, the other kernels are invented in their shape; that apt would
#     remove proxmox-ve for firmware-amd-graphics was read once by hand, not here;
#   * that Debian 12/13 hosts have firmware-amd-graphics at that name and
#     component today: the apt-cache policy answer is scripted per release
#     (debian_install; 20250410-2 for trixie is what k81 read on a live PVE
#     9.2, the bookworm version is a guess), because the base profile would
#     answer with the NVIDIA candidate of Ubuntu 24.04 (580...); what a Debian
#     host without a candidate does is not tested here (k86; the existing
#     no-candidate golden is the Ubuntu one);
#   * what the remote shell does with a command: the key download pipeline, the
#     printf quoting, the `grep -rsHE` over modprobe.d, the dearmor chain, are
#     recorded verbatim and never evaluated -- a wrong quote or flag in them
#     is invisible here;
#   * a reboot (the connection is a scripted object), Secure Boot reading of
#     a real efivars file, a real module load or KFD node. The state script is
#     masked as <AMD state script> in the goldens (detect/debian-12--amd-only
#     holds it in full); the sequence of canned states encodes WHEN the host
#     becomes usable, which is the guess the test makes, not an observation.
# -----------------------------------------------------------------------------

use Test::RexGPU::Golden qw( record_host golden_is mutating_lines );
use Test::RexGPU::AMD qw( amd_host amd_state gpu_synapse gpu_mi300x gpu_navi31 sequence module_path os_kernel );
use Rex::GPU::AMD;

my $STATE_CMD = Rex::GPU::AMD->state_script;

# A connection whose reconnect() dies for the first $fail_first calls.
{
  package Local::FakeConn;
  sub new { my ( $class, %a ) = @_; bless { fail_first => 0, %a, disconnects => 0, reconnects => 0 }, $class }
  sub disconnect { $_[0]{disconnects}++; return 1 }
  sub reconnect  {
    my ( $self ) = @_;
    $self->{reconnects}++;
    die "connection refused\n" if $self->{reconnects} <= $self->{fail_first};
    return 1;
  }
}

# The transcript with the (very long) state script masked; the script is
# pinned in full by t/golden/detect/debian-12--amd-only.txt.
sub masked {
  my ( $rec ) = @_;
  return { %$rec, lines => [ map { $_ eq 'run: '.$STATE_CMD ? 'run: <AMD state script>' : $_ } @{ $rec->{lines} } ] };
}

my %SLOT = (
  mi300x => { slot => '0000:c1:00.0', class => '1200', device_id => '74a1' },
  navi31 => { slot => '0000:0a:00.0', class => '0300', device_id => '744c' },
  synapse => { slot => '0000:95:00.0', class => '0380', device_id => '1586' },
);
my %KFD = ( mi300x => 90402, navi31 => 110000, synapse => 110501 );

# a fresh host: amdgpu not loaded, no /dev/kfd, the device unbound
sub fresh {
  my ( $gpu, %o ) = @_;
  return amd_state(amdgpu => 0, kfd => 0,
    gpus => [ { %{ $SLOT{$gpu} }, driver => undef, render => undef, %o } ]);
}
# the same host once the driver works
sub working {
  my ( $gpu ) = @_;
  return amd_state(gpus => [ { %{ $SLOT{$gpu} }, kfd => $KFD{$gpu}, vram => 137438953472, gtt => 33535848448 } ]);
}
# amdgpu (an older inbox one) is loaded and the GPU bound, but no KFD: a reboot is needed
sub loaded_unusable {
  my ( $gpu ) = @_;
  return amd_state(amdgpu => 1, kfd => 0, gpus => [ { %{ $SLOT{$gpu} }, render => undef } ]);
}

my %GPU = ( mi300x => \&gpu_mi300x, navi31 => \&gpu_navi31, synapse => \&gpu_synapse );

sub dkms_status {
  my ( $kernel ) = @_;
  return [ qr{^dkms status -m amdgpu -k } => sequence(
    [ '', 0 ],
    [ "amdgpu/6.16.13-2255209.24.04, $kernel, x86_64: installed", 0 ]), 0 ];
}

# install_driver on a host; returns ( $rec, $return )
sub install {
  my ( $host, %args ) = @_;
  my $conn = Local::FakeConn->new(fail_first => delete $args{fail_first} // 0);
  my $how;
  @SLEPT = ();
  my $rec = record_host(
    host => $host,
    subs => { 'Rex::get_current_connection' => sub { return { conn => $conn } } },
    code => sub { $how = Rex::GPU::AMD::install_driver(%args) },
  );
  return ( $rec, $how, $conn );
}

sub no_pkg { my ( $rec ) = @_; return !grep { /^pkg:/ } @{ $rec->{lines} } }
sub warns  { my ( $rec ) = @_; return [ map { $_->[1] } grep { $_->[0] eq 'warn' } @{ $rec->{logs} } ] }
sub shutdowns { my ( $rec ) = @_; return scalar grep { /shutdown -r/ } @{ $rec->{lines} } }

# One golden per (host, scenario). $o{host} = [ os, kernel, extra amd_host args ]
sub dkms_case {
  my ( $name, $os, $gpu, %o ) = @_;
  my $kernel = $o{kernel} // os_kernel($os);
  my $host = amd_host($os,
    kernel => $kernel, state => [ fresh($gpu), working($gpu) ], module => 'dkms',
    responses => [ @{ $o{responses} // [] }, dkms_status($kernel) ],
    %{ $o{host} // {} });
  my ( $rec, $how ) = install($host, gpus => [ $GPU{$gpu}->() ], method => 'dkms', %{ $o{args} // {} });
  return ( $rec, $how );
}

#### dkms, per OS

subtest 'dkms install, per OS (goldens)' => sub {
  my @case = (
    [ 'ubuntu-24.04--dkms--mi300x',          'ubuntu-24.04', 'mi300x' ],
    [ 'ubuntu-22.04--dkms--mi300x',          'ubuntu-22.04', 'mi300x' ],
    [ 'ubuntu-26.04--dkms--mi300x',          'ubuntu-26.04', 'mi300x' ],
    [ 'debian-12--dkms--mi300x',             'debian-12',    'mi300x' ],
    [ 'debian-13--dkms--mi300x',             'debian-13',    'mi300x' ],
    [ 'rhel-9--dkms--mi300x',                'rhel-9',       'mi300x' ],
    [ 'rocky-10--dkms--mi300x',              'rocky-10',     'mi300x' ],
  );
  for my $c (@case) {
    my ( $name, $os, $gpu ) = @$c;
    my ( $rec, $how ) = dkms_case($name, $os, $gpu);
    is($rec->{error}, undef, "$name: lives");
    is($how, 'dkms', '... returns dkms');
    ok(no_pkg($rec), '... no Rex::Pkg call (no pkg: line)');
    my ( $install ) = grep { /^run: (?:DEBIAN_FRONTEND=noninteractive apt-get .* install|dnf install) -y / } @{ $rec->{lines} };
    like($install, qr/ amdgpu-dkms\b/, '... one direct install command, amdgpu-dkms among its packages');
    golden_is(masked($rec), "amd/$name");
  }
};

subtest 'dkms: the headers are the RUNNING kernel\'s, never a metapackage' => sub {
  for my $c ([ 'ubuntu-24.04', '6.8.0-85-generic', qr/linux-headers-6\.8\.0-85-generic amdgpu-dkms/ ],
             [ 'debian-13',    '6.12.48+deb13-amd64', qr/linux-headers-6\.12\.48\+deb13-amd64 amdgpu-dkms/ ],
             [ 'rhel-9',       '5.14.0-570.12.1.el9_6.x86_64', qr/kernel-headers-5\.14\.0-570\.12\.1\.el9_6\.x86_64 kernel-devel-5\.14\.0-570\.12\.1\.el9_6\.x86_64 kernel-devel-matched-5\.14\.0-570\.12\.1\.el9_6\.x86_64 amdgpu-dkms/ ]) {
    my ( $os, $kernel, $re ) = @$c;
    my ( $rec ) = dkms_case("x", $os, 'mi300x', kernel => $kernel);
    my ( $install ) = grep { /^run: (?:DEBIAN_FRONTEND=noninteractive apt-get .* install|dnf install) -y / && /amdgpu-dkms/ } @{ $rec->{lines} };
    like($install, $re, "$os: headers (and for RHEL devel, devel-matched) of $kernel");
    unlike($install, qr/linux-headers-(?:generic|amd64)\b/, '... not a metapackage');
  }
};

subtest 'dkms on Ubuntu 24.04 with kernel 7.0: linux-modules-extra has no candidate and is left out (golden)' => sub {
  my $K = '7.0.0-42-generic';
  my ( $rec, $how ) = dkms_case('x', 'ubuntu-24.04', 'navi31', kernel => $K, responses => [
    [ "LC_ALL=C apt-cache policy linux-modules-extra-$K 2>/dev/null" =>
        "linux-modules-extra-$K:\n  Installed: (none)\n  Candidate: (none)\n  Version table:\n", 0 ] ]);
  is($rec->{error}, undef, 'lives');
  is($how, 'dkms', 'dkms');
  my ( $install ) = grep { /apt-get .* install -y .*amdgpu-dkms/ } @{ $rec->{lines} };
  like($install, qr/ install -y linux-headers-\Q$K\E amdgpu-dkms\z/, 'headers and amdgpu-dkms only');
  unlike($install, qr/modules-extra/, '... no linux-modules-extra');
  ok(no_pkg($rec), 'no pkg: line');
  golden_is(masked($rec), 'amd/ubuntu-24.04--dkms--navi31--kernel-7.0');
};

#### inbox

subtest 'inbox on Ubuntu 24.04 kernel 7.0 (the Ryzen AI Max APU): firmware only when amdgpu.ko is there (golden)' => sub {
  my $K = '7.0.0-42-generic';
  my $host = amd_host('ubuntu-24.04', kernel => $K, state => [ fresh('synapse'), working('synapse') ], module => 'inbox',
    responses => [
      # no firmware package installed yet; the first one is installed by the run
      [ qr{^dpkg -l linux-firmware-amd-graphics 2>/dev/null \| grep -q '\^ii'$} => sequence([ '', 1 ], [ '', 0 ]), 0 ],
      [ qr{^dpkg -l linux-firmware 2>/dev/null \| grep -q '\^ii'$} => '', 1 ],
    ]);
  my ( $rec, $how ) = install($host, gpus => [ gpu_synapse() ]);
  is($rec->{error}, undef, 'lives');
  is($how, 'inbox', 'auto picks inbox from the gfx1151 row');
  my ( $install ) = grep { /apt-get .* install -y / } @{ $rec->{lines} };
  like($install, qr/ install -y linux-firmware-amd-graphics\z/, 'the firmware package alone');
  ok(!( grep { /linux-modules-extra/ } @{ $rec->{lines} }), 'no linux-modules-extra anywhere (the module is in linux-modules)');
  ok(!( grep { /amdgpu-dkms|radeon\.com|amdgpu\.list/ } @{ $rec->{lines} }), 'no DKMS, no AMD repository, no key');
  ok(no_pkg($rec), 'no pkg: line');
  is(scalar(grep { $_ eq 'run: modprobe amdgpu' } @{ $rec->{lines} }), 1, 'amdgpu was not loaded: modprobed once');
  golden_is(masked($rec), 'amd/ubuntu-24.04--inbox--synapse--firmware');
};

subtest 'inbox on 24.04 kernel 6.8 for a DKMS-row GPU, as asked: modules-extra is installed (golden)' => sub {
  my $K = '6.8.0-85-generic';
  my $host = amd_host('ubuntu-24.04', kernel => $K, state => [ fresh('mi300x'), working('mi300x') ],
    module => [ 'none', 'inbox' ]);
  my ( $rec, $how ) = install($host, gpus => [ gpu_mi300x() ], method => 'inbox');
  is($rec->{error}, undef, 'lives');
  is($how, 'inbox', 'inbox');
  like(warns($rec)->[0], qr/AMD supports it with amdgpu-dkms; using the inbox driver as asked \(method => 'inbox'\)/, 'warns that AMD supports dkms for it');
  my ( $install ) = grep { /apt-get .* install -y / } @{ $rec->{lines} };
  like($install, qr/ install -y linux-modules-extra-\Q$K\E\z/, 'linux-modules-extra of the running kernel (the firmware is "installed")');
  golden_is(masked($rec), 'amd/ubuntu-24.04--inbox--mi300x--modules-extra');
};

subtest 'inbox: nothing to install when module and firmware are there' => sub {
  my $host = amd_host('ubuntu-24.04', kernel => '7.0.0-42-generic', state => [ fresh('synapse'), working('synapse') ], module => 'inbox');
  my ( $rec, $how ) = install($host, gpus => [ gpu_synapse() ], method => 'inbox');
  is($rec->{error}, undef, 'lives');
  is($how, 'inbox', 'returns inbox');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [ 'run: modprobe amdgpu' ], 'the only change: modprobe amdgpu');
  ok(!( grep { /apt-get|dnf/ } @{ $rec->{lines} }), 'no apt-get, no dnf');
};

#### dies before any change

subtest 'dies BEFORE any change' => sub {
  my $K = '6.8.0-85-generic';
  my @case = (
    [ 'ubuntu-24.04--dkms--secure-boot', qr/Secure Boot is enabled/,
      sub { dkms_case('x', 'ubuntu-24.04', 'mi300x', host => { secure_boot => 1 }) } ],
    [ 'ubuntu-24.04--dkms--arm64', qr/amdgpu-dkms is built for amd64 only; this host is arm64/,
      sub { dkms_case('x', 'ubuntu-24.04', 'mi300x', host => { arch => 'arm64' }) } ],
    [ 'rhel-9--dkms--aarch64', qr/amdgpu-dkms is built for x86_64 only; this host is aarch64/,
      sub { dkms_case('x', 'rhel-9', 'mi300x', host => { arch => 'aarch64' }) } ],
    [ 'ubuntu-24.04--dkms--foreign-repo-file', qr{/etc/apt/sources\.list\.d/amdgpu\.list exists with other content than amdgpu 31\.60 needs},
      sub { dkms_case('x', 'ubuntu-24.04', 'mi300x', responses => [
        [ 'cat /etc/apt/sources.list.d/amdgpu.list 2>/dev/null' => 'deb https://mirror.example.com/amdgpu/ubuntu noble main', 0 ] ]) } ],
    [ 'rhel-9--dkms--foreign-repo-file', qr{/etc/yum\.repos\.d/amdgpu\.repo exists with other content},
      sub { dkms_case('x', 'rhel-9', 'mi300x', responses => [
        [ 'cat /etc/yum.repos.d/amdgpu.repo 2>/dev/null' => "[amdgpu]\nbaseurl=https://mirror.example.com/amdgpu/\n", 0 ] ]) } ],
    [ 'ubuntu-24.04--dkms--unsupported-kernel', qr/amdgpu-dkms 31\.60 supports Ubuntu 24\.04\.5 LTS with kernel 6\.8 or 7\.0 \(-generic\); this host runs 6\.14\.0-1-generic/,
      sub { dkms_case('x', 'ubuntu-24.04', 'mi300x', kernel => '6.14.0-1-generic') } ],
    [ 'ubuntu-24.04--dkms--hwe-flavour', qr/this host runs 6\.8\.0-85-lowlatency/,
      sub { dkms_case('x', 'ubuntu-24.04', 'mi300x', kernel => '6.8.0-85-lowlatency') } ],
    [ 'debian-13--dkms--unsupported-kernel', qr/amdgpu-dkms 31\.60 supports Debian GNU\/Linux 13 \(trixie\) with kernel 6\.12 \(6\.12\.N\+deb13-amd64\); this host runs 6\.11\.0-1-amd64/,
      sub { dkms_case('x', 'debian-13', 'mi300x', kernel => '6.11.0-1-amd64') } ],
    [ 'rhel-9--dkms--unsupported-kernel', qr/amdgpu-dkms 31\.60 supports Red Hat Enterprise Linux 9\.6 \(Plow\) with kernel 5\.14\.0-687, -570 or -427; this host runs 5\.14\.0-503\.el9\.x86_64/,
      sub { dkms_case('x', 'rhel-9', 'mi300x', kernel => '5.14.0-503.el9.x86_64') } ],
    [ 'ubuntu-24.04--inbox--apu-kernel-6.8', qr/AMD GPU 0000:95:00\.0 \[1002:1586\] \(gfx1151\): AMD \(inbox driver only\) supports Ubuntu 24\.04\.5 LTS with kernel 7\.0 \(-generic\); this host runs 6\.8\.0-85-generic -- Ubuntu 26\.04 \(GA kernel 7\.0\) and Ubuntu 24\.04 \(HWE kernel 7\.0\)/,
      sub { my $h = amd_host('ubuntu-24.04', kernel => $K, state => [ fresh('synapse') ]);
            install($h, gpus => [ gpu_synapse() ]) } ],
    [ 'debian-13--inbox--apu', qr/AMD supports them with the inbox driver only on Ubuntu 26\.04 \(GA kernel 7\.0\) and Ubuntu 24\.04 \(HWE kernel 7\.0\).*this host runs Debian GNU\/Linux 13 \(trixie\) with kernel/,
      sub { my $h = amd_host('debian-13', state => [ fresh('synapse') ]);
            install($h, gpus => [ gpu_synapse() ]) } ],
    [ 'ubuntu-24.04--dkms--nomodeset', qr/the kernel command line has nomodeset/,
      sub { dkms_case('x', 'ubuntu-24.04', 'mi300x', host => { cmdline => 'BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro nomodeset' }) } ],
    [ 'ubuntu-24.04--dkms--modeset-0', qr/the kernel command line has amdgpu\.modeset=0/,
      sub { dkms_case('x', 'ubuntu-24.04', 'mi300x', host => { cmdline => 'ro quiet amdgpu.modeset=0' }) } ],
    [ 'ubuntu-24.04--dkms--cmdline-blacklist', qr/the kernel command line has modprobe\.blacklist=nouveau,amdgpu/,
      sub { dkms_case('x', 'ubuntu-24.04', 'mi300x', host => { cmdline => 'ro modprobe.blacklist=nouveau,amdgpu' }) } ],
    [ 'ubuntu-24.04--dkms--blacklisted', qr{amdgpu is blacklisted \(/etc/modprobe\.d/blacklist-gpu\.conf:blacklist amdgpu\); remove that first},
      sub { dkms_case('x', 'ubuntu-24.04', 'mi300x', responses => [
        [ qr{^grep -rsHE --include='\*\.conf' } => "/etc/modprobe.d/blacklist-gpu.conf:blacklist amdgpu\n", 0 ] ]) } ],
    [ 'ubuntu-24.04--dkms--bound-to-vfio', qr/AMD GPU 0000:c1:00\.0 \[1002:74a1\] \(gfx942\) is bound to vfio-pci; install_driver does not unbind it/,
      sub { my $h = amd_host('ubuntu-24.04', state => [ amd_state(amdgpu => 0, kfd => 0, gpus => [
              { %{ $SLOT{mi300x} }, driver => 'vfio-pci', render => undef } ]) ]);
            install($h, gpus => [ gpu_mi300x() ], method => 'dkms') } ],
    [ 'fedora-like-unsupported-os', qr/Unsupported OS for the AMD driver: Fedora Linux 42 \(Workstation Edition\) \(supported: Ubuntu, Debian, RHEL, Rocky Linux, AlmaLinux\)/,
      sub { my $h = amd_host('ubuntu-24.04', state => [ fresh('mi300x') ], responses => [
              [ 'cat /etc/os-release 2>/dev/null' => qq{NAME="Fedora Linux"\nID=fedora\nVERSION_ID="42"\nPRETTY_NAME="Fedora Linux 42 (Workstation Edition)"}, 0 ] ]);
            install($h, gpus => [ gpu_mi300x() ]) } ],
  );
  for my $c (@case) {
    my ( $name, $re, $code ) = @$c;
    my ( $rec ) = $code->();
    like($rec->{error}, $re, "$name: dies with the reason");
    like($rec->{error}, qr/Nothing was changed on the host/, '... "Nothing was changed on the host"');
    is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... and no command that changes the host ran');
    ok(!$rec->{trapped}, '... no unmocked Rex function reached');
    # a few are also pinned as goldens: the die comes after exactly these reads
    golden_is(masked($rec), "amd/$name") if $name =~ /secure-boot|arm64|foreign-repo-file|apu-kernel|bound-to-vfio/;
  }
};

#### Debian inbox and Proxmox VE (k81)

# pve-firmware as dpkg-query -W -f='${Status}\n' prints it
sub pve_status {
  my ( $status ) = @_;
  return [ qr{^dpkg-query -W -f='\$\{Status\}\\n' pve-firmware 2>/dev/null$} => $status, 0 ];
}
sub pve_queries { my ( $rec ) = @_; return scalar grep { /dpkg-query/ } @{ $rec->{lines} } }

# inbox install_driver on a Debian host; os_release replaces /etc/os-release
sub debian_install {
  my ( $os, %o ) = @_;
  my $gpu = delete $o{gpu} // 'mi300x';
  my $release = delete $o{os_release};
  my $host = amd_host($os,
    ( defined $o{kernel} ? ( kernel => $o{kernel} ) : () ),
    state => [ fresh($gpu), working($gpu) ], module => 'inbox',
    responses => [ @{ $o{responses} // [] },
      # firmware-amd-graphics HAS a candidate, scripted: else the Ubuntu base
      # profile's NVIDIA policy answer would stand in for it. 13: read on a
      # live PVE 9.2 (trixie/non-free-firmware); 12: a plausible bookworm
      # version, GUESSED.
      [ 'LC_ALL=C apt-cache policy firmware-amd-graphics 2>/dev/null' =>
        "firmware-amd-graphics:\n  Installed: (none)\n  Candidate: ".( $os eq 'debian-13' ? '20250410-2' : '20230210-5' )."\n  Version table:\n", 0 ],
      ( defined $release ? [ 'cat /etc/os-release 2>/dev/null' => $release, 0 ] : () ) ]);
  return install($host, gpus => [ $GPU{$gpu}->() ], method => 'inbox');
}
# firmware-amd-graphics not installed before the run, installed after it
sub firmware_missing {
  return [ qr{^dpkg -l firmware-amd-graphics 2>/dev/null \| grep -q '\^ii'$} => sequence([ '', 1 ], [ '', 0 ]), 0 ];
}

subtest 'inbox on Debian 12 and 13 with the release\'s own kernel: pve-firmware read, then firmware-amd-graphics (goldens)' => sub {
  for my $os (qw( debian-12 debian-13 )) {
    my ( $rec, $how ) = debian_install($os, responses => [ firmware_missing() ]);
    is($rec->{error}, undef, "$os: lives");
    is($how, 'inbox', '... returns inbox');
    is(pve_queries($rec), 1, '... pve-firmware asked exactly once');
    my ( $install ) = grep { /apt-get .* install -y / } @{ $rec->{lines} };
    like($install, qr/ install -y firmware-amd-graphics\z/, '... firmware-amd-graphics alone');
    ok(no_pkg($rec), '... no pkg: line');
    ok(!( grep { /amdgpu-dkms|radeon\.com|amdgpu\.list/ } @{ $rec->{lines} }), '... no DKMS, no AMD repository');
    my @l = @{ $rec->{lines} };
    my ( $q ) = grep { $l[$_] =~ /dpkg-query/ } 0 .. $#l;
    my ( $stop ) = grep { $l[$_] =~ /systemctl stop/ } 0 .. $#l;
    ok($q < $stop, '... the pve-firmware read comes before the first mutating command');
    golden_is(masked($rec), "amd/$os--inbox--mi300x--firmware");
  }
};

subtest 'inbox on Debian: firmware already installed, nothing but modprobe' => sub {
  my ( $rec, $how ) = debian_install('debian-13');
  is($rec->{error}, undef, 'lives');
  is($how, 'inbox', 'inbox');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [ 'run: modprobe amdgpu' ], 'the only change: modprobe amdgpu');
};

subtest 'Debian: dies before any change, runs no apt-get (goldens for the new messages)' => sub {
  my $PVE = 'install ok installed';
  my @case = (
    [ 'debian-11--inbox', qr/the inbox amdgpu is supported on Debian 12 and 13 only, not Debian GNU\/Linux 11 \(bullseye\)/,
      sub { debian_install('debian-12', kernel => '5.10.0-34-amd64', os_release => join("\n",
              'PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"', 'NAME="Debian GNU/Linux"', 'VERSION_ID="11"', 'ID=debian')) } ],
    [ 'debian-testing--inbox', qr/the inbox amdgpu is supported on Debian 12 and 13 only, not Debian GNU\/Linux trixie\/sid/,
      sub { debian_install('debian-13', os_release => join("\n",
              'PRETTY_NAME="Debian GNU/Linux trixie/sid"', 'NAME="Debian GNU/Linux"', 'ID=debian')) } ],
    [ 'debian-13--inbox--pve-kernel', qr/the inbox amdgpu is supported on Debian GNU\/Linux 13 \(trixie\) with Debian's own kernel 6\.12 \(6\.12\.N\+deb13-amd64\) only; this host runs 7\.0\.14-20-pve/,
      sub { debian_install('debian-13', kernel => '7.0.14-20-pve') } ],
    [ 'debian-12--inbox--cloud-kernel', qr/with Debian's own kernel 6\.1 .* only; this host runs 6\.1\.0-37-cloud-amd64/,
      sub { debian_install('debian-12', kernel => '6.1.0-37-cloud-amd64') } ],
    [ 'debian-13--inbox--proxmox-debian-kernel', qr/this is a Proxmox VE host \(pve-firmware is installed\): .*removing proxmox-ve and the Proxmox kernel/,
      sub { debian_install('debian-13', responses => [ pve_status($PVE) ]) } ],
    [ 'debian-13--dkms--proxmox-debian-kernel', qr/this is a Proxmox VE host \(pve-firmware is installed\)/,
      sub { my ( $rec ) = dkms_case('x', 'debian-13', 'mi300x', responses => [ pve_status($PVE) ]); $rec } ],
    [ 'debian-12--dkms--proxmox-debian-kernel', qr/this is a Proxmox VE host \(pve-firmware is installed\)/,
      sub { my ( $rec ) = dkms_case('x', 'debian-12', 'mi300x', responses => [ pve_status($PVE) ]); $rec } ],
    [ 'debian-13--inbox--proxmox-pve-kernel', qr/\Ainstall_driver: this is a Proxmox VE host/,
      sub { debian_install('debian-13', kernel => '7.0.14-20-pve', responses => [ pve_status($PVE) ]) } ],
    [ 'debian-13--inbox--proxmox-hold', qr/this is a Proxmox VE host/,
      sub { debian_install('debian-13', responses => [ pve_status('hold ok installed') ]) } ],
    [ 'debian-13--inbox--proxmox-unpacked', qr/this is a Proxmox VE host/,
      sub { debian_install('debian-13', responses => [ pve_status('install ok unpacked') ]) } ],
    [ 'debian-13--inbox--proxmox-half-installed', qr/this is a Proxmox VE host/,
      sub { debian_install('debian-13', responses => [ pve_status('install reinstreq half-installed') ]) } ],
  );
  my %golden = map { $_ => 1 } qw( debian-11--inbox debian-13--inbox--pve-kernel
    debian-13--inbox--proxmox-debian-kernel debian-13--dkms--proxmox-debian-kernel debian-13--inbox--proxmox-pve-kernel );
  for my $c (@case) {
    my ( $name, $re, $code ) = @$c;
    my ( $rec ) = $code->();
    like($rec->{error}, $re, "$name: dies with the reason");
    like($rec->{error}, qr/Nothing was changed on the host/, '... "Nothing was changed on the host"');
    is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... no command that changes the host ran');
    ok(!( grep { /apt-get|systemctl stop|dnf/ } @{ $rec->{lines} }), '... no apt-get, no systemctl stop');
    ok(!$rec->{trapped}, '... no unmocked Rex function reached');
    golden_is(masked($rec), "amd/$name") if $golden{$name};
  }
  # the Proxmox message wins over the kernel message
  my ( $rec ) = debian_install('debian-13', kernel => '7.0.14-20-pve', responses => [ pve_status($PVE) ]);
  unlike($rec->{error}, qr/Debian's own kernel/, 'pve-firmware with a -pve kernel: the Proxmox message, not the kernel one');
};

subtest 'pve-firmware removed but config left (rc): not a Proxmox host' => sub {
  my ( $rec, $how ) = debian_install('debian-13', responses => [ pve_status('deinstall ok config-files'), firmware_missing() ]);
  is($rec->{error}, undef, 'lives');
  is($how, 'inbox', 'inbox');
  is(pve_queries($rec), 1, 'asked once');
  ok(( grep { /apt-get .* install -y firmware-amd-graphics$/ } @{ $rec->{lines} } ), 'firmware-amd-graphics installed');
  ( $rec ) = debian_install('debian-13', responses => [ pve_status('unknown ok not-installed'), firmware_missing() ]);
  is($rec->{error}, undef, 'not-installed: lives too');
};

subtest 'a working amdgpu on Proxmox is answered with present: state read only (golden)' => sub {
  my $host = amd_host('debian-13', kernel => '7.0.14-20-pve', state => [ working('mi300x') ], module => 'inbox',
    responses => [ pve_status('install ok installed') ]);
  my ( $rec, $how ) = install($host, gpus => [ gpu_mi300x() ]);
  is($rec->{error}, undef, 'lives');
  is($how, 'present', 'present');
  is(pve_queries($rec), 0, 'pve-firmware not even asked');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], 'no change');
  ok(!( grep { /apt-get|dpkg/ } @{ $rec->{lines} }), 'no apt, no dpkg');
  golden_is(masked($rec), 'amd/debian-13--present--proxmox');
};

#### dies with a change made, no driver installed

subtest 'a key that is not the pinned one: dies at the key, nothing installed (golden)' => sub {
  my ( $rec ) = dkms_case('x', 'ubuntu-24.04', 'mi300x', host => { key => 'DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF' });
  like($rec->{error}, qr/The key from https:\/\/repo\.radeon\.com\/rocm\/rocm\.gpg\.key is not the AMD signing key expected \(fingerprint CA8BB4727A47B4D09B4EE8969386B48A1A693C5C; got DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF\); \/etc\/apt\/keyrings\/rocm\.gpg was not changed/,
    'dies naming expected and actual fingerprint');
  ok(!( grep { /apt-get .* install |dnf install|> \/etc\/apt\/sources\.list\.d\/amdgpu\.list/ } @{ $rec->{lines} }), 'no install, no repository file written');
  like($rec->{lines}[-1], qr{^run: rm -rf /etc/apt/keyrings/rocm\.gpg\.tmp\.d$}, 'the key directory is removed');
  ok(!( grep { /--dearmor/ } @{ $rec->{lines} }), 'the key was never dearmored into place');
  golden_is(masked($rec), 'amd/ubuntu-24.04--dkms--key-mismatch');

  ( $rec ) = dkms_case('x', 'rhel-9', 'mi300x', host => { key => 'DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF' });
  like($rec->{error}, qr/is not the AMD signing key expected/, 'RHEL: the same');
  ok(!( grep { /rpm --import|dnf install/ } @{ $rec->{lines} }), '... no rpm --import, no install');
};

subtest 'a required package without a candidate: dies after apt-get update, before any install (golden)' => sub {
  my $K = '7.0.0-42-generic';
  my $host = amd_host('ubuntu-24.04', kernel => $K, state => [ fresh('mi300x') ], module => 'none',
    responses => [ [ "LC_ALL=C apt-cache policy linux-modules-extra-$K 2>/dev/null" => "linux-modules-extra-$K:\n  Installed: (none)\n  Candidate: (none)\n", 0 ] ]);
  my ( $rec ) = install($host, gpus => [ gpu_mi300x() ], method => 'inbox');
  like($rec->{error}, qr/\Ainstall_driver: linux-modules-extra-\Q$K\E cannot be installed from the host's package sources \(no candidate\)\. Nothing was installed/,
    'dies naming the package');
  ok(!( grep { /apt-get .* install / } @{ $rec->{lines} }), 'no install command');
  ok(( grep { /apt-get .* update -q$/ } @{ $rec->{lines} }), '... after the index refresh');
  golden_is(masked($rec), 'amd/ubuntu-24.04--inbox--mi300x--no-candidate');
};

#### dies after the install

subtest 'a package not installed afterwards (half-configured DKMS): dies, naming the package (golden)' => sub {
  my ( $rec ) = dkms_case('x', 'ubuntu-24.04', 'mi300x', responses => [
    [ qr{^dpkg -l amdgpu-dkms 2>/dev/null \| grep -q '\^ii'$} => '', 1 ] ]);
  like($rec->{error}, qr/\Aamdgpu-dkms not installed after apt-get install -- check the apt output; a failed DKMS build leaves it half-configured/,
    'dies after the install');
  ok(!( grep { $_ eq 'run: modprobe amdgpu' } @{ $rec->{lines} }), '... no modprobe after a failed verify');
  ok(no_pkg($rec), 'verified by dpkg, not Rex::Pkg');
  golden_is(masked($rec), 'amd/ubuntu-24.04--dkms--mi300x--verify-failed');

  ( $rec ) = dkms_case('x', 'rhel-9', 'mi300x', responses => [
    [ qr{^rpm -q amdgpu-dkms 2>&1$} => 'package amdgpu-dkms is not installed', 1 ] ]);
  like($rec->{error}, qr/\Aamdgpu-dkms not installed after dnf install -- check the dnf output/, 'RHEL: the same, by rpm -q');
  ok(no_pkg($rec), '... verified by rpm, not Rex::Pkg');
  golden_is(masked($rec), 'amd/rhel-9--dkms--mi300x--verify-failed');
};

subtest 'dkms status without the module for the running kernel: dies (an RPM whose %post failed passes rpm -q)' => sub {
  my ( $rec ) = dkms_case('x', 'rhel-9', 'mi300x', responses => [ [ qr{^dkms status -m amdgpu -k } => '', 0 ] ]);
  like($rec->{error}, qr/amdgpu-dkms is installed, but dkms reports no amdgpu module built and installed for kernel 5\.14\.0-570\.12\.1\.el9_6\.x86_64/,
    'dies');
  ok(!( grep { $_ eq 'run: modprobe amdgpu' } @{ $rec->{lines} }), '... before any modprobe');

  ( $rec ) = dkms_case('x', 'ubuntu-24.04', 'mi300x', host => { module => 'inbox' });
  like($rec->{error}, qr/amdgpu-dkms is built for kernel 6\.8\.0-85-generic, but modinfo still resolves amdgpu to the inbox module/,
    'built, but modinfo still finds the inbox module: dies');
};

#### activation: modprobe and reboot

subtest 'usable after modprobe: the method is returned, no reboot even with reboot => 1' => sub {
  my ( $rec, $how ) = dkms_case('x', 'ubuntu-24.04', 'mi300x', args => { reboot => 1 });
  is($rec->{error}, undef, 'lives');
  is($how, 'dkms', 'dkms');
  is(shutdowns($rec), 0, 'no shutdown');
  is(scalar(grep { $_ eq 'run: modprobe amdgpu' } @{ $rec->{lines} }), 1, 'amdgpu was not loaded: `modprobe amdgpu` once');
  is($rec->{lines}[-1], 'run: '.$STATE_CMD, '... followed by the state read that decides');
  ok(( grep { /amdgpu loaded and verified/ } map { $_->[1] } @{ $rec->{logs} }), '... "loaded and verified"');
};

subtest 'amdgpu already loaded (old inbox driver): no modprobe; reboot => 0 warns and returns' => sub {
  my $K = '6.8.0-85-generic';
  my $host = amd_host('ubuntu-24.04', kernel => $K, state => [ loaded_unusable('mi300x') ], module => 'dkms',
    responses => [ dkms_status($K) ]);
  my ( $rec, $how ) = install($host, gpus => [ gpu_mi300x() ], method => 'dkms', reboot => 0);
  is($rec->{error}, undef, 'lives');
  is($how, 'dkms', 'returns the method');
  is(scalar(grep { $_ eq 'run: modprobe amdgpu' } @{ $rec->{lines} }), 0, 'no modprobe: it was loaded, a load would change nothing');
  is(shutdowns($rec), 0, 'no shutdown');
  is(scalar @{ warns($rec) }, 1, 'exactly one warning');
  like(warns($rec)->[0], qr/AMD driver \(dkms\) installed, not active yet -- reboot the host \(or pass reboot => 1\) to activate it\z/, '... reboot the host');
  golden_is(masked($rec), 'amd/ubuntu-24.04--dkms--mi300x--no-reboot');
};

subtest 'reboot => 1: one shutdown -r, the boot_id check, the state read, usable (golden)' => sub {
  my $K = '6.8.0-85-generic';
  my $ID_OLD = '11111111-2222-3333-4444-555555555555';
  my $ID_NEW = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  my $host = amd_host('ubuntu-24.04', kernel => $K, state => [ loaded_unusable('mi300x'), working('mi300x') ], module => 'dkms',
    responses => [
      dkms_status($K),
      [ 'cat /proc/sys/kernel/random/boot_id 2>/dev/null' => sequence([ $ID_OLD, 0 ], [ $ID_NEW, 0 ]), 0 ],
      [ 'echo ok' => 'ok', 0 ],
    ]);
  my ( $rec, $how, $conn ) = install($host, gpus => [ gpu_mi300x() ], method => 'dkms', reboot => 1);
  is($rec->{error}, undef, 'lives');
  is($how, 'dkms', 'returns the method');
  is(shutdowns($rec), 1, 'exactly one shutdown -r');
  is(scalar(grep { $_ eq 'run: modprobe amdgpu' } @{ $rec->{lines} }), 0, 'no modprobe (it was loaded)');
  my ( $at ) = grep { $rec->{lines}[$_] =~ /shutdown -r/ } 0 .. $#{ $rec->{lines} };
  is($rec->{lines}[$at - 1], 'run: cat /proc/sys/kernel/random/boot_id 2>/dev/null', 'the boot_id is read right before the shutdown');
  is($rec->{lines}[$at], q{run: nohup sh -c 'sleep 2 && shutdown -r now' >/dev/null 2>&1 &}, '... the reboot command, as emitted');
  is($rec->{lines}[$at + 1], 'run: echo ok', '... then the reconnect probe');
  is($rec->{lines}[-1], 'run: '.$STATE_CMD, '... and the last command is the state read that must find the driver usable');
  is_deeply(\@SLEPT, [ 20 ], 'slept 20 s, reconnected on the first try');
  is($conn->{reconnects}, 1, 'one reconnect');
  ok(( grep { /and verified after the reboot/ } map { $_->[1] } @{ $rec->{logs} }), '"verified after the reboot"');
  ok(no_pkg($rec), 'no pkg: line');
  golden_is(masked($rec), 'amd/ubuntu-24.04--dkms--mi300x--reboot');
};

subtest 'reboot => 1 but the driver is still unusable afterwards: dies' => sub {
  my $K = '6.8.0-85-generic';
  my $host = amd_host('ubuntu-24.04', kernel => $K, state => [ loaded_unusable('mi300x') ], module => 'dkms',
    responses => [ dkms_status($K), [ 'echo ok' => 'ok', 0 ] ]);
  my ( $rec ) = install($host, gpus => [ gpu_mi300x() ], method => 'dkms', reboot => 1);
  like($rec->{error}, qr/\AAMD driver \(dkms\) installed, but not usable after the reboot: no \/dev\/kfd \(the ROCm compute interface of amdgpu\); AMD GPU 0000:c1:00\.0 \[1002:74a1\] \(gfx942\): no KFD compute node/,
    'dies listing what is missing');
  is(shutdowns($rec), 1, 'the one shutdown was issued');
};

subtest 'the host does not come back: dies "did not come back", after 60 reconnects' => sub {
  my $K = '6.8.0-85-generic';
  my $host = amd_host('ubuntu-24.04', kernel => $K, state => [ loaded_unusable('mi300x') ], module => 'dkms',
    responses => [ dkms_status($K), [ 'cat /proc/sys/kernel/random/boot_id 2>/dev/null' => '', 1 ] ]);
  my ( $rec, undef, $conn ) = install($host, gpus => [ gpu_mi300x() ], method => 'dkms', reboot => 1, fail_first => 1000);
  like($rec->{error}, qr/\AHost did not come back after reboot\z/, 'dies');
  is($conn->{reconnects}, 60, '60 reconnects tried');
  ok(!( grep { $_ eq 'run: echo ok' } @{ $rec->{lines} }), 'the probe never ran (no reconnect succeeded)');
};

subtest 'no Rex::Pkg anywhere: not for the driver, not for the helpers' => sub {
  # the whole set of success transcripts above already asserts it per case;
  # here the helpers (curl, gnupg) are missing, the one place a pkg call would
  # be tempting.
  my $K = '6.8.0-85-generic';
  my $host = amd_host('ubuntu-24.04', kernel => $K, state => [ fresh('mi300x'), working('mi300x') ], module => 'dkms',
    responses => [ dkms_status($K), [ qr{^command -v (?:curl|gpg) >/dev/null 2>&1$} => '', 1 ] ]);
  my ( $rec, $how ) = install($host, gpus => [ gpu_mi300x() ], method => 'dkms');
  is($rec->{error}, undef, 'lives');
  ok(no_pkg($rec), 'no pkg: line');
  ok(( grep { /^run: DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y --no-upgrade curl gnupg$/ } @{ $rec->{lines} }),
    'the missing helpers are installed with a direct apt-get, lock timeout set');
};

done_testing;
