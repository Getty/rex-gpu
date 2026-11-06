#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# sleep() is a builtin: only a CORE::GLOBAL override installed before
# Rex::GPU::AMD is compiled reaches the sleeps of the reboot path (same trick
# as t/17-amd-install-driver.t).
our @SLEPT;
BEGIN { *CORE::GLOBAL::sleep = sub (;$) { push @SLEPT, $_[0]; return $_[0] // 0 } }

use FindBin qw( $Bin );
use lib "$Bin/lib";

# -----------------------------------------------------------------------------
# Rex::GPU::AMD::install_driver, dkms method: the die for "amdgpu-dkms is
# installed, but dkms reports no amdgpu module built" names a hold on
# amdgpu-dkms (karr k95).
#
# `apt-get install -y` does not change a package that is on hold (apt-mark
# hold), and aborts the install where the change would have to be made. The
# package then shows `hi` for dpkg -l, passes verify_packages (k89), and no
# module is built for the running kernel: the old message sent the operator to
# make.log, which does not exist or is stale. Since k95 post_install asks dpkg
# for the selection of amdgpu-dkms, but only on that failure path.
#
# CLAIMS:
#   * apt (Ubuntu 24.04, Debian 13 and 12), method dkms, amdgpu-dkms on hold
#     (dpkg -l `hi`, ${Status} `hold ok installed`), no module in `dkms status`
#     afterwards: dies with the message that names the hold, says `apt-get
#     install -y` does not change a held package, gives `apt-mark unhold
#     amdgpu-dkms`, and still points at /var/lib/dkms/amdgpu/*/build/make.log;
#   * the same without a hold (`ii`, `install ok installed`): the message is
#     the old one, character for character (anchored, nothing appended);
#   * a hold with the Status of a package that is not installed (`hold ok
#     not-installed`) counts as held too (the selection is what is asked);
#   * held, but the module is built after the install: lives, returns dkms, and
#     no dpkg-query for amdgpu-dkms is run -- the question belongs on the
#     failure path only;
#   * RHEL 9, no module built: the old message, and no dpkg-query at all
#     (Setup::package_held answers 0 without a host command);
#   * none of the cases routes a package through Rex::Pkg (no `pkg:` line) and
#     no unmocked Rex function is reached.
#
# NOT covered:
#   * what `apt-get install -y` really does to a held package on a given
#     release (leave it, or abort) -- the message states it, nothing here runs
#     apt; whether `apt-mark unhold` then lets the build through;
#   * the ${Status} lines are hand-written in dpkg-query's documented format
#     ("amdgpu-dkms hold ok installed 1:6.16.13-2255209.24.04"), not captured
#     on a host; the version string is invented in its shape;
#   * the `dkms status` answers are hand-written (see Test::RexGPU::AMD); a
#     real failed build can leave other lines (`added`, `built`) than the
#     empty answer scripted here, all of which count as "not installed";
#   * a hold set some other way than apt-mark/dpkg --set-selections (an apt
#     preferences pin does not show in ${Status}), and a held amdgpu-dkms that
#     is not the cause of the missing module;
#   * the make.log itself, a real DKMS build, a reboot.
# This test fails against the code before k95 (the held cases get the old
# message) and passes after.
# -----------------------------------------------------------------------------

use Test::RexGPU::Golden qw( record_host );
use Test::RexGPU::AMD qw( amd_host amd_state gpu_mi300x sequence os_kernel dpkg_l );
use Rex::GPU::AMD;

# A connection whose reconnect() works; install_driver does not reboot here.
{
  package Local::FakeConn;
  sub new { bless { disconnects => 0, reconnects => 0 }, shift }
  sub disconnect { $_[0]{disconnects}++; return 1 }
  sub reconnect  { $_[0]{reconnects}++; return 1 }
}

my $SLOT = { slot => '0000:c1:00.0', class => '1200', device_id => '74a1' };
sub fresh {
  return amd_state(amdgpu => 0, kfd => 0, gpus => [ { %$SLOT, driver => undef, render => undef } ]);
}
sub working {
  return amd_state(gpus => [ { %$SLOT, kfd => 90402, vram => 137438953472, gtt => 33535848448 } ]);
}

# amdgpu-dkms as dpkg-query -W -f='${Package} ${Status} ${Version}\n' prints it
sub dpkg_query {
  my ( $status ) = @_;
  return [ qr{^dpkg-query -W -f='\$\{Package\} \$\{Status\} \$\{Version\}\\n' amdgpu-dkms 2>/dev/null$}
    => "amdgpu-dkms $status 1:6.16.13-2255209.24.04", 0 ];
}
sub held_queries { my ( $rec ) = @_; return scalar grep { /dpkg-query .*amdgpu-dkms/ } @{ $rec->{lines} } }

# install_driver(method => dkms) for an MI300X.
#   built => 1  the module is there after the install (dkms status: nothing
#               before, installed after); 0: nothing built, ever
#   dpkg  => 'hi' | 'ii'   dpkg -l state of amdgpu-dkms (apt only)
#   status => '...'        the dpkg-query ${Status} answer (apt only)
sub dkms_install {
  my ( $os, %o ) = @_;
  my $kernel = os_kernel($os);
  my $dkms = $o{built}
    ? sequence([ '', 0 ], [ "amdgpu/6.16.13-2255209.24.04, $kernel, x86_64: installed", 0 ])
    : sequence([ '', 0 ]);
  my $apt = $os !~ /^(?:rhel|rocky)/;
  my $host = amd_host($os,
    kernel => $kernel, state => [ fresh(), working() ], module => $o{built} ? 'dkms' : 'none',
    responses => [
      [ qr{^dkms status -m amdgpu -k } => $dkms, 0 ],
      ( $apt ? ( dpkg_l('amdgpu-dkms' => $o{dpkg}), dpkg_query($o{status}) ) : () ),
      ( $apt ? () : (
        [ qr{^rpm -q amdgpu-dkms 2>&1$} => sequence([ 'package amdgpu-dkms is not installed', 1 ], [ 'amdgpu-dkms', 0 ]), 0 ],
        [ qr{^rpm -q (?:kernel-\S+) 2>&1$} => 'ok', 0 ],
        [ qr{^dnf -q repoquery --available } => 'x-0:1.noarch', 0 ],
      ) ),
    ]);
  my $conn = Local::FakeConn->new;
  my $how;
  @SLEPT = ();
  my $rec = record_host(
    host => $host,
    subs => { 'Rex::get_current_connection' => sub { return { conn => $conn } } },
    code => sub { $how = Rex::GPU::AMD::install_driver(gpus => [ gpu_mi300x() ], method => 'dkms') },
  );
  return ( $rec, $how );
}

sub no_pkg { my ( $rec ) = @_; return !grep { /^pkg:/ } @{ $rec->{lines} } }

my $MAKE_LOG = '/var/lib/dkms/amdgpu/*/build/make.log';
sub unheld_message {
  my ( $kernel ) = @_;
  return "install_driver: amdgpu-dkms is installed, but dkms reports no amdgpu module built and installed for kernel $kernel; see $MAKE_LOG";
}
sub held_message {
  my ( $kernel ) = @_;
  return "install_driver: amdgpu-dkms is installed, but dkms reports no amdgpu module built and installed for kernel $kernel; "
    ."amdgpu-dkms is on hold, and apt-get install -y does not change a held package (where it would have to, it aborts the install). "
    ."Run apt-mark unhold amdgpu-dkms and install_driver again; if the module is still missing then, see $MAKE_LOG";
}

#### held, nothing built

for my $os (qw( ubuntu-24.04 debian-13 debian-12 )) {
  subtest "$os: amdgpu-dkms on hold, no module built: the message names the hold and the way out" => sub {
    my ( $rec ) = dkms_install($os, built => 0, dpkg => 'hi', status => 'hold ok installed');
    my $err = $rec->{error} // '';
    is($err, held_message(os_kernel($os)), 'the full message');
    like($err, qr/is on hold/, '... names the hold');
    like($err, qr/apt-mark unhold amdgpu-dkms/, '... gives apt-mark unhold amdgpu-dkms');
    like($err, qr{\Q$MAKE_LOG\E}, '... still points at make.log');
    is(held_queries($rec), 1, 'the hold is asked once, with dpkg-query');
    ok(!( grep { $_ eq 'run: modprobe amdgpu' } @{ $rec->{lines} }), 'dies before any modprobe');
    ok(no_pkg($rec), 'no pkg: line');
    ok(!$rec->{trapped}, 'no unmocked Rex function reached');
  };
}

subtest 'a hold on a package dpkg does not have installed counts as the selection, too' => sub {
  my ( $rec ) = dkms_install('ubuntu-24.04', built => 0, dpkg => 'hi', status => 'hold ok not-installed');
  is($rec->{error}, held_message(os_kernel('ubuntu-24.04')), 'the hold message');
};

#### not held, nothing built: the old message, unchanged

for my $os (qw( ubuntu-24.04 debian-13 debian-12 )) {
  subtest "$os: amdgpu-dkms not on hold, no module built: the old message, word for word" => sub {
    my ( $rec ) = dkms_install($os, built => 0, dpkg => 'ii', status => 'install ok installed');
    is($rec->{error}, unheld_message(os_kernel($os)), 'exactly the old message');
    unlike($rec->{error} // '', qr/hold/, '... no word about a hold');
    is(held_queries($rec), 1, 'the hold was asked, and answered no');
    ok(no_pkg($rec), 'no pkg: line');
    ok(!$rec->{trapped}, 'no unmocked Rex function reached');
  };
}

#### held, module built: the hold is not asked

subtest 'amdgpu-dkms on hold, but the module is built: lives, no dpkg-query for amdgpu-dkms' => sub {
  for my $os (qw( ubuntu-24.04 debian-13 )) {
    my ( $rec, $how ) = dkms_install($os, built => 1, dpkg => 'hi', status => 'hold ok installed');
    is($rec->{error}, undef, "$os: lives");
    is($how, 'dkms', '... returns dkms');
    is(held_queries($rec), 0, '... the hold is never asked (the question belongs on the failure path)');
    ok(no_pkg($rec), '... no pkg: line');
  }
};

#### RHEL: no hold concept, old message, no dpkg-query

subtest 'rhel-9: no module built: the old message, no dpkg-query at all' => sub {
  my ( $rec ) = dkms_install('rhel-9', built => 0);
  is($rec->{error}, unheld_message(os_kernel('rhel-9')), 'exactly the old message');
  is(scalar(grep { /dpkg-query/ } @{ $rec->{lines} }), 0, 'no dpkg-query');
  ok(no_pkg($rec), 'no pkg: line');
  ok(!$rec->{trapped}, 'no unmocked Rex function reached');
};

done_testing;
