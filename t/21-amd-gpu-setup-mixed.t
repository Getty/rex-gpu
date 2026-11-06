#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use FindBin qw( $Bin );
use lib "$Bin/lib";

# -----------------------------------------------------------------------------
# karr k90: gpu_setup with amd_integrated => 1 on a host with an APU (inbox
# driver only, gfx1151) next to a GPU that needs amdgpu-dkms (MI300X, gfx942)
# -- the REAL Rex::GPU::AMD::install_driver, called by the real gpu_setup, on
# a scripted host. Only detection and the connection check are replaced.
#
# CLAIMS:
#   * gpu_setup(amd_integrated => 1) dies in install_driver before any change
#     (no mutating command), with a message that names gpu_setup's ways out:
#     "Leave out gpu_setup's amd_integrated => 1 ..." and "Or call
#     Rex::GPU::AMD->install_driver directly instead of gpu_setup:"; where the
#     inbox driver carries the APU (Ubuntu 24.04 HWE 7.0) that call is "pass
#     method => 'inbox' ..."; where it does not (Ubuntu 22.04,
#     inbox_only_unsupported; a Setup with only inbox_unsupported) it is
#     "method => 'inbox' is no way out ...", then "Pass gpus => with <dGPU>
#     only to leave <APU> out";
#   * the same host through install_driver directly: the message is the one
#     of before k90, with no "gpu_setup" in it, and the flag is not set;
#   * the guard: when an inbox-only GPU is NOT integrated (a hardware_class of
#     your own), leaving out amd_integrated would not skip it, so there is no
#     amd_integrated advice and the addition starts with "Call
#     Rex::GPU::AMD->install_driver directly instead of gpu_setup: ";
#   * $Rex::GPU::AMD::GPU_SETUP is true inside install_driver only, false
#     inside verify_amd, and false after gpu_setup -- also when install_driver
#     died; install_driver gets exactly gpus => [...], reboot => 0|1;
#   * the early dies (Proxmox) keep their message under gpu_setup.
#
# NOT covered -- scripted host, hand-written output:
#   * the state script in a real shell, a real amdgpu / KFD; the Ubuntu
#     24.04 / 22.04 answers are the hand-written profiles of Test::RexGPU::AMD
#     (kernel strings guessed there);
#   * that the advised way out works on a host: gpu_setup without
#     amd_integrated skipping the APU is t/15's dispatch, with recorders.
# -----------------------------------------------------------------------------

use Test::RexGPU::Golden qw( record_host mutating_lines );
use Test::RexGPU::AMD qw( amd_host amd_state gpu_synapse gpu_mi300x );
use Rex::Config;
use Rex::GPU;
use Rex::GPU::AMD;
use Rex::GPU::AMD::Hardware;
use Rex::GPU::AMD::Setup::Ubuntu;

my $STATE = 'run: '.Rex::GPU::AMD->state_script;
my $A = 'AMD GPU 0000:95:00.0 [1002:1586] (gfx1151)';
my $B = 'AMD GPU 0000:c1:00.0 [1002:74a1] (gfx942)';
my $HEAD = qr/\Ainstall_driver: AMD supports \Q$A\E only with the inbox driver and \Q$B\E with amdgpu-dkms, and one amdgpu drives every GPU of a host\. /;
my $TAIL = qr/Nothing was changed on the host\n?\z/;
my $LEAVE = "Leave out gpu_setup's amd_integrated => 1 to give the driver to $B only; gpu_setup then skips $A with a warning. Or call Rex::GPU::AMD->install_driver directly instead of gpu_setup: ";

my %BROKEN = (
  synapse => { slot => '0000:95:00.0', class => '0380', device_id => '1586',
               driver => undef, kfd => undef, render => undef, vram => undef, gtt => undef },
  mi300x  => { slot => '0000:c1:00.0', class => '1200', device_id => '74a1',
               driver => undef, kfd => undef, render => undef },
);
my $BOTH = amd_state(amdgpu => 0, kfd => 0, gpus => [ $BROKEN{synapse}, $BROKEN{mi300x} ]);
my $PVE  = [ qr{^dpkg-query -W -f='\$\{Status\}\\n' pve-firmware 2>/dev/null$} => '', 0 ];

{
  package Test::InboxUnsupportedSetup;   # only inbox_unsupported gives a reason
  use parent -norequire, 'Rex::GPU::AMD::Setup::Ubuntu';
  sub inbox_unsupported { 'the inbox amdgpu is not allowed on this test host' }
  package Test::InboxUnsupportedAMD;
  use parent -norequire, 'Rex::GPU::AMD';
  sub setup_class_for_os { 'Test::InboxUnsupportedSetup' }

  # the gfx1151 row as a discrete, inbox-only one: the guard's case
  package Test::NotAPUHW;
  use parent -norequire, 'Rex::GPU::AMD::Hardware';
  sub targets {
    my ( $class ) = @_;
    return map { $_->{gfx_target} eq 'gfx1151' ? { %$_, integrated => 0 } : $_ } $class->SUPER::targets;
  }
  package Test::NotAPUAMD;
  use parent -norequire, 'Rex::GPU::AMD';
  sub hardware_class { 'Test::NotAPUHW' }
}

sub host {
  my ( $os, %o ) = @_;
  return amd_host($os, state => $BOTH, ( defined $o{kernel} ? ( kernel => $o{kernel} ) : () ),
    responses => [ $PVE ]);
}

sub detect_mocks {
  my ( @gpus ) = @_;
  return (
    'Rex::GPU::gpu_detect'        => sub { return { nvidia => [], nvswitch => [], amd => [ @gpus ] } },
    'Rex::GPU::_check_connection' => sub { return },
  );
}

# gpu_setup (amd_integrated => 1) or install_driver directly, on the host.
# %o: via => 'gpu_setup'|'direct', class => AMD subclass
sub run_on {
  my ( $host, %o ) = @_;
  my @gpus = ( gpu_synapse(), gpu_mi300x() );
  my $class = $o{class} // 'Rex::GPU::AMD';
  return record_host(host => $host, subs => { detect_mocks(@gpus) },
    code => sub {
      ( $o{via} // 'gpu_setup' ) eq 'direct'
        ? $class->install_driver(gpus => \@gpus)
        : Rex::GPU::gpu_setup(amd_integrated => 1, amd => $class);
    });
}

sub clean {
  my ( $rec, $label ) = @_;
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], "$label: no mutating command ran");
  is($rec->{lines}[0], $STATE, "$label: the first command is the state read");
}

subtest 'gpu_setup: the inbox driver carries the APU -- gpu_setup ways out, then method => inbox' => sub {
  my $rec = run_on(host('ubuntu-24.04', kernel => '7.0.0-42-generic'));
  ok(!$rec->{trapped}, 'no unmocked Rex function reached');
  like($rec->{error}, qr/$HEAD\Q${LEAVE}pass method => 'inbox' to drive all of them with the inbox driver. \E$TAIL/,
    'dies with the whole message');
  unlike($rec->{error}, qr/Pass gpus|no way out/, '... no dead-end note');
  clean($rec, 'HWE 7.0');
};

subtest 'gpu_setup: the inbox driver does NOT carry the APU -- reason, then gpus' => sub {
  my $rec = run_on(host('ubuntu-22.04'));
  like($rec->{error}, qr/$HEAD\Q${LEAVE}method => 'inbox' is no way out on this host for $A: \E.*Ubuntu 22\.04.*\Q Pass gpus => with $B only to leave $A out. \E$TAIL/s,
    'Ubuntu 22.04: both gpu_setup ways out, the reason, gpus =>');
  unlike($rec->{error}, qr/pass method => 'inbox'/i, '... no method => inbox advice');
  clean($rec, 'Ubuntu 22.04');

  $rec = run_on(host('ubuntu-24.04', kernel => '7.0.0-42-generic'), class => 'Test::InboxUnsupportedAMD');
  like($rec->{error}, qr/$HEAD\Q${LEAVE}method => 'inbox' is no way out on this host: the inbox amdgpu is not allowed on this test host. Pass gpus => with $B only to leave $A out. \E$TAIL/,
    'only inbox_unsupported: "no way out on this host: <reason>", then gpus =>');
  clean($rec, 'inbox_unsupported');
};

subtest 'install_driver directly: the message of before k90, no gpu_setup in it' => sub {
  my $rec = run_on(host('ubuntu-24.04', kernel => '7.0.0-42-generic'), via => 'direct');
  like($rec->{error}, qr/$HEAD\QPass method => 'inbox' to drive all of them with the inbox driver. \E$TAIL/, 'HWE 7.0: unchanged');
  unlike($rec->{error}, qr/gpu_setup/, '... no "gpu_setup"');
  clean($rec, 'direct, HWE 7.0');

  $rec = run_on(host('ubuntu-22.04'), via => 'direct');
  like($rec->{error}, qr/$HEAD\Qmethod => 'inbox' is no way out on this host for $A: \E.*\Q Pass gpus => with $B only to leave $A out. \E$TAIL/s, 'Ubuntu 22.04: unchanged');
  unlike($rec->{error}, qr/gpu_setup/, '... no "gpu_setup"');
  is($Rex::GPU::AMD::GPU_SETUP, undef, 'the flag is not set outside gpu_setup');
};

subtest 'the guard: an inbox-only GPU that is not an APU gets no amd_integrated advice' => sub {
  my $rec = run_on(host('ubuntu-24.04', kernel => '7.0.0-42-generic'), class => 'Test::NotAPUAMD');
  like($rec->{error}, qr/$HEAD\QCall Rex::GPU::AMD->install_driver directly instead of gpu_setup: pass method => 'inbox' to drive all of them with the inbox driver. \E$TAIL/,
    'the addition starts with "Call Rex::GPU::AMD->install_driver directly instead of gpu_setup: "');
  unlike($rec->{error}, qr/amd_integrated|Leave out/, '... no amd_integrated advice');
  clean($rec, 'not an APU');

  $rec = run_on(host('ubuntu-22.04'), class => 'Test::NotAPUAMD');
  like($rec->{error}, qr/$HEAD\QCall Rex::GPU::AMD->install_driver directly instead of gpu_setup: method => 'inbox' is no way out\E/,
    'also with the "no way out" hint');
  unlike($rec->{error}, qr/amd_integrated/, '... no amd_integrated advice');
};

subtest 'early dies keep their message under gpu_setup' => sub {
  my $rec = run_on(amd_host('debian-13', state => $BOTH, responses => [ [ $PVE->[0] => 'install ok installed', 0 ] ]));
  like($rec->{error}, qr/\Ainstall_driver: this is a Proxmox VE host \(pve-firmware is installed\)/, 'Proxmox: its own message');
  unlike($rec->{error}, qr/gpu_setup|amd_integrated/, '... no gpu_setup advice');
};

subtest 'the flag: set in install_driver only, reset after gpu_setup, arguments unchanged' => sub {
  my ( @args, @flag );
  my @gpus = ( gpu_synapse(), gpu_mi300x() );
  for my $die (0, 1) {
    @args = (); @flag = ();
    my $rec = record_host(host => host('ubuntu-24.04'),
      subs => {
        detect_mocks(@gpus),
        'Rex::GPU::AMD::install_driver' => sub { @args = @_; push @flag, [ install_driver => $Rex::GPU::AMD::GPU_SETUP ]; die "boom\n" if $die; 'present' },
        'Rex::GPU::AMD::verify_amd'     => sub { push @flag, [ verify_amd => $Rex::GPU::AMD::GPU_SETUP ]; return { ok => 1, gpus => [] } },
      },
      code => sub { Rex::GPU::gpu_setup(amd_integrated => 1, reboot => 1) });
    my $label = $die ? 'install_driver dies' : 'install_driver lives';
    is_deeply(\@args, [ gpus => \@gpus, reboot => 1 ], "$label: install_driver got exactly gpus and reboot");
    is($flag[0][1], 1, "$label: the flag is true inside install_driver");
    is($Rex::GPU::AMD::GPU_SETUP, undef, "$label: the flag is false after gpu_setup");
    if ($die) {
      like($rec->{error}, qr/\Aboom/, '... the die reaches the caller');
      is_deeply([ map { $_->[0] } @flag ], [ 'install_driver' ], '... verify_amd not reached');
    }
    else {
      is_deeply(\@flag, [ [ install_driver => 1 ], [ verify_amd => undef ] ], '... verify_amd sees the flag false');
    }
  }
};

done_testing;
