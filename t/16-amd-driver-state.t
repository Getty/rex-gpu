#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use FindBin qw( $Bin );
use lib "$Bin/lib";

# -----------------------------------------------------------------------------
# Rex::GPU::AMD: what install_driver does when it changes NOTHING, and
# verify_amd (karr k1), against a scripted host.
#
# CLAIMS:
#   * install_driver on a host whose driver works returns 'present' and runs
#     exactly one command, the read-only state script, for method auto; an
#     explicit method adds only the read-only `uname -r` and `modinfo -n
#     amdgpu` (to tell the kinds apart) -- for auto, inbox and dkms;
#   * an explicit method that is not the working driver's kind (dkms asked,
#     inbox works; inbox asked, DKMS works) is still 'present', with a warning
#     naming the working kind; a matching method warns about nothing;
#   * method dkms for a GPU AMD supports only with the inbox driver (the
#     Ryzen APU) dies after the state read, also where the driver works;
#   * these die with NO change (only read-only commands, none at all for the
#     argument checks): an invalid method, an unknown option, malformed gpus,
#     an explicit gpus => [], a GPU that is not on the host, a host with no
#     AMD GPU, an unreadable state, and inbox + dkms GPUs together under auto;
#   * every host command goes through Rex::GPU::AMD->host_run: a subclass that
#     overrides it sees all of them;
#   * verify_amd returns { ok, gpus => [ { slot device_id gfx_target
#     vram_bytes gtt_bytes kfd_node kfd_nodes } ] } from the one state read;
#     it never dies; every problem is a warning and makes ok 0 (module not
#     loaded, /dev/kfd missing, no KFD node, no render node, GPU not on the
#     host, unreadable state, bad arguments); gpus => [subset] reports and
#     judges only those; gpus => [] warns and returns { ok => 0, gpus => [] }
#     with no command.
#
# NOT covered -- scripted host, hand-written output:
#   * the state script itself in a real shell: it is a string here, fed
#     canned output, never run (t/14's header says the same);
#   * a real amdgpu / KFD: "works" means the canned lines say so. The synapse
#     lines imitate the host read on 2026-10-31 (Test::RexGPU::AMD).
# -----------------------------------------------------------------------------

use Test::RexGPU::Golden qw( record_host mutating_lines );
use Test::RexGPU::AMD qw( amd_host amd_state gpu_synapse gpu_mi300x gpu_navi31 ubuntu_amd_host module_path );
use Rex::Config;
use Rex::GPU::AMD;

my $STATE_CMD = Rex::GPU::AMD->state_script;
my $STATE = 'run: '.$STATE_CMD;
my $K = '7.0.0-42-generic';

my %G = (
  synapse => { slot => '0000:95:00.0', class => '0380', device_id => '1586', kfd => 110501,
               vram => 137438953472, gtt => 33535848448 },
  mi300x  => { slot => '0000:c1:00.0', class => '1200', device_id => '74a1', kfd => 90402 },
  navi31  => { slot => '0000:0a:00.0', class => '0300', device_id => '744c', kfd => 110000 },
);
my %BROKEN = (
  synapse => { %{ $G{synapse} }, driver => undef, kfd => undef, render => undef, vram => undef, gtt => undef },
  mi300x  => { %{ $G{mi300x}  }, driver => undef, kfd => undef, render => undef },
);

sub working { my ( @keys ) = @_; return amd_state(nodes => [ { id => 0, gfx => 0 } ], gpus => [ @G{@keys} ]) }

# run $code against the scripted host; returns ( return value, record )
sub on {
  my ( $host, $code ) = @_;
  my $ret;
  my $rec = record_host(host => $host, code => sub { $ret = $code->() });
  return ( $ret, $rec );
}
sub warns { my ( $rec ) = @_; return [ map { $_->[1] } grep { $_->[0] eq 'warn' } @{ $rec->{logs} } ] }

#### present

subtest 'auto on a working inbox driver: present, ONE command, nothing changed' => sub {
  my ( $how, $rec ) = on(ubuntu_amd_host(state => working('synapse'), module => 'inbox'),
    sub { Rex::GPU::AMD::install_driver(gpus => [ gpu_synapse() ]) });
  is($rec->{error}, undef, 'lives');
  is($how, 'present', 'present');
  is_deeply($rec->{lines}, [ $STATE ], 'exactly one command: the state script');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... which the harness knows as read-only');
  is_deeply(warns($rec), [], 'no warning');

  ( $how, $rec ) = on(ubuntu_amd_host(state => working('synapse'), module => 'inbox'),
    sub { Rex::GPU::AMD::install_driver() });
  is($how, 'present', 'no gpus => every AMD GPU of the host: present');
  is_deeply($rec->{lines}, [ $STATE ], '... one command');

  ( $how, $rec ) = on(ubuntu_amd_host(state => working('synapse'), module => 'inbox'),
    sub { Rex::GPU::AMD->install_driver(gpus => [ { slot => '95:00.0' } ]) });
  is($how, 'present', 'as a class method, with only a short slot');
  is_deeply($rec->{lines}, [ $STATE ], '... one command');
};

subtest 'explicit method on the matching working driver: present, read-only probes only, no warning' => sub {
  my @case = (
    [ 'inbox on a working inbox APU', 'synapse', gpu_synapse(), 'inbox', 'inbox' ],
    [ 'dkms on a working DKMS Instinct', 'mi300x', gpu_mi300x(), 'dkms', 'dkms' ],
    [ 'inbox on a working inbox Instinct', 'mi300x', gpu_mi300x(), 'inbox', 'inbox' ],
  );
  for my $c (@case) {
    my ( $label, $key, $gpu, $method, $module ) = @$c;
    my ( $how, $rec ) = on(ubuntu_amd_host(state => working($key), module => $module),
      sub { Rex::GPU::AMD::install_driver(gpus => [ $gpu ], method => $method) });
    is($how, 'present', "$label: present");
    is_deeply($rec->{lines}, [ $STATE, 'run: uname -r', 'run: modinfo -n amdgpu 2>/dev/null' ],
      '... the state read, then uname -r and modinfo to tell the kind');
    is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... nothing that changes the host');
    is_deeply(warns($rec), [], '... no warning');
  }
};

subtest 'an explicit method that is not the working driver\'s kind: present + warning' => sub {
  my ( $how, $rec ) = on(ubuntu_amd_host(state => working('mi300x'), module => 'inbox'),
    sub { Rex::GPU::AMD::install_driver(gpus => [ gpu_mi300x() ], method => 'dkms') });
  is($how, 'present', 'dkms asked, inbox works: present');
  is(scalar @{ warns($rec) }, 1, 'one warning');
  like(warns($rec)->[0], qr/method => 'dkms' asked, but a working inbox amdgpu already drives the GPUs; install_driver never replaces a working driver\. Nothing was changed on the host\z/,
    '... naming the working kind');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], 'nothing changed');

  ( $how, $rec ) = on(ubuntu_amd_host(state => working('mi300x'), module => 'dkms'),
    sub { Rex::GPU::AMD::install_driver(gpus => [ gpu_mi300x() ], method => 'inbox') });
  is($how, 'present', 'inbox asked, DKMS works: present');
  like(warns($rec)->[0], qr/method => 'inbox' asked, but a working DKMS amdgpu already drives the GPUs/, '... warning names DKMS');

  ( $how, $rec ) = on(ubuntu_amd_host(state => working('mi300x'), module => 'none'),
    sub { Rex::GPU::AMD::install_driver(gpus => [ gpu_mi300x() ], method => 'dkms') });
  is($how, 'present', 'dkms asked, module path unknown (modinfo prints nothing): present');
  like(warns($rec)->[0], qr/method => 'dkms' asked, but a working amdgpu already drives/, '... warning without a kind');
};

subtest 'method dkms for an inbox-only GPU dies after the state read, also where it works' => sub {
  for my $state (working('synapse'), amd_state(amdgpu => 0, kfd => 0, gpus => [ $BROKEN{synapse} ])) {
    my ( undef, $rec ) = on(ubuntu_amd_host(state => $state),
      sub { Rex::GPU::AMD::install_driver(gpus => [ gpu_synapse() ], method => 'dkms') });
    like($rec->{error}, qr/\Ainstall_driver: method => 'dkms', but AMD supports AMD GPU 0000:95:00\.0 \[1002:1586\] \(gfx1151\) only with the distribution kernel's inbox amdgpu, not amdgpu-dkms\. Nothing was changed on the host\n?\z/,
      'dies naming the GPU and why');
    is_deeply($rec->{lines}, [ $STATE ], '... after the state read only');
  }
};

#### dies with no change

subtest 'arguments that die before ANY command' => sub {
  my $host = sub { ubuntu_amd_host(state => working('synapse')) };
  my @case = (
    [ 'invalid method',     [ method => 'both' ],            qr/\Ainstall_driver: method must be 'auto', 'inbox' or 'dkms', not 'both'\. Nothing was changed on the host\n?\z/ ],
    [ 'unknown option',     [ speed => 'fast' ],             qr/\Ainstall_driver: unknown option speed \(known: gpus, method, reboot\)\. Nothing was changed on the host\n?\z/ ],
    [ 'two unknown options', [ b => 1, a => 2 ],              qr/\Ainstall_driver: unknown options a, b /i ],
    [ 'gpus => []',         [ gpus => [] ],                  qr/\Ainstall_driver: gpus is empty; omit gpus for every AMD GPU of the host\. Nothing was changed on the host\n?\z/ ],
    [ 'gpus not an array',  [ gpus => 'all' ],               qr/gpus must be an arrayref of GPU hashrefs/ ],
    [ 'gpus of strings',    [ gpus => [ '95:00.0' ] ],       qr/gpus must be an arrayref of GPU hashrefs/ ],
    [ 'an NVIDIA GPU',      [ gpus => [ { name => 'RTX 4000', vendor => 'nvidia', device_id => '27b0' } ] ],
                            qr/RTX 4000 is vendor 'nvidia', not amd/ ],
    [ 'no slot, no id',     [ gpus => [ { name => 'X' } ] ], qr/X has neither a slot nor a device_id/ ],
    [ 'a bad slot',         [ gpus => [ { slot => '95-00' } ] ], qr/slot that is no PCI address: '95-00'/ ],
    [ 'a bad device_id',    [ gpus => [ { device_id => '15' } ] ], qr/device_id that is not four hex digits: '15'/ ],
  );
  for my $c (@case) {
    my ( $label, $args, $re ) = @$c;
    my ( undef, $rec ) = on($host->(), sub { Rex::GPU::AMD::install_driver(@$args) });
    like($rec->{error}, $re, "$label: dies");
    like($rec->{error}, qr/Nothing was changed on the host/, '... "Nothing was changed"') unless $label eq 'two unknown options';
    is_deeply($rec->{lines}, [], '... before any command');
  }
};

subtest 'states that die after the read-only probes' => sub {
  # a slot that is not on the host
  my ( undef, $rec ) = on(ubuntu_amd_host(state => working('synapse')),
    sub { Rex::GPU::AMD::install_driver(gpus => [ { slot => '0000:aa:00.0', name => 'ghost' } ]) });
  like($rec->{error}, qr/\Ainstall_driver: AMD GPU 0000:aa:00\.0 \[1002:\?\?\?\?\] is not on the host\. Nothing was changed on the host\n?\z/, 'a slot not on the host: dies');
  is_deeply($rec->{lines}, [ $STATE ], '... after the state read only');

  ( undef, $rec ) = on(ubuntu_amd_host(state => working('synapse')),
    sub { Rex::GPU::AMD::install_driver(gpus => [ { device_id => '74a1' } ]) });
  like($rec->{error}, qr/AMD GPU \[1002:74a1\] is not on the host/, 'a device ID not on the host: dies');

  # the same device ID twice, one device: the second is not on the host
  ( undef, $rec ) = on(ubuntu_amd_host(state => working('synapse')),
    sub { Rex::GPU::AMD::install_driver(gpus => [ { device_id => '1586' }, { device_id => '1586' } ]) });
  like($rec->{error}, qr/AMD GPU \[1002:1586\] is not on the host/, 'one device cannot satisfy two entries');

  ( undef, $rec ) = on(ubuntu_amd_host(state => amd_state(gpus => [])),
    sub { Rex::GPU::AMD::install_driver() });
  like($rec->{error}, qr/\Ainstall_driver: no AMD GPU found on the host \(vendor 1002, PCI class 03xx or 1200 under \/sys\/bus\/pci\/devices\)\. Nothing was changed on the host\n?\z/,
    'a host with no AMD GPU: dies');
  is_deeply($rec->{lines}, [ $STATE ], '... after the state read only');

  for my $bad ('garbage', '', amd_state(gpus => [ $G{synapse} ], end => 0)) {
    ( undef, $rec ) = on(ubuntu_amd_host(state => $bad), sub { Rex::GPU::AMD::install_driver() });
    like($rec->{error}, qr/\Ainstall_driver: could not read the AMD driver state from the host \(sysfs, KFD topology\)\. Nothing was changed on the host\n?\z/,
      'a state read that did not finish: dies');
    is_deeply($rec->{lines}, [ $STATE ], '... after the one read');
  }
};

subtest 'inbox-only and DKMS GPUs together under auto die; method inbox is the way out' => sub {
  my $both = amd_state(amdgpu => 0, kfd => 0, gpus => [ $BROKEN{synapse}, $BROKEN{mi300x} ]);
  my ( undef, $rec ) = on(ubuntu_amd_host(state => $both),
    sub { Rex::GPU::AMD::install_driver(gpus => [ gpu_synapse(), gpu_mi300x() ]) });
  like($rec->{error}, qr/\Ainstall_driver: AMD supports AMD GPU 0000:95:00\.0 \[1002:1586\] \(gfx1151\) only with the inbox driver and AMD GPU 0000:c1:00\.0 \[1002:74a1\] \(gfx942\) with amdgpu-dkms, and one amdgpu drives every GPU of a host\. Pass method => 'inbox' to drive all of them with the inbox driver\. Nothing was changed on the host\n?\z/,
    'auto: dies, naming both and the way out');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... only read-only commands ran');
  is($rec->{lines}[0], $STATE, '... after the state read');
};

#### the seam

{
  package Test::AMDSeam;
  use parent -norequire, 'Rex::GPU::AMD';
  our @SEEN;
  sub host_run {
    my ( $class, $command, %opt ) = @_;
    push @SEEN, $command;
    return $command eq Rex::GPU::AMD->state_script ? $main::SEAM_STATE : '';
  }
}

subtest 'host_run is the one seam: an override sees every command, Rex is never reached' => sub {
  local $main::SEAM_STATE = working('synapse');
  @Test::AMDSeam::SEEN = ();
  my $how = Test::AMDSeam->install_driver(gpus => [ gpu_synapse() ]);
  is($how, 'present', 'present via the subclass');
  is_deeply(\@Test::AMDSeam::SEEN, [ $STATE_CMD ], 'the override saw the one state read');

  @Test::AMDSeam::SEEN = ();
  my $v = Test::AMDSeam->verify_amd;
  is($v->{ok}, 1, 'verify_amd via the subclass');
  is_deeply(\@Test::AMDSeam::SEEN, [ $STATE_CMD ], '... one command, through the seam');

  # a bare function call follows `set gpu_amd_class`
  Rex::Config->set(gpu_amd_class => 'Test::AMDSeam');
  @Test::AMDSeam::SEEN = ();
  my $ok = eval { Rex::GPU::AMD::verify_amd(); 1 };
  my $err = $@;
  Rex::Config->set(gpu_amd_class => undef);
  die $err unless $ok;
  is(scalar @Test::AMDSeam::SEEN, 1, 'Rex::GPU::AMD::verify_amd() with set gpu_amd_class runs as that class');
};

#### verify_amd

subtest 'verify_amd on a working host' => sub {
  my ( $v, $rec ) = on(ubuntu_amd_host(state => working('synapse')), sub { Rex::GPU::AMD::verify_amd() });
  is($rec->{error}, undef, 'lives');
  is_deeply($v, { ok => 1, gpus => [ {
    slot => '0000:95:00.0', device_id => '1586', gfx_target => 'gfx1151',
    vram_bytes => '137438953472', gtt_bytes => '33535848448', kfd_node => 1, kfd_nodes => [ 1 ],
  } ] }, 'ok, and the documented per-GPU entry');
  is_deeply($rec->{lines}, [ $STATE ], 'one command, the state script');
  is_deeply(warns($rec), [], 'no warning');

  ( $v, $rec ) = on(ubuntu_amd_host(state => working('synapse')),
    sub { Rex::GPU::AMD->verify_amd(gpus => [ { device_id => '1586' } ]) });
  is($v->{ok}, 1, 'by device ID, as a class method');
};

subtest 'verify_amd lists every problem as a warning and returns ok 0' => sub {
  my @case = (
    [ 'amdgpu not loaded', amd_state(amdgpu => 0, kfd => 0, gpus => [ $BROKEN{synapse} ]),
      [ qr/the amdgpu kernel module is not loaded/, qr/no \/dev\/kfd/, qr/AMD GPU 0000:95:00\.0 \[1002:1586\] \(gfx1151\): no KFD compute node/, qr/no render node/ ] ],
    [ 'no /dev/kfd only', amd_state(kfd => 0, gpus => [ $G{synapse} ]),
      [ qr/no \/dev\/kfd \(the ROCm compute interface of amdgpu\)/ ] ],
    [ 'no KFD node for the GPU', amd_state(gpus => [ { %{ $G{synapse} }, kfd => undef } ]),
      [ qr/AMD GPU 0000:95:00\.0 \[1002:1586\] \(gfx1151\): no KFD compute node/ ] ],
    [ 'a CPU-only node (gfx_target_version 0) is no GPU node', amd_state(nodes => [ { id => 0, gfx => 0 } ], gpus => [ { %{ $G{synapse} }, kfd => undef } ]),
      [ qr/no KFD compute node/ ] ],
    [ 'no render node', amd_state(gpus => [ { %{ $G{synapse} }, render => undef } ]),
      [ qr/AMD GPU 0000:95:00\.0 \[1002:1586\] \(gfx1151\): no render node/ ] ],
  );
  for my $c (@case) {
    my ( $label, $state, $res ) = @$c;
    my ( $v, $rec ) = on(ubuntu_amd_host(state => $state), sub { Rex::GPU::AMD::verify_amd() });
    is($rec->{error}, undef, "$label: never dies");
    is($v->{ok}, 0, '... ok 0');
    my @w = grep { /^  AMD: / } @{ warns($rec) };
    is(scalar @w, scalar @$res, '... '.scalar(@$res).' problem warning(s)');
    like($w[$_], $res->[$_], '... problem '.($_ + 1)) for 0 .. $#$res;
    is_deeply($rec->{lines}, [ $STATE ], '... one command');
  }
  my ( $v ) = on(ubuntu_amd_host(state => amd_state(amdgpu => 0, kfd => 0, gpus => [ $BROKEN{synapse} ])), sub { Rex::GPU::AMD::verify_amd() });
  is_deeply($v->{gpus}, [ { slot => '0000:95:00.0', device_id => '1586', gfx_target => 'gfx1151',
    vram_bytes => undef, gtt_bytes => undef, kfd_node => undef, kfd_nodes => [] } ],
    'the entry still lists the GPU: the table\'s gfx target, undef for what is not there');
};

subtest 'verify_amd(gpus => [subset]) judges only those' => sub {
  my $two = amd_state(gpus => [ $G{navi31}, { %{ $G{mi300x} }, kfd => undef, render => undef } ]);
  my $host = sub { ubuntu_amd_host(state => $two) };
  my ( $v ) = on($host->(), sub { Rex::GPU::AMD::verify_amd(gpus => [ gpu_navi31() ]) });
  is($v->{ok}, 1, 'the working GPU alone: ok');
  is_deeply([ map { $_->{slot} } @{ $v->{gpus} } ], [ '0000:0a:00.0' ], '... one entry');
  ( $v ) = on($host->(), sub { Rex::GPU::AMD::verify_amd(gpus => [ gpu_mi300x() ]) });
  is($v->{ok}, 0, 'the broken GPU alone: not ok');
  is_deeply([ map { $_->{slot} } @{ $v->{gpus} } ], [ '0000:c1:00.0' ], '... one entry');
  ( $v ) = on($host->(), sub { Rex::GPU::AMD::verify_amd() });
  is($v->{ok}, 0, 'no gpus: every AMD GPU of the host is judged: not ok');
  is_deeply([ map { $_->{slot} } @{ $v->{gpus} } ], [ '0000:0a:00.0', '0000:c1:00.0' ], '... both entries, in PCI order');
  ( $v ) = on($host->(), sub { Rex::GPU::AMD::verify_amd(gpus => [ gpu_mi300x(), gpu_navi31() ]) });
  is_deeply([ map { $_->{slot} } @{ $v->{gpus} } ], [ '0000:c1:00.0', '0000:0a:00.0' ], 'entries in the order given');
};

subtest 'verify_amd: a GPU not on the host, and a partitioned GPU' => sub {
  my ( $v, $rec ) = on(ubuntu_amd_host(state => working('synapse')),
    sub { Rex::GPU::AMD::verify_amd(gpus => [ { slot => '0000:aa:00.0' } ]) });
  is($v->{ok}, 0, 'not on the host: ok 0');
  is_deeply($v->{gpus}, [ { slot => '0000:aa:00.0', device_id => undef, gfx_target => undef,
    vram_bytes => undef, gtt_bytes => undef, kfd_node => undef, kfd_nodes => [] } ], '... undef everywhere but the slot');
  ok(( grep { /not on the host/ } @{ warns($rec) } ), '... a warning says so');

  # an MI300X in a partition mode: two KFD nodes at one PCI address
  my %node = (gfx => 90402, vendor_id => 4098, device_id => 0x74a1, location_id => 0xc100, domain => 0, render => 128);
  my $parted = amd_state(gpus => [ { %{ $G{mi300x} }, kfd => undef } ], nodes => [ { id => 2, %node }, { id => 3, %node, render => 129 } ]);
  ( $v ) = on(ubuntu_amd_host(state => $parted), sub { Rex::GPU::AMD::verify_amd() });
  is($v->{ok}, 1, 'partitioned MI300X: ok');
  is_deeply([ @{ $v->{gpus}[0] }{qw( kfd_node kfd_nodes gfx_target )} ], [ 2, [ 2, 3 ], 'gfx942' ], '... the lowest node, all nodes, gfx942');
};

subtest 'verify_amd never dies' => sub {
  for my $case (
    [ 'unreadable state', ubuntu_amd_host(state => 'garbage'), [], qr/could not read the AMD driver state from the host/ ],
    [ 'gpus => []', ubuntu_amd_host(state => working('synapse')), [ gpus => [] ], qr/\Averify_amd: gpus is empty; omit gpus for every AMD GPU of the host\.\z/ ],
    [ 'malformed gpus', ubuntu_amd_host(state => working('synapse')), [ gpus => 'x' ], qr/\Averify_amd: gpus must be an arrayref/ ],
    [ 'unknown option', ubuntu_amd_host(state => working('synapse')), [ speed => 1 ], qr/\Averify_amd: unknown option speed \(known: gpus\)/ ],
  ) {
    my ( $label, $host, $args, $re ) = @$case;
    my ( $v, $rec ) = on($host, sub { Rex::GPU::AMD::verify_amd(@$args) });
    is($rec->{error}, undef, "$label: no die");
    is_deeply($v, { ok => 0, gpus => [] }, '... { ok => 0, gpus => [] }');
    ok(( grep { $_ =~ $re } @{ warns($rec) } ), '... the warning');
  }
  my ( undef, $rec ) = on(ubuntu_amd_host(state => working('synapse')), sub { Rex::GPU::AMD::verify_amd(gpus => []) });
  is_deeply($rec->{lines}, [], 'gpus => []: no command at all');
};

done_testing;
