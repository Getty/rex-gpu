use strict;
use warnings;
use Test::More;

use FindBin qw( $Bin );
use lib "$Bin/lib";

# -----------------------------------------------------------------------------
# NVLink platforms Rex::GPU does not set up (karr #49).
#
# CLAIMS:
#   * Setup->nvlink_platforms maps the GPUs' device IDs, and nothing else:
#     B200 2901/2909 and B300 3182 => hgx-nvlink5, GB200 2941 and GB300
#     31c2/31c3 => nvl72, each platform once however many GPUs; H100, RTX
#     5090, no GPU => nothing. A subclass can override the ID list;
#   * an HGX B200/B300 has no nvswitch (t/93 checks detection), so
#     install_driver runs no Fabric Manager step: its transcript is exactly
#     the RTX 5090's (same open >= 570 / >= 580 source) plus ONE read-only
#     systemctl is-active of nvidia-fabricmanager.service, at the end;
#   * the Fabric Manager / nvlsm / OFED warning is logged exactly once, on a
#     fresh install and on an already-installed driver, and names whether the
#     unit is active; it does not make install_driver die;
#   * GB200: only the nvidia-imex info line, no warning, no extra command;
#     H100 without nvswitches: none of this.
#
# NOT covered -- none of it runs without a real HGX B200/B300 or GB200 host:
# that 2901/2909/3182/2941/31c2/31c3 are the IDs lspci reports there, that the
# unit name is right on those hosts, and that Fabric Manager + nvlsm + OFED
# actually bring the fabric up.
# -----------------------------------------------------------------------------

use Test::RexGPU::Golden qw(
  record_host golden_is host_profile gpu_fixture mutating_lines working_driver
);
use Rex::GPU::NVIDIA;
use Rex::GPU::NVIDIA::Setup;

my $IS_ACTIVE = 'run: systemctl is-active --quiet nvidia-fabricmanager.service';
my $WARN_RE   = qr/^HGX B200\/B300 \(NVLink 5\): NVSwitches are not PCIe devices here/;
my $IMEX_RE   = qr/^GB200\/GB300 NVL72 compute tray: multi-node NVLink needs nvidia-imex/;

sub platforms_of {
  my ( @ids ) = @_;
  return [ Rex::GPU::NVIDIA::Setup->new(gpus => [ map { { device_id => $_ } } @ids ])->nvlink_platforms ];
}

sub driver {
  my ( $host, @gpus ) = @_;
  return record_host(host => $host, code => sub { Rex::GPU::NVIDIA::install_driver(gpus => [ @gpus ]) });
}

sub logs_like {
  my ( $rec, $re ) = @_;
  return [ grep { $_->[1] =~ $re } @{ $rec->{logs} } ];
}

#### Pure mapping

subtest 'nvlink_platforms by device ID' => sub {
  is_deeply(platforms_of(('2901') x 8), [ 'hgx-nvlink5' ], '8x B200 2901: hgx-nvlink5 once');
  is_deeply(platforms_of('2909'), [ 'hgx-nvlink5' ], 'B200 2909');
  is_deeply(platforms_of('3182'), [ 'hgx-nvlink5' ], 'B300 3182');
  is_deeply(platforms_of('2941'), [ 'nvl72' ], 'GB200 2941');
  is_deeply(platforms_of('31C2', '31c3'), [ 'nvl72' ], 'GB300 31C2/31c3, any case');
  is_deeply(platforms_of('2330'), [], 'H100: none');
  is_deeply(platforms_of('2b85'), [], 'RTX 5090 (Blackwell, not HGX): none');
  is_deeply(platforms_of(undef), [], 'no device_id: none');
  is_deeply(platforms_of(), [], 'no GPU: none');
  is_deeply(
    [ Rex::GPU::NVIDIA::Setup->new(gpus => [ 'junk', { device_id => '2901' } ])->nvlink_platforms ],
    [ 'hgx-nvlink5' ], 'non-hashref elements are ignored');

  {
    package My::Setup::NoHGX;
    use Moo;
    extends 'Rex::GPU::NVIDIA::Setup';
    sub nvlink_platform_ids { () }
  }
  is_deeply([ My::Setup::NoHGX->new(gpus => [ { device_id => '2901' } ])->nvlink_platforms ], [],
    'a subclass overrides the ID list');
};

#### install_driver on HGX B200 / B300

for my $case (
  [ 'ubuntu-24.04', 'b200', 'blackwell' ],
  [ 'rocky-9',      'b200', 'blackwell' ],
  [ 'ubuntu-24.04', 'b300', undef ]
) {
  my ( $os, $gpu, $twin ) = @$case;
  # systemctl is-active exits 3 for an inactive or unknown unit
  my $rec = driver(host_profile($os, responses => [
    [ 'systemctl is-active --quiet nvidia-fabricmanager.service' => '', 3 ]
  ]), ( gpu_fixture($gpu) ) x 8);
  is($rec->{error}, undef, "$os 8x $gpu: lives");
  golden_is($rec, "driver/$os--hgx-$gpu");

  my @lines = @{ $rec->{lines} };
  is((grep { $_ eq $IS_ACTIVE } @lines), 1, '... one systemctl is-active');
  is($lines[-1], $IS_ACTIVE, '... and it is the last host command');
  ok(!(grep { /fabricmanager/ && $_ ne $IS_ACTIVE } @lines),
    '... no Fabric Manager install, enable or start (no nvswitches, not the k23 path)');
  if (defined $twin) {
    my $plain = driver(host_profile($os), gpu_fixture($twin));
    is_deeply([ @lines[0 .. $#lines - 1] ], $plain->{lines},
      "... otherwise exactly the $twin install");
  }

  my $warn = logs_like($rec, $WARN_RE);
  is(scalar @$warn, 1, '... the warning once, not per GPU');
  is($warn->[0][0], 'warn', '... at warn level');
  like($warn->[0][1], qr/nvlsm.*libibumad3, infiniband-diags.*kernel >= 5\.17.*cudaErrorSystemNotReady/,
    '... naming nvlsm, OFED, the kernel and the CUDA error');
  like($warn->[0][1], qr/\(nvidia-fabricmanager\.service is not active\)$/, '... and the inactive unit');
  is(scalar @{ logs_like($rec, $IMEX_RE) }, 0, '... no IMEX note');
}

{
  my $rec = driver(host_profile('ubuntu-24.04', responses => [
    [ 'systemctl is-active --quiet nvidia-fabricmanager.service' => '', 0 ]
  ]), ( gpu_fixture('b200') ) x 8);
  my $warn = logs_like($rec, $WARN_RE);
  is(scalar @$warn, 1, 'Fabric Manager active: still warns once');
  like($warn->[0][1], qr/\(nvidia-fabricmanager\.service is active; nvlsm, OFED\/MOFED and the kernel were not checked\)$/,
    '... saying the unit is active and what was not checked');
}

{
  my $rec = driver(host_profile('ubuntu-24.04', responses => [ working_driver() ]),
    ( gpu_fixture('b200') ) x 8);
  is($rec->{error}, undef, 'HGX B200, driver already installed: lives');
  is_deeply($rec->{lines}, [
    'run: nvidia-smi -L 2>&1',
    q{run: /sbin/ldconfig -p 2>/dev/null | grep -q '^[[:space:]]*libcuda\.so\.1 '},
    $IS_ACTIVE
  ], '... only the probes and is-active');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... all read-only');
  is(scalar @{ logs_like($rec, $WARN_RE) }, 1, '... the warning once');
}

#### GB200 compute tray, H100

{
  my $rec = driver(host_profile('ubuntu-24.04'), ( gpu_fixture('gb200') ) x 4);
  is($rec->{error}, undef, 'GB200: lives');
  ok(!(grep { /fabricmanager/ } @{ $rec->{lines} }), '... no Fabric Manager command');
  is_deeply($rec->{lines}, driver(host_profile('ubuntu-24.04'), gpu_fixture('blackwell'))->{lines},
    '... exactly the RTX 5090 install');
  my $imex = logs_like($rec, $IMEX_RE);
  is(scalar @$imex, 1, '... the IMEX note once');
  is($imex->[0][0], 'info', '... at info level');
  is(scalar @{ logs_like($rec, $WARN_RE) }, 0, '... no HGX warning');
}

{
  my $rec = driver(host_profile('ubuntu-24.04'), ( gpu_fixture('h100') ) x 8);
  is($rec->{error}, undef, 'H100 without nvswitches: lives');
  ok(!(grep { /fabricmanager/ } @{ $rec->{lines} }), '... no Fabric Manager command');
  is(scalar @{ logs_like($rec, qr/NVLink|nvidia-imex/) }, 0, '... none of these messages');
}

done_testing;
