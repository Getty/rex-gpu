#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# -----------------------------------------------------------------------------
# Rex::GPU::AMD::Hardware lookups (karr k1): PCI device ID -> gfx target ->
# compute / integrated / driver. Pure functions, no host.
#
# CLAIMS (spot checks of the curator's rows, not the table):
#   * 1586 -> gfx1151, compute 1, integrated 1, driver inbox (Strix Halo APU);
#     74a1 -> gfx942 compute 1 integrated 0 driver dkms (MI300X); 75a0 ->
#     gfx950; 7408 -> gfx90a; 744c -> gfx1100; 66af -> gfx906 compute 0
#     (known, not ROCm-capable); 164e and 1902 -> no row (undef);
#   * a device ID is matched with or without 0x, in any case; anything that is
#     no four hex digits, and undef, has no row;
#   * gfx_target_from_version decodes the KFD gfx_target_version
#     (110501 -> gfx1151, 90402 -> gfx942, 100306 -> gfx1036, 90010 -> gfx90a);
#     0 (a CPU node), undef, text and a minor/stepping above 15 -> undef;
#   * resolve: the KFD target wins over the table, with a warning naming both
#     when they differ and none when they agree; gfx1036 from KFD -> compute 0
#     whatever the device ID says; no target at all -> every verdict undef
#     (unknown, never 0);
#   * table consistency: every device ID is four lowercase hex digits, listed
#     once, and every device row names a gfx target that has a target row.
#
# NOT covered: that any row is TRUE -- the rows are the hardware curator's,
# cited from AMD's matrix, the kernel and libdrm; this file reads four of
# them back and checks the table does not contradict itself. Whether a GPU
# with a row really runs ROCm, and with that driver, needs the GPU.
# -----------------------------------------------------------------------------

use Rex::GPU::AMD::Hardware;

my $H = 'Rex::GPU::AMD::Hardware';

sub logged {
  my ( $code ) = @_;
  my @warn;
  no warnings 'redefine';
  local *Rex::Logger::info = sub { push @warn, [ $_[1] // 'info', $_[0] ] };
  $code->();
  return @warn;
}

subtest 'device rows (spot checks)' => sub {
  my %want = (
    '1586' => [ 'gfx1151', 1, 1, 'inbox' ],
    '74a1' => [ 'gfx942',  1, 0, 'dkms'  ],
    '75a0' => [ 'gfx950',  1, 0, 'dkms'  ],
    '7408' => [ 'gfx90a',  1, 0, 'dkms'  ],
    '744c' => [ 'gfx1100', 1, 0, 'dkms'  ],
    '66af' => [ 'gfx906',  0, 0, undef   ],
  );
  for my $id (sort keys %want) {
    my ( $gfx, $compute, $integrated, $driver ) = @{ $want{$id} };
    is($H->gfx_target_for_device_id($id), $gfx, "$id -> $gfx");
    my $hw = $H->resolve(device_id => $id);
    is_deeply([ @{$hw}{qw( gfx_target compute integrated driver )} ],
      [ $gfx, $compute, $integrated, $driver ], "... compute $compute, integrated $integrated, driver ".( $driver // 'undef' ));
  }
  for my $id (qw( 164e 1902 )) {
    is($H->for_device_id($id), undef, "$id has no device row");
    is_deeply($H->resolve(device_id => $id),
      { gfx_target => undef, compute => undef, integrated => undef, driver => undef, family => undef },
      '... resolve: every verdict undef (unknown), not 0');
  }
};

subtest 'device ID spelling' => sub {
  is($H->gfx_target_for_device_id('0x1586'), 'gfx1151', '0x1586');
  is($H->gfx_target_for_device_id('74A1'), 'gfx942', 'upper case');
  is($H->gfx_target_for_device_id("1586\n"), 'gfx1151', 'trailing newline');
  for my $bad ( undef, '', '158', '15866', 'zzzz', '0x15', 'gfx1151' ) {
    is($H->for_device_id($bad), undef, 'no row for '.( defined $bad ? "'$bad'" : 'undef' ));
  }
  is($H->target('GFX1151')->{gfx_target}, 'gfx1151', 'target(): case does not matter');
  is($H->target('1151'), undef, 'target(): not a gfx name');
};

subtest 'gfx_target_from_version' => sub {
  my %want = ( 110501 => 'gfx1151', 90402 => 'gfx942', 100306 => 'gfx1036', 90010 => 'gfx90a',
               90006 => 'gfx906', 120001 => 'gfx1201' );
  is($H->gfx_target_from_version($_), $want{$_}, "$_ -> $want{$_}") for sort keys %want;
  is($H->gfx_target_from_version($_), undef, 'undef for '.( $_ // 'undef' ))
    for 0, undef, 'x', '', -1, 91600, 90016;
};

subtest 'resolve: the running driver wins over the table' => sub {
  my $hw;
  my @warn = logged(sub {
    $hw = $H->resolve(device_id => '1586', kfd_gfx_target => 'gfx1151', name => 'synapse');
  });
  is($hw->{gfx_target}, 'gfx1151', 'agreeing KFD and table');
  is_deeply(\@warn, [], '... no warning');

  @warn = logged(sub {
    $hw = $H->resolve(device_id => '7550', kfd_gfx_target => 'gfx1036', name => 'odd');
  });
  is($hw->{gfx_target}, 'gfx1036', 'KFD gfx1036 on a table gfx1201 ID: KFD wins');
  is($hw->{compute}, 0, '... gfx1036 is not ROCm-capable');
  is($hw->{integrated}, 1, '... integrated (Raphael/Mendocino iGPU)');
  is(scalar(@warn), 1, 'one warning');
  is($warn[0][0], 'warn', '... a warning');
  like($warn[0][1], qr/KFD\) reports gfx1036, the device table says gfx1201 -- using gfx1036/,
    '... naming both targets');

  # KFD only, no table row for the ID: the target row alone decides
  @warn = logged(sub { $hw = $H->resolve(device_id => '164e', kfd_gfx_target => 'gfx1036') });
  is_deeply([ @{$hw}{qw( gfx_target compute integrated )} ], [ 'gfx1036', 0, 1 ], 'ID without a row, KFD gfx1036 -> compute 0, integrated 1');
  is_deeply(\@warn, [], '... no warning (nothing to disagree with)');

  # a gfx target without a target row: the target is kept, the verdict unknown
  $hw = $H->resolve(device_id => '1902', kfd_gfx_target => 'gfx9999');
  is($hw->{gfx_target}, 'gfx9999', 'unknown gfx target is still reported');
  is_deeply([ @{$hw}{qw( compute integrated driver )} ], [ undef, undef, undef ], '... compute undef (unknown), never 0');
};

subtest 'table consistency' => sub {
  my ( %seen, @dup, @bad, @orphan );
  for my $row ($H->devices) {
    for my $id (@{ $row->{ids} }) {
      push @bad, $id unless $id =~ /\A[0-9a-f]{4}\z/;
      push @dup, $id if $seen{$id}++;
    }
    push @orphan, $row->{gfx_target} unless $H->target($row->{gfx_target});
  }
  is_deeply(\@bad, [], 'every device ID is four lowercase hex digits');
  is_deeply(\@dup, [], 'no device ID listed twice (the first row would silently win)');
  is_deeply(\@orphan, [], 'every device row names a gfx target with a target row');
  my ( %t, @dupt );
  for my $row ($H->targets) { push @dupt, $row->{gfx_target} if $t{ $row->{gfx_target} }++ }
  is_deeply(\@dupt, [], 'no gfx target row twice');
  cmp_ok(scalar(keys %seen), '>', 100, 'a table of real size (not emptied)');
};

done_testing;
