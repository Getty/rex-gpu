use strict;
use warnings;
use Test::More;

# -----------------------------------------------------------------------------
# Unit tests for Rex::GPU::NVIDIA::Requirement (karr #30, epic karr #25).
#
# Pure value object, no run/dpkg/rpm. Claims pinned here:
#   * the generation table at every range boundary (and the IDs just outside)
#   * satisfied_by: kernel module x branch bounds, unknowns never pass a bound
#   * intersect: either/min/max combine, conflicts croak naming both sides
#   * a subclass overriding `generations` adds a row without touching the base
#   * the table never makes a GPU compute (Detect::_is_nvidia_compute unchanged)
#
# NOT covered: nothing in Rex::GPU::NVIDIA's install paths reads the object
# yet (only the two Detect wrappers, pinned by t/80 and t/95), so none of this
# says anything about which driver a real host gets.
# -----------------------------------------------------------------------------

use Rex::GPU::Detect;
use Rex::GPU::NVIDIA::Requirement;

my $R = 'Rex::GPU::NVIDIA::Requirement';

sub shape {
  my ( $req ) = @_;
  return [ map { $req->$_ } qw( generation kernel_module min_branch max_branch ) ];
}

my $UNKNOWN = [ undef, 'either', undef, undef ];
my $BW      = [ 'Blackwell', 'open', 570, undef ];
my $BWU     = [ 'Blackwell Ultra', 'open', 580, undef ];
my $MPV     = [ 'Maxwell/Pascal/Volta', 'proprietary', undef, 580 ];
my $KEP     = [ 'Kepler or older', 'proprietary', undef, 470 ];

subtest 'generation table at the range boundaries' => sub {
  my %want = (
    '0000' => $KEP, '0020' => $KEP, '102d' => $KEP, '133f' => $KEP,
    '1340' => $MPV, '1db4' => $MPV, '1DB4' => $MPV, '1df6' => $MPV,
    '1df7' => $UNKNOWN, '1e02' => $UNKNOWN, '2330' => $UNKNOWN, '28f8' => $UNKNOWN,
    '28ff' => $UNKNOWN,
    '2900' => $BW, '2901' => $BW, '2e12' => $BW, '2E12' => $BW, '2fff' => $BW,
    '3000' => $UNKNOWN, '3181' => $UNKNOWN,
    '3182' => $BWU,
    '3183' => $UNKNOWN, '31c1' => $UNKNOWN,
    '31c2' => $BWU, '31c3' => $BWU,
    '31c4' => $UNKNOWN, 'ffff' => $UNKNOWN
  );
  for my $id ( sort keys %want ) {
    my $req = $R->for_device_id($id);
    is_deeply( shape($req), $want{$id}, $id.' => '.( $want{$id}[0] // 'unknown' ) );
    is( $req->device_id, lc $id, $id.' => device_id normalised to lowercase' );
  }
  for my $bad ( undef, '', '1db', 'zzzz', '1db40', '2b85x' ) {
    my $req = $R->for_device_id($bad);
    is_deeply( shape($req), $UNKNOWN, 'malformed '.( $bad // 'undef' ).' => unknown' );
    is( $req->device_id, undef, '... with no device_id' );
  }
};

subtest 'from_gpu' => sub {
  my $req = $R->from_gpu({ name => 'GV100GL [Tesla V100 PCIe 32GB]', device_id => '1db6' });
  is_deeply( shape($req), $MPV, 'V100 hashref => Maxwell/Pascal/Volta' );
  is( $req->name, 'GV100GL [Tesla V100 PCIe 32GB]', 'name carried for messages' );
  is_deeply( shape( $R->from_gpu({}) ), $UNKNOWN, 'no device_id => unknown' );
  ok( !eval { $R->from_gpu(undef); 1 }, 'undef dies' );
  like( $@, qr/needs a GPU hashref/, '... saying what it needs' );
  ok( !eval { $R->from_gpu('1db4'); 1 }, 'a bare ID string dies' );
};

subtest 'constructor validation' => sub {
  ok( !eval { $R->new( kernel_module => 'nouveau' ); 1 }, 'unknown kernel_module dies' );
  ok( !eval { $R->new( kernel_module => undef ); 1 },     'undef kernel_module dies' );
  ok( !eval { $R->new( min_branch => '580.95' ); 1 },     'non-integer branch dies' );
  ok( !eval { $R->new( device_id => '2E12' ); 1 },        'uppercase device_id via new dies' );
  ok( !eval { $R->new( min_branch => 590, max_branch => 580 ); 1 }, 'min above max dies' );
  like( $@, qr/min_branch 590 is above max_branch 580/, '... naming both' );
  is_deeply( shape( $R->new ), $UNKNOWN, 'defaults: either, no bounds' );
};

subtest 'satisfied_by' => sub {
  my $open    = { kernel_module => 'open',        branch => 580 };
  my $prop    = { kernel_module => 'proprietary', branch => 580 };
  my $open570 = { kernel_module => 'open',        branch => 570 };
  my $open565 = { kernel_module => 'open',        branch => 565 };
  my $prop595 = { kernel_module => 'proprietary', branch => 595 };
  my $prop470 = { kernel_module => 'proprietary', branch => 470 };
  my $open_nobranch = { kernel_module => 'open' };
  my $nomodule      = { branch => 580 };

  my @matrix = (
    # requirement,              source,          want
    [ $R->new,                  $open,           1 ],
    [ $R->new,                  $prop,           1 ],
    [ $R->new,                  $open_nobranch,  1 ],
    [ $R->new,                  $nomodule,       1 ],
    [ $R->for_device_id('2901'), $open,          1 ],
    [ $R->for_device_id('2901'), $open570,       1 ],
    [ $R->for_device_id('2901'), $open565,       0 ],
    [ $R->for_device_id('2901'), $prop,          0 ],
    [ $R->for_device_id('2901'), $open_nobranch, 0 ],
    [ $R->for_device_id('2901'), $nomodule,      0 ],
    [ $R->for_device_id('3182'), $open570,       0 ],
    [ $R->for_device_id('3182'), $open,          1 ],
    [ $R->for_device_id('1db4'), $prop,          1 ],
    [ $R->for_device_id('1db4'), $prop470,       1 ],
    [ $R->for_device_id('1db4'), $prop595,       0 ],
    [ $R->for_device_id('1db4'), $open,          0 ],
    [ $R->for_device_id('102d'), $prop470,       1 ],
    [ $R->for_device_id('102d'), $prop,          0 ],
    [ $R->for_device_id('27b0'), $prop595,       1 ],
    [ $R->for_device_id('27b0'), $open565,       1 ]
  );
  for my $row (@matrix) {
    my ( $req, $src, $want ) = @$row;
    is( $req->satisfied_by($src), $want,
      ( $req->device_id // 'unbound' ).' ('.$req->describe.') vs '
      .( $src->{kernel_module} // '?' ).'/'.( $src->{branch} // '?' ).' => '.$want );
  }
  ok( !eval { $R->new->satisfied_by(undef); 1 }, 'undef source dies' );
  ok( !eval { $R->new->satisfied_by({ kernel_module => 'open', branch => '580.95.05' }); 1 },
    'full version string as branch dies' );
};

subtest 'intersect' => sub {
  my $v100 = $R->from_gpu({ name => 'Tesla V100', device_id => '1db4' });
  my $p100 = $R->from_gpu({ name => 'Tesla P100', device_id => '15f8' });
  my $k80  = $R->from_gpu({ name => 'Tesla K80',  device_id => '102d' });
  my $b200 = $R->from_gpu({ name => 'B200',       device_id => '2901' });
  my $b300 = $R->from_gpu({ name => 'B300',       device_id => '3182' });
  my $h100 = $R->from_gpu({ name => 'H100',       device_id => '2330' });

  is( $R->intersect($v100), $v100, 'one requirement comes back unchanged' );

  my $bw = $R->intersect( $b200, $h100 );
  is_deeply( [ @{ shape($bw) }[ 1 .. 3 ] ], [ 'open', 570, undef ], 'either + open => open' );
  is( $bw->generation, undef, 'combined has no generation' );
  is_deeply( $bw->members, [ $b200, $h100 ], 'members lists the inputs' );

  my $bwu = $R->intersect( $b200, $b300 );
  is( $bwu->min_branch, 580, 'min_branch is the highest lower bound' );

  my $old = $R->intersect( $v100, $k80 );
  is_deeply( [ @{ shape($old) }[ 1 .. 3 ] ], [ 'proprietary', undef, 470 ],
    'max_branch is the lowest upper bound' );

  is_deeply( [ @{ shape( $R->intersect( $h100, $h100 ) ) }[ 1 .. 3 ] ],
    [ 'either', undef, undef ], 'either + either => either, no bounds' );

  my $nested = $R->intersect( $R->intersect( $v100, $p100 ), $h100 );
  is_deeply( $nested->members, [ $v100, $p100, $h100 ], 'nested intersections flatten' );
  is( $nested->max_branch, 580, '... and keep their bounds' );

  my $inst = $b200->intersect($b300);
  is_deeply( $inst->members, [ $b200, $b300 ], 'object invocant is one of the requirements' );

  ok( !eval { $R->intersect( $v100, $b200 ); 1 }, 'V100 + B200 dies' );
  like( $@, qr/no single NVIDIA driver supports all GPUs/, '... says why' );
  like( $@, qr/B200 \(Blackwell, 10de:2901\) needs the open kernel module/, '... names the open side' );
  like( $@, qr/Tesla V100 \(Maxwell\/Pascal\/Volta, 10de:1db4\) needs the proprietary one/,
    '... names the proprietary side' );

  ok( !eval { $v100->intersect($b200); 1 }, 'same conflict via object invocant' );

  my $new_only = $R->new( name => 'Future GPU', min_branch => 590 );
  ok( !eval { $R->intersect( $new_only, $h100, $v100 ); 1 },
    'min 590 + max 580 dies (branch conflict, no module conflict)' );
  like( $@, qr/Future GPU needs driver branch 590 or newer, but Tesla V100 .* up to branch 580/,
    '... naming both bounds' );

  ok( !eval { $R->intersect( $new_only, $b200, $v100 ); 1 }, 'both conflicts at once' );
  like( $@, qr/open kernel module.*; .*branch 590 or newer/, '... reports both' );

  ok( !eval { $R->intersect; 1 }, 'empty list dies' );
  ok( !eval { $R->intersect( $v100, { kernel_module => 'open' } ); 1 }, 'a hashref dies' );
};

subtest 'subclass overrides generations' => sub {
  {
    package My::Test::Requirement;
    use Moo;
    extends 'Rex::GPU::NVIDIA::Requirement';
    sub generations {
      my ( $self ) = @_;
      return (
        { generation => 'Hopper (site)', first => 0x2330, last => 0x2330,
          kernel_module => 'open', min_branch => 575 },
        $self->SUPER::generations
      );
    }
  }
  my $h100 = My::Test::Requirement->for_device_id('2330');
  isa_ok( $h100, 'My::Test::Requirement' );
  is_deeply( shape($h100), [ 'Hopper (site)', 'open', 575, undef ], 'added row wins' );
  is_deeply( shape( My::Test::Requirement->for_device_id('1db4') ), $MPV, 'built-in rows kept' );
  is_deeply( shape( $R->for_device_id('2330') ), $UNKNOWN, 'base class unaffected' );
  isa_ok( My::Test::Requirement->intersect( $h100, $h100 ), 'My::Test::Requirement' );
};

subtest 'the table never makes a GPU compute' => sub {
  # Blackwell and pre-Turing IDs with a name no rule knows: still not compute.
  for my $id (qw( 2901 2b85 3182 1db4 102d )) {
    is( Rex::GPU::Detect::_is_nvidia_compute( '0300', 'Device', $id ), 0,
      $id.' as VGA "Device" => not compute' );
  }
  is( Rex::GPU::Detect::_is_nvidia_compute( '0300', 'Device', '2e12' ), 1,
    'GB10 still compute via the Detect allowlist' );
};

done_testing;
