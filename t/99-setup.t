use strict;
use warnings;
use Test::More;

use FindBin qw( $Bin );
use lib "$Bin/lib";

# -----------------------------------------------------------------------------
# Unit tests for the Setup classes (karr #31, T2 of epic #25):
# Rex::GPU::NVIDIA::Setup, ::Setup::Apt, ::Setup::Debian, ::Setup::Ubuntu.
#
# CLAIMS:
#   * install runs its steps in the fixed order and stops after
#     already_installed when a driver works;
#   * plan only reads the host: for every Debian/Ubuntu profile x GPU it
#     emits no mutating command (Golden.pm's read-only list), and a Blackwell
#     on a Debian release without a CUDA repo dies inside plan;
#   * facts passed to new() are not read from the host;
#   * run_cmd is the seam: a subclass that overrides it sees every command;
#   * a subclass overriding one step changes exactly that step;
#   * setup_class_for_os picks Debian / Ubuntu / none by OS.
# That install_driver still emits the same commands is t/96's job (goldens).
#
# NOT covered: anything a real host does with these commands -- none of this
# runs apt, dpkg or a GPU.
# -----------------------------------------------------------------------------

use Test::RexGPU::Golden qw( record_host host_profile gpu_fixture mutating_lines );
use Rex::GPU::NVIDIA;

my $APT  = 'Rex::GPU::NVIDIA::Setup::Apt';
my $DEB  = 'Rex::GPU::NVIDIA::Setup::Debian';
my $UBU  = 'Rex::GPU::NVIDIA::Setup::Ubuntu';

#### Class layout

isa_ok($APT, 'Rex::GPU::NVIDIA::Setup');
isa_ok($DEB, $APT);
isa_ok($UBU, $APT);

#### setup_class_for_os

{
  my %want = (
    'debian-12'    => $DEB,
    'debian-13'    => $DEB,
    'ubuntu-24.04' => $UBU,
    'rocky-9'      => undef,
    'leap-15.6'    => undef
  );
  for my $os (sort keys %want) {
    my $class;
    my $rec = record_host(host => host_profile($os),
      code => sub { $class = Rex::GPU::NVIDIA->setup_class_for_os });
    is($class, $want{$os}, "$os => ".($want{$os} // 'no Setup class'));
    is_deeply($rec->{lines}, [], "$os: resolving the class runs nothing");
  }
}

#### plan only reads the host

for my $os (qw( debian-12 debian-13 ubuntu-22.04 ubuntu-24.04 )) {
  my $class = $os =~ /^ubuntu/ ? $UBU : $DEB;
  for my $g (qw( ada blackwell volta none )) {
    my $plan;
    my $rec = record_host(host => host_profile($os),
      code => sub { $plan = $class->new(gpu => gpu_fixture($g))->plan });
    is($rec->{error}, undef, "$os + $g: plan lives");
    is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], "$os + $g: plan emits only read-only probes");
    ok(@{ $plan->{packages} } && @{ $plan->{verify} }, "$os + $g: packages and verify filled");
  }
}

{
  my $rec = record_host(host => host_profile('debian-12', release => '11.11'),
    code => sub { $DEB->new(gpu => gpu_fixture('blackwell'))->plan });
  like($rec->{error}, qr/CUDA repo only covers Debian 12 and 13/, 'debian-11 + Blackwell dies in plan');
  is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], '... before any change');

  $rec = record_host(host => host_profile('debian-12'),
    code => sub { $DEB->new(gpu => gpu_fixture('kepler'))->plan });
  like($rec->{error}, qr/Kepler or older.*Nothing was changed/, 'Kepler dies in plan');
  is_deeply($rec->{lines}, [], '... before any host interaction');
}

#### Injected facts are not read

{
  my $plan;
  my $rec = record_host(host => host_profile('debian-12'), code => sub {
    $plan = $DEB->new(gpu => gpu_fixture('blackwell'), os => 'Debian',
      release => '13.1', arch => 'arm64', kernel => '6.12.0-test')->plan;
  });
  is_deeply($rec->{lines}, [], 'facts given to new(): plan reads nothing from the host');
  is($plan->{cuda_repo}{distro}, 'debian13', 'injected release decides the CUDA repo');
  is($plan->{cuda_repo}{arch},   'sbsa',     'injected arch decides the repo arch');
  is_deeply($plan->{packages},
    [ 'linux-headers-6.12.0-test', 'nvidia-driver-cuda', 'nvidia-kernel-open-dkms' ],
    'injected kernel names the headers');
}

#### run_cmd is the seam (no harness)

{
  package My::FakeHost;
  use Moo;
  extends 'Rex::GPU::NVIDIA::Setup::Ubuntu';
  has seen => ( is => 'ro', default => sub { [] } );
  sub run_cmd {
    my ( $self, $cmd ) = @_;
    push @{ $self->seen }, $cmd;
    $? = 0;
    return $cmd =~ /^apt-cache search .*-server\$'/ ? 'nvidia-driver-595-server' : '';
  }
}

{
  no warnings 'redefine';
  local *Rex::Logger::info = sub { };
  my $s = My::FakeHost->new(os => 'Ubuntu', release => '24.04', arch => 'amd64', kernel => '6.8.0-1');
  my $plan = $s->plan;
  is_deeply($plan->{packages},
    [ 'linux-headers-6.8.0-1', 'linux-headers-generic', 'nvidia-driver-595-server' ],
    'overridden run_cmd feeds the apt-cache search');
  is_deeply($plan->{verify}, [ 'nvidia-driver-595-server' ], 'the chosen driver is verified');
  is(scalar @{ $s->seen }, 1, 'plan ran exactly one command through run_cmd');
  like($s->seen->[0], qr/^apt-cache search /, '... the search');
}

#### Step order and the already-installed short-circuit

{
  package My::Steps;
  use Moo;
  extends 'Rex::GPU::NVIDIA::Setup';
  has log       => ( is => 'ro', default => sub { [] } );
  has installed => ( is => 'ro', default => 0 );
  sub already_installed { my ( $s ) = @_; push @{ $s->log }, 'already_installed'; $s->installed }
  for my $step (qw( prepare_host prepare_source install_packages verify_packages post_install )) {
    no strict 'refs';
    *{$step} = sub { my ( $s, $plan ) = @_; push @{ $s->log }, $step.'('.$plan->{tag}.')' };
  }
  sub plan { my ( $s ) = @_; push @{ $s->log }, 'plan'; return { tag => 'p' } }
}

{
  my $s = My::Steps->new;
  is($s->install, 1, 'install returns 1 after an install');
  is_deeply($s->log, [ 'already_installed', 'plan', 'prepare_host(p)', 'prepare_source(p)',
    'install_packages(p)', 'verify_packages(p)', 'post_install(p)' ],
    'steps run in the fixed order, each handed the plan');

  $s = My::Steps->new(installed => 1);
  is($s->install, 0, 'install returns 0 when a driver already works');
  is_deeply($s->log, [ 'already_installed' ], '... and nothing after already_installed runs');
}

{
  my $rec = record_host(
    host => host_profile('ubuntu-24.04', responses => [
      [ 'nvidia-smi -L 2>&1' => 'GPU 0: NVIDIA RTX 4000 SFF Ada Generation (UUID: GPU-0)', 0 ]
    ]),
    code => sub { die "install returned true\n" if $UBU->new(gpu => gpu_fixture('ada'))->install }
  );
  is($rec->{error}, undef, 'working driver: install returns 0');
  is_deeply($rec->{lines}, [ 'run: nvidia-smi -L 2>&1' ], '... after nothing but the probe');
}

#### A subclass overriding one step

{
  package My::Mirror;
  use Moo;
  extends 'Rex::GPU::NVIDIA::Setup::Debian';
  sub prepare_source {
    my ( $self, $plan ) = @_;
    $self->run_cmd('echo site mirror', auto_die => 0);
    $self->SUPER::prepare_source($plan);
  }
}

{
  my $base = record_host(host => host_profile('debian-12'),
    code => sub { $DEB->new(gpu => gpu_fixture('ada'))->install });
  my $mine = record_host(host => host_profile('debian-12'),
    code => sub { My::Mirror->new(gpu => gpu_fixture('ada'))->install });
  is($mine->{error}, undef, 'subclass install lives');
  my @want = @{ $base->{lines} };
  my ($at) = grep { $want[$_] =~ /apt-get .* update -q$/ } 0 .. $#want;
  splice @want, $at, 0, 'run: echo site mirror';
  is_deeply($mine->{lines}, \@want, 'exactly one extra command, right before apt-get update');
  ok(( grep { $_ eq 'run: update-initramfs -u 2>/dev/null' } @{ $base->{lines} } ),
    'post_install rebuilds the initramfs with the apt layer command');
}

#### Pure helpers are callable on the class, as the old wrappers use them

is(Rex::GPU::NVIDIA::Setup->_cuda_repo_arch('arm64'), 'sbsa', '_cuda_repo_arch on the class');
is(Rex::GPU::NVIDIA::Setup->_major_version('10.1'), 10, '_major_version keeps the dots in mind');
is(Rex::GPU::NVIDIA::_os_major_version('15.6'), 15, 'old wrapper _os_major_version still answers');

done_testing;
