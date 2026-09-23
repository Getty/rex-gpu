use strict;
use warnings;
use Test::More;

use FindBin qw( $Bin );
use lib "$Bin/lib";

# -----------------------------------------------------------------------------
# Unit tests for the Setup classes (karr #31/#32, T2/T3 of epic #25):
# Rex::GPU::NVIDIA::Setup, ::Setup::Apt, ::Setup::Debian, ::Setup::Ubuntu,
# ::Setup::Rpm, ::Setup::RHEL, ::Setup::SUSE.
#
# CLAIMS:
#   * install runs its steps in the fixed order and stops after
#     already_installed when a driver works;
#   * plan only reads the host: for every Debian/Ubuntu/RHEL/Leap profile x
#     GPU it emits no mutating command (Golden.pm's read-only list), a
#     Blackwell on a Debian release without a CUDA repo dies inside plan, and
#     the RHEL plan does not read `uname -m` (it runs after EPEL/CRB);
#   * a failed pre-Turing module-stream enable dies before any dnf install;
#   * facts passed to new() are not read from the host;
#   * run_cmd is the seam: a subclass that overrides it sees every command;
#   * a subclass overriding one step changes exactly that step;
#   * setup_class_for_os picks Debian / Ubuntu / RHEL / SUSE / none by OS,
#     and an OS without a class still probes nvidia-smi and rejects Kepler
#     before it dies.
# That install_driver still emits the same commands is t/96's job (goldens).
#
# NOT covered: anything a real host does with these commands -- none of this
# runs apt, dnf, zypper, rpm or a GPU.
# -----------------------------------------------------------------------------

use Test::RexGPU::Golden qw( record_host host_profile gpu_fixture mutating_lines );
use Rex::GPU::NVIDIA;

my $APT  = 'Rex::GPU::NVIDIA::Setup::Apt';
my $DEB  = 'Rex::GPU::NVIDIA::Setup::Debian';
my $UBU  = 'Rex::GPU::NVIDIA::Setup::Ubuntu';
my $RPM  = 'Rex::GPU::NVIDIA::Setup::Rpm';
my $RHEL = 'Rex::GPU::NVIDIA::Setup::RHEL';
my $SUSE = 'Rex::GPU::NVIDIA::Setup::SUSE';

#### Class layout

isa_ok($APT, 'Rex::GPU::NVIDIA::Setup');
isa_ok($DEB, $APT);
isa_ok($UBU, $APT);
isa_ok($RPM, 'Rex::GPU::NVIDIA::Setup');
isa_ok($RHEL, $RPM);
isa_ok($SUSE, $RPM);
is($RHEL->package_manager, 'dnf',    'RHEL installs with dnf');
is($SUSE->package_manager, 'zypper', 'SUSE installs with zypper');

#### setup_class_for_os

{
  my %want = (
    'debian-12'    => $DEB,
    'debian-13'    => $DEB,
    'ubuntu-24.04' => $UBU,
    'rocky-9'      => $RHEL,
    'rocky-10'     => $RHEL,
    'leap-15.6'    => $SUSE,
    'leap-16.0'    => $SUSE
  );
  for my $os (sort keys %want) {
    my $class;
    my $rec = record_host(host => host_profile($os),
      code => sub { $class = Rex::GPU::NVIDIA->setup_class_for_os });
    is($class, $want{$os}, "$os => ".($want{$os} // 'no Setup class'));
    is_deeply($rec->{lines}, [], "$os: resolving the class runs nothing");
  }
}

{
  my $class;
  my $rec = record_host(host => host_profile('debian-12', os => 'Gentoo'),
    code => sub { $class = Rex::GPU::NVIDIA->setup_class_for_os });
  is($class, undef, 'Gentoo => no Setup class');

  $rec = record_host(host => host_profile('debian-12', os => 'Gentoo'),
    code => sub { Rex::GPU::NVIDIA::install_driver(gpu => gpu_fixture('ada')) });
  like($rec->{error}, qr/^Unsupported OS for NVIDIA driver installation: Gentoo$/,
    'install_driver on an OS without a class dies naming it');
  is_deeply($rec->{lines}, [ 'run: nvidia-smi -L 2>&1', 'run(auto_die=default): uname -r' ],
    '... after only the probe and the kernel read, as before T3');

  $rec = record_host(host => host_profile('debian-12', os => 'Gentoo'),
    code => sub { Rex::GPU::NVIDIA::install_driver(gpu => gpu_fixture('kepler')) });
  like($rec->{error}, qr/Kepler or older/, '... a Kepler still gets the Kepler message first');

  $rec = record_host(host => host_profile('debian-12', os => 'Gentoo', responses => [
      [ 'nvidia-smi -L 2>&1' => 'GPU 0: NVIDIA RTX 4000 SFF Ada Generation (UUID: GPU-0)', 0 ]
    ]),
    code => sub { Rex::GPU::NVIDIA::install_driver(gpu => gpu_fixture('ada')) });
  is($rec->{error}, undef, '... and a working driver still short-circuits without dying');
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

for my $os (qw( rocky-9 rocky-10 leap-15.6 leap-16.0 )) {
  my $class = $os =~ /^rocky/ ? $RHEL : $SUSE;
  for my $g (qw( ada blackwell volta none )) {
    my $plan;
    my $rec = record_host(host => host_profile($os),
      code => sub { $plan = $class->new(gpu => gpu_fixture($g))->plan });
    is($rec->{error}, undef, "$os + $g: plan lives");
    is_deeply([ mutating_lines(@{ $rec->{lines} }) ], [], "$os + $g: plan emits only read-only probes");
    is_deeply([ grep { /uname -m/ } @{ $rec->{lines} } ], [], "$os + $g: plan does not read the arch");
    ok(scalar @{ $plan->{packages} }, "$os + $g: packages filled");
    if ($class eq $SUSE) {
      # the default open meta package is not verified (karr #27, unchanged)
      is(scalar @{ $plan->{verify} }, ($g eq 'volta' ? 1 : 0),
        "$os + $g: only the pre-Turing meta package is verified");
    }
    else {
      is($plan->{verify}[0], 'nvidia-driver', "$os + $g: nvidia-driver verified");
    }
  }
}

{
  my $plan;
  record_host(host => host_profile('rocky-9'),
    code => sub { $plan = $RHEL->new(gpu => gpu_fixture('volta'))->plan });
  is_deeply($plan->{verify}, [ 'nvidia-driver', 'kmod-nvidia-latest-dkms' ],
    'rocky-9 + V100: the proprietary kmod is verified too');
  is($plan->{legacy}{module_stream}, '580-dkms', '... stream 580-dkms decided in plan');

  my $rec = record_host(host => host_profile('rocky-9'), code => sub {
    $plan = $RHEL->new(os => 'Redhat', release => '8.10', kernel => '4.18.0-553.el8_10.x86_64')->plan;
  });
  is_deeply($rec->{lines}, [], 'RHEL 8, facts given to new(): plan reads nothing from the host');
  is_deeply($plan->{packages},
    [ 'kernel-devel-4.18.0-553.el8_10.x86_64', 'kernel-headers', 'nvidia-open' ],
    'RHEL 8: running-kernel devel package, nvidia-open');
}

{
  # Pre-Turing on RHEL 9, module stream enable fails: dies in prepare_source,
  # before any driver package is installed.
  my $rec = record_host(host => host_profile('rocky-9', responses => [
      [ 'dnf module enable nvidia-driver:580-dkms -y' => 'Error: conflicting stream', 1 ]
    ]),
    code => sub { Rex::GPU::NVIDIA::install_driver(gpu => gpu_fixture('volta')) });
  like($rec->{error}, qr/dnf module enable nvidia-driver:580-dkms failed/,
    'rocky-9 + V100, stream enable fails: dies');
  is_deeply([ grep { /dnf install/ } @{ $rec->{lines} } ], [], '... before any dnf install');
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

{
  package My::RHEL::Mirror;
  use Moo;
  extends 'Rex::GPU::NVIDIA::Setup::RHEL';
  sub prepare_source {
    my ( $self, $plan ) = @_;
    $self->run_cmd('echo site mirror', auto_die => 0);
    $self->SUPER::prepare_source($plan);
  }

  package My::SUSE::NoLock;
  use Moo;
  extends 'Rex::GPU::NVIDIA::Setup::SUSE';
  sub install_packages {
    my ( $self, $plan ) = @_;
    $self->Rex::GPU::NVIDIA::Setup::Rpm::install_packages($plan);
  }
}

{
  my $base = record_host(host => host_profile('rocky-10'),
    code => sub { $RHEL->new(gpu => gpu_fixture('ada'))->install });
  my $mine = record_host(host => host_profile('rocky-10'),
    code => sub { My::RHEL::Mirror->new(gpu => gpu_fixture('ada'))->install });
  is($mine->{error}, undef, 'RHEL subclass install lives');
  my @want = @{ $base->{lines} };
  my ($at) = grep { $want[$_] eq 'run: uname -m' } 0 .. $#want;
  splice @want, $at, 0, 'run: echo site mirror';
  is_deeply($mine->{lines}, \@want, 'RHEL: one extra command, right before the arch read of prepare_source');
  ok(( grep { $_ eq 'run: dracut --force 2>/dev/null' } @{ $base->{lines} } ),
    'post_install rebuilds the initramfs with dracut on the rpm layer');

  $base = record_host(host => host_profile('leap-16.0'),
    code => sub { $SUSE->new(gpu => gpu_fixture('ada'))->install });
  $mine = record_host(host => host_profile('leap-16.0'),
    code => sub { My::SUSE::NoLock->new(gpu => gpu_fixture('ada'))->install });
  is($mine->{error}, undef, 'SUSE subclass install lives');
  is_deeply($mine->{lines}, [ grep { !/zypper addlock/ } @{ $base->{lines} } ],
    'SUSE: overriding install_packages drops exactly the addlock');
}

#### Pure helpers are callable on the class, as the old wrappers use them

is(Rex::GPU::NVIDIA::Setup->_cuda_repo_arch('arm64'), 'sbsa', '_cuda_repo_arch on the class');
is(Rex::GPU::NVIDIA::Setup->_major_version('10.1'), 10, '_major_version keeps the dots in mind');
is(Rex::GPU::NVIDIA::_os_major_version('15.6'), 15, 'old wrapper _os_major_version still answers');
is($RPM->_rpm_version_in_branch('580.95.05', 580), 1, '_rpm_version_in_branch on the class');
is_deeply([ $SUSE->nvidia_repo_params('15.6') ],
  [ 'https://download.nvidia.com/opensuse/leap/15.6/', 'nvidia-open-driver-G06-signed-kmp-meta' ],
  'nvidia_repo_params on the class');
is($RHEL->legacy_driver_plan(10, gpu_fixture('volta'))->{versionlock}, '*nvidia*580*',
  'legacy_driver_plan on the class');

done_testing;
