# ABSTRACT: NVIDIA driver setup for RHEL, Rocky, AlmaLinux and CentOS Stream (experimental)

package Rex::GPU::NVIDIA::Setup::RHEL;
our $VERSION = '0.002';
use Moo;
use Rex::Commands::Gather ();
use Rex::Logger ();
use namespace::autoclean;

extends 'Rex::GPU::NVIDIA::Setup::Rpm';

=method major

The major version of the raw release string: C<10.1> is 10, never the
dot-stripped C<101> of C<operating_system_version>.

=cut

sub major {
  my ( $self ) = @_;
  return $self->_major_version($self->release);
}

=attr os_release

C</etc/os-release> as a hashref (C<ID>, C<ID_LIKE>, C<VERSION_ID>, ...; quotes
removed), read on first use with C<cat> through
L<Rex::GPU::NVIDIA::Setup/run_cmd>, or C<{}> when the file cannot be read.
Unless passed to C<new>.

=method is_rhel

True on Red Hat Enterprise Linux itself (C</etc/os-release> C<ID=rhel>), false
on Rocky, Alma, CentOS Stream and a host without C</etc/os-release>. The OS
name cannot tell: without C<lsb_release> Rex reports C<Redhat> for RHEL, Rocky
and Alma alike.

=method rex_pkg_works

True when L<Rex::Commands::Pkg/pkg> can work on this host: C<Rex::Pkg> picks
its provider through L<Rex::Commands::Gather/is_redhat>, and dies (C<OS/Provider
not supported>) on a name it does not know, such as C<Rocky> or C<AlmaLinux>
reported by C<lsb_release>.

=cut

has os_release => ( is => 'lazy' );

sub _build_os_release {
  my ( $self ) = @_;
  my $out = $self->run_cmd('cat /etc/os-release 2>/dev/null', auto_die => 0);
  return {} if $? != 0;
  return $self->_parse_os_release($out);
}

# Pure: KEY=VALUE lines of os-release(5), the value unquoted.
sub _parse_os_release {
  my ( $self, $text ) = @_;
  my %kv;
  for my $line (split /\n/, $text // '') {
    next unless $line =~ /^([A-Z0-9_]+)=(.*?)\s*$/;
    my ( $key, $value ) = ( $1, $2 );
    $value =~ s/^(["'])(.*)\1$/$2/;
    $kv{$key} = $value;
  }
  return \%kv;
}

sub is_rhel {
  my ( $self ) = @_;
  return ($self->os_release->{ID} // '') eq 'rhel' ? 1 : 0;
}

sub rex_pkg_works {
  my ( $self ) = @_;
  return Rex::Commands::Gather::is_redhat($self->os) ? 1 : 0;
}

=method install_helpers

  $self->install_helpers('python3-dnf-plugin-versionlock');

Installs inert helper packages: through L<Rex::GPU::NVIDIA::Setup/pkg_cmd>
where L</rex_pkg_works>, otherwise C<dnf install -y> run directly and
verified with C<rpm -q> (dies if one is missing).

=cut

sub install_helpers {
  my ( $self, @packages ) = @_;
  return $self->pkg_cmd([ @packages ], ensure => 'present') if $self->rex_pkg_works;
  $self->run_cmd($self->package_manager.' install -y '.join(' ', @packages), auto_die => 0);
  $self->verify_packages({ verify => [ @packages ] });
}

=method kernel_packages

C<kernel-devel-matched> + C<kernel-headers> on 9 and later,
C<kernel-devel-$kernel> + C<kernel-headers> before.

=method sources

From NVIDIA's CUDA repository, in this order:

=over

=item * C<cuda-open-dkms> -- the open kernel module, the newest branch the
repository carries (at least 580). On 10 and later (no module streams
there): C<kmod-nvidia-open-dkms> + C<nvidia-driver> + C<nvidia-driver-cuda>.
Before 10: C<nvidia-open> from module stream C<nvidia-driver:open-dkms>,
whose enable may fail without harm.

=item * C<cuda-580-dkms> -- the proprietary kmod
(C<kmod-nvidia-latest-dkms>, C<nvidia-driver>, C<nvidia-driver-cuda>) held
on branch 580: module stream C<nvidia-driver:580-dkms> before 10, a
C<dnf versionlock> on C<*nvidia*580*> on 10 and later. Both the stream and
the lock must succeed (L</prepare_source>), and the installed
C<nvidia-driver> must be a 580 (L</verify_packages>).

=back

C<nvidia-driver> is verified on both, plus the proprietary kmod on the
second. So a GPU without constraints and Blackwell get C<cuda-open-dkms>,
Maxwell/Pascal/Volta C<cuda-580-dkms>.

=method plan

The base plan plus C<< $plan->{major} >> and C<< $plan->{rhel} >>
(L</is_rhel>, which reads C</etc/os-release>) for the later steps. Reads no
architecture: C<uname -m> runs in L</prepare_source>, after EPEL and CRB are
enabled, as it always did -- on RHEL itself in L</prepare_host>, which needs
it for the CodeReady Builder repository name.

=cut

sub kernel_packages {
  my ( $self ) = @_;
  return ( ($self->major >= 9 ? 'kernel-devel-matched' : 'kernel-devel-'.$self->kernel),
    'kernel-headers' );
}

# branch_at_least 580: every tree carries it. kmod-nvidia-open-dkms in
# repos/rhel{8,9}/{x86_64,sbsa} spans 515..615, in repos/rhel10 580..615
# (directory listings checked 2026-09-23).
#
# cuda-580-dkms (karr #26):
#   * RHEL 8/9: the CUDA repo's module stream nvidia-driver:580-dkms, whose
#     artifacts are kmod-nvidia-latest-dkms + nvidia-driver(-cuda) 3:580.*
#     (checked in repos/rhel{8,9}/x86_64 modules.yaml, 2026-09-23).
#   * RHEL 10: no module streams, so a dnf versionlock on '*nvidia*580*' per
#     NVIDIA's version-locking guide (docs.nvidia.com/datacenter/tesla/
#     driver-installation-guide/version-locking.html). repos/rhel10/x86_64
#     carries kmod-nvidia-latest-dkms, nvidia-driver and nvidia-driver-cuda at
#     580.x (checked 2026-09-23).
sub sources {
  my ( $self ) = @_;
  my $major = $self->major;
  my $open = $major >= 10
    ? { packages => [ 'kmod-nvidia-open-dkms', 'nvidia-driver', 'nvidia-driver-cuda' ] }
    : { packages => [ 'nvidia-open' ], module_stream => 'open-dkms', stream_optional => 1 };
  return (
    {
      name            => 'cuda-open-dkms',
      kernel_module   => 'open',
      branch_at_least => 580,
      verify          => [ 'nvidia-driver' ],
      %$open
    },
    {
      name          => 'cuda-580-dkms',
      kernel_module => 'proprietary',
      branch        => 580,
      packages      => [ 'kmod-nvidia-latest-dkms', 'nvidia-driver', 'nvidia-driver-cuda' ],
      verify        => [ 'nvidia-driver', 'kmod-nvidia-latest-dkms' ],
      pin_branch    => 580,
      $major >= 10 ? ( versionlock => '*nvidia*580*' ) : ( module_stream => '580-dkms' )
    }
  );
}

sub plan {
  my ( $self ) = @_;
  my $plan = $self->SUPER::plan;
  $plan->{major} = $self->major;
  $plan->{rhel}  = $self->is_rhel;
  return $plan;
}

=method prepare_host

Enables EPEL, which C<dkms> comes from (the NVIDIA kmod packages require it;
neither the CUDA repository nor the distribution carries it), and the
CodeReady Builder repository EPEL packages may depend on:

=over

=item * Rocky, Alma, CentOS Stream: C<epel-release> through
L</install_helpers>, then C<crb> (9 and later) or C<powertools> (before 9)
with C<dnf config-manager>; a failure there is ignored.

=item * RHEL itself (L</is_rhel>), which has no C<epel-release> package: EPEL's
release RPM, C<dnf install -y
https://dl.fedoraproject.org/pub/epel/epel-release-latest-MAJOR.noarch.rpm>,
verified with C<rpm -q epel-release> (dies if missing); then
C<subscription-manager repos --enable
codeready-builder-for-rhel-MAJOR-ARCH-rpms> (C<uname -m>), which warns on
failure but does not die -- a host without subscription-manager (RHUI) names
the repository differently.

=back

=method epel_release_url

  my $url = $setup->epel_release_url(9);

EPEL's release RPM for a RHEL major version.

=cut

sub epel_release_url {
  my ( $self, $major ) = @_;
  return 'https://dl.fedoraproject.org/pub/epel/epel-release-latest-'.$major.'.noarch.rpm';
}

# RHEL (karr #39): per EPEL's getting-started guide and NVIDIA's driver
# installation guide (RHEL 8/9/10 pre-installation steps), both checked
# 2026-09-24: subscription-manager enables CRB, EPEL comes from its release
# RPM URL. dkms: EPEL 8/9/10 carry it, repos/rhel{8,9,10}/x86_64 of the CUDA
# repo do not, and kmod-nvidia-{open,latest}-dkms Require it.
sub prepare_host {
  my ( $self, $plan ) = @_;
  Rex::Logger::info('  Enabling EPEL and extra repos...');
  if ($plan->{rhel}) {
    my $major = $plan->{major};
    $self->run_cmd($self->package_manager.' install -y '.$self->epel_release_url($major), auto_die => 0);
    $self->verify_packages({ verify => [ 'epel-release' ] });
    my $crb = 'codeready-builder-for-rhel-'.$major.'-'.$self->arch.'-rpms';
    $self->run_cmd('subscription-manager repos --enable '.$crb, auto_die => 0);
    Rex::Logger::info('  Could not enable '.$crb.' with subscription-manager; '
      .'EPEL packages that need CodeReady Builder will not install', 'warn')
      if $? != 0;
    return;
  }
  $self->install_helpers('epel-release');
  if ($plan->{major} >= 9) {
    $self->run_cmd('dnf config-manager --set-enabled crb 2>/dev/null || true', auto_die => 0);
  }
  else {
    $self->run_cmd('dnf config-manager --set-enabled powertools 2>/dev/null || true', auto_die => 0);
  }
}

=method prepare_source

Adds NVIDIA's CUDA repository C<rhelN> for the host architecture (read here,
C<uname -m>: aarch64 is the C<sbsa> tree), expires dnf's cache, then selects
the driver branch the chosen source asks for:

=over

=item * C<module_stream>: C<dnf module enable nvidia-driver:STREAM -y>. For
C<cuda-580-dkms> a failure B<dies> here, before any driver package is
installed -- without the pin dnf would resolve the newest branch, which does
not support the GPU; for C<cuda-open-dkms> (C<stream_optional>) it is
ignored.

=item * C<versionlock>: C<python3-dnf-plugin-versionlock> (L</install_helpers>), then
C<dnf versionlock add>; a failure dies the same way.

=back

=cut

sub prepare_source {
  my ( $self, $plan ) = @_;
  my $major = $plan->{major};

  # Arch-aware: aarch64 server/datacenter parts (Grace, Hopper, Blackwell) are
  # published under the "sbsa" tree, not "x86_64".
  my $distro = "rhel$major";
  my $arch   = $self->_cuda_repo_arch($self->arch);
  Rex::Logger::info("  Adding NVIDIA CUDA repo ($distro/$arch)...");
  $self->run_cmd("dnf config-manager --add-repo https://developer.download.nvidia.com/compute/cuda/repos/$distro/$arch/cuda-$distro.repo 2>/dev/null",
    auto_die => 0);
  $self->run_cmd('dnf clean expire-cache', auto_die => 0);

  my $source = $plan->{source} or return;
  if (my $stream = $source->{module_stream}) {
    if ($source->{stream_optional}) {
      $self->run_cmd("dnf module enable nvidia-driver:$stream -y 2>/dev/null || true", auto_die => 0);
    }
    else {
      # Pre-Turing (karr #26): unlike the open stream, a failed enable is NOT
      # swallowed: without it dnf would resolve the newest branch.
      $self->run_cmd("dnf module enable nvidia-driver:$stream -y", auto_die => 0);
      die "dnf module enable nvidia-driver:$stream failed — another "
        . "nvidia-driver stream is probably enabled already (`dnf module reset "
        . "nvidia-driver` switches it); no driver was installed\n"
        if $? != 0;
    }
  }
  if (my $lock = $source->{versionlock}) {
    $self->install_helpers('python3-dnf-plugin-versionlock');
    $self->run_cmd("dnf versionlock add '$lock'", auto_die => 0);
    die "dnf versionlock add '$lock' failed; no driver was installed\n"
      if $? != 0;
  }
}

=method verify_packages

The rpm layer's C<rpm -q> check, then for a source with C<pin_branch>
(C<cuda-580-dkms>): dies unless the installed C<nvidia-driver> is on that
branch (C<rpm -q --qf '%{VERSION}'>), not a newer one that cannot drive the
GPU.

=cut

sub verify_packages {
  my ( $self, $plan ) = @_;
  $self->SUPER::verify_packages($plan);
  my $branch = $plan->{source} && $plan->{source}{pin_branch} or return;
  my $version = $self->run_cmd("rpm -q --qf '%{VERSION}' nvidia-driver 2>&1", auto_die => 0);
  chomp $version if defined $version;
  die "nvidia-driver is " . ($version // 'unknown') . ", not branch "
    . "$branch — this pre-Turing GPU needs $branch\n"
    unless $self->_rpm_version_in_branch($version, $branch);
}

1;

=head1 DESCRIPTION

B<Experimental>, like L<Rex::GPU::NVIDIA::Setup>. The NVIDIA driver install
for the RHEL family (RHEL, Rocky Linux, AlmaLinux, CentOS Stream): EPEL and
CRB/PowerTools, NVIDIA's CUDA repository, the open-kernel DKMS driver by
default and the proprietary 580 kmod where the GPUs need it
(L</sources>), on the rpm layer L<Rex::GPU::NVIDIA::Setup::Rpm> with
C<dnf>.

=head1 SEE ALSO

L<Rex::GPU::NVIDIA::Setup>, L<Rex::GPU::NVIDIA/install_driver>

=cut
