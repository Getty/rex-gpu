# ABSTRACT: NVIDIA driver setup for RHEL, Rocky, AlmaLinux and CentOS Stream (experimental)

package Rex::GPU::NVIDIA::Setup::RHEL;
our $VERSION = '0.002';
use Moo;
use Rex::Logger ();
use namespace::autoclean;

extends 'Rex::GPU::NVIDIA::Setup::Rpm';

=method plan

Adds to the base plan, from the major version of the raw release string
(C<10.1> is 10, never the dot-stripped C<101>):

=over

=item * Kernel headers: C<kernel-devel-matched> + C<kernel-headers> on 9 and
later, C<kernel-devel-$kernel> + C<kernel-headers> before.

=item * Pre-Turing (Maxwell/Pascal/Volta): the proprietary set of
L</legacy_driver_plan> (C<kmod-nvidia-latest-dkms>, C<nvidia-driver>,
C<nvidia-driver-cuda>), stored as C<< $plan->{legacy} >> so
L</prepare_source> pins the branch and L</verify_packages> checks it.

=item * 10 and later: C<kmod-nvidia-open-dkms> + C<nvidia-driver> +
C<nvidia-driver-cuda> (no module streams there).

=item * Before 10: C<nvidia-open> from module stream
C<nvidia-driver:open-dkms>.

=back

Verified: C<nvidia-driver>, plus the proprietary kmod for pre-Turing.
Reads no architecture: C<uname -m> runs in L</prepare_source>, after EPEL
and CRB are enabled, as it always did.

=cut

sub plan {
  my ( $self ) = @_;
  my $plan = $self->SUPER::plan;
  my $major  = $self->_major_version($self->release);
  my $legacy = $self->legacy_driver_plan($major, $self->gpu);
  $plan->{major}  = $major;
  $plan->{legacy} = $legacy;

  push @{ $plan->{packages} },
    ($major >= 9 ? 'kernel-devel-matched' : 'kernel-devel-'.$self->kernel), 'kernel-headers';

  # Driver packages -- different for v10 (no module streams, dkms variant)
  if ($legacy) {
    Rex::Logger::info("  Pre-Turing GPU — proprietary driver, branch $legacy->{branch}");
    push @{ $plan->{packages} }, @{ $legacy->{packages} };
  }
  elsif ($major >= 10) {
    push @{ $plan->{packages} }, 'kmod-nvidia-open-dkms', 'nvidia-driver', 'nvidia-driver-cuda';
  }
  else {
    push @{ $plan->{packages} }, 'nvidia-open';
  }

  $plan->{verify} = [ 'nvidia-driver', ($legacy ? $legacy->{kmod} : ()) ];
  return $plan;
}

=method prepare_host

Enables EPEL (C<epel-release> through L<Rex::GPU::NVIDIA::Setup/pkg_cmd>, an
inert helper) and the distribution's C<crb> (9 and later) or C<powertools>
(before 9) repository, which DKMS and the driver's dependencies come from.

=cut

sub prepare_host {
  my ( $self, $plan ) = @_;
  Rex::Logger::info('  Enabling EPEL and extra repos...');
  $self->pkg_cmd(['epel-release'], ensure => 'present');
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
the driver branch:

=over

=item * Pre-Turing: C<dnf module enable nvidia-driver:580-dkms> (before 10),
or C<python3-dnf-plugin-versionlock> plus C<dnf versionlock add '*nvidia*580*'>
(10 and later). Either failing B<dies> here, before any driver package is
installed: without the pin dnf would resolve the newest branch, which does
not support the GPU.

=item * Before 10: C<dnf module enable nvidia-driver:open-dkms>, failure
ignored.

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

  if (my $legacy = $plan->{legacy}) {
    # Pre-Turing (karr #26): proprietary kmod, held on branch $legacy->{branch}.
    # Unlike the open path below, a failed stream enable or lock is NOT
    # swallowed: without it dnf would resolve the newest branch, which does not
    # support this GPU.
    if ($legacy->{module_stream}) {
      $self->run_cmd("dnf module enable nvidia-driver:$legacy->{module_stream} -y", auto_die => 0);
      die "dnf module enable nvidia-driver:$legacy->{module_stream} failed — another "
        . "nvidia-driver stream is probably enabled already (`dnf module reset "
        . "nvidia-driver` switches it); no driver was installed\n"
        if $? != 0;
    }
    if ($legacy->{versionlock}) {
      $self->pkg_cmd(['python3-dnf-plugin-versionlock'], ensure => 'present');
      $self->run_cmd("dnf versionlock add '$legacy->{versionlock}'", auto_die => 0);
      die "dnf versionlock add '$legacy->{versionlock}' failed; no driver was installed\n"
        if $? != 0;
    }
  }
  elsif ($major < 10) {
    $self->run_cmd('dnf module enable nvidia-driver:open-dkms -y 2>/dev/null || true', auto_die => 0);
  }
}

=method verify_packages

The rpm layer's C<rpm -q> check, then for pre-Turing: dies unless the
installed C<nvidia-driver> is on the pinned branch
(C<rpm -q --qf '%{VERSION}'>), not a newer one that cannot drive the GPU.

=cut

sub verify_packages {
  my ( $self, $plan ) = @_;
  $self->SUPER::verify_packages($plan);
  my $legacy = $plan->{legacy} or return;
  my $version = $self->run_cmd("rpm -q --qf '%{VERSION}' nvidia-driver 2>&1", auto_die => 0);
  chomp $version if defined $version;
  die "nvidia-driver is " . ($version // 'unknown') . ", not branch "
    . "$legacy->{branch} — this pre-Turing GPU needs $legacy->{branch}\n"
    unless $self->_rpm_version_in_branch($version, $legacy->{branch});
}

=method legacy_driver_plan

  my $legacy = $self->legacy_driver_plan($major, $gpu);

Pure. C<undef> for every GPU that is not pre-Turing (the open path stays as
it is). For Maxwell/Pascal/Volta the proprietary kmod
(C<kmod-nvidia-latest-dkms>) on the 580 branch:
C<{ branch, module_stream, versionlock, packages, kmod }> -- module stream
C<580-dkms> before 10, versionlock C<*nvidia*580*> on 10 and later.

=cut

#   * RHEL 8/9: the CUDA repo's module stream nvidia-driver:580-dkms, whose
#     artifacts are kmod-nvidia-latest-dkms + nvidia-driver(-cuda) 3:580.*
#     (checked in repos/rhel{8,9}/x86_64 modules.yaml, 2026-09-23).
#   * RHEL 10: no module streams, so a dnf versionlock on '*nvidia*580*' per
#     NVIDIA's version-locking guide (docs.nvidia.com/datacenter/tesla/
#     driver-installation-guide/version-locking.html). repos/rhel10/x86_64
#     carries kmod-nvidia-latest-dkms, nvidia-driver and nvidia-driver-cuda at
#     580.x (checked 2026-09-23).
sub legacy_driver_plan {
  my ( $self, $major, $gpu ) = @_;
  my $legacy = $self->_legacy_requirement($gpu);
  return unless $legacy;
  my $branch = $legacy->{max_branch};
  return {
    branch        => $branch,
    module_stream => ($major >= 10 ? undef : "$branch-dkms"),
    versionlock   => ($major >= 10 ? "*nvidia*$branch*" : undef),
    packages      => [ 'kmod-nvidia-latest-dkms', 'nvidia-driver', 'nvidia-driver-cuda' ],
    kmod          => 'kmod-nvidia-latest-dkms'
  };
}

1;

=head1 DESCRIPTION

B<Experimental>, like L<Rex::GPU::NVIDIA::Setup>. The NVIDIA driver install
for the RHEL family (RHEL, Rocky Linux, AlmaLinux, CentOS Stream): EPEL and
CRB/PowerTools, NVIDIA's CUDA repository, the open-kernel DKMS driver by
default, on the rpm layer L<Rex::GPU::NVIDIA::Setup::Rpm> with C<dnf>.

=head1 SEE ALSO

L<Rex::GPU::NVIDIA::Setup>, L<Rex::GPU::NVIDIA/install_driver>

=cut
