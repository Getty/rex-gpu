# ABSTRACT: NVIDIA driver setup for openSUSE Leap (experimental)

package Rex::GPU::NVIDIA::Setup::SUSE;
our $VERSION = '0.002';
use Moo;
use Rex::Logger ();
use namespace::autoclean;

extends 'Rex::GPU::NVIDIA::Setup::Rpm';

=method package_manager

C<zypper>.

=cut

sub package_manager { 'zypper' }

=method plan

Adds one kmp meta package from NVIDIA's GFX repository
(L</nvidia_repo_params>, stored as C<< $plan->{repo_url} >>): it
co-installs the kernel module and the userspace at one version, so
C<nvidia-smi> never sees a C<Driver/library version mismatch>. Pre-signed
kmp packages need no kernel headers.

Only the pre-Turing proprietary C<nvidia-driver-G06-kmp-meta> is verified.
The default open meta packages are B<not> verified -- that gap is known and
kept as it was.

=cut

sub plan {
  my ( $self ) = @_;
  my $plan = $self->SUPER::plan;
  my $legacy = $self->_legacy_requirement($self->gpu);
  my ($repo_url, $meta_pkg) = $self->nvidia_repo_params($self->release, $legacy);
  $plan->{repo_url} = $repo_url;
  push @{ $plan->{packages} }, $meta_pkg;

  # Pre-Turing only (karr #26): verify the proprietary meta package landed. It
  # requires the kmp and the userspace at its own exact version, so installed
  # means both are. Other GPUs keep the unverified path as before.
  $plan->{verify} = $legacy ? [ $meta_pkg ] : [];
  return $plan;
}

=method prepare_host

Removes (C<rpm -e>) every installed C<nvidia*> / C<libnvidia*> package except
the container toolkit's: C<libnvidia-ml> / C<libnvidia-cfg> from the OSS
non-free repository lag behind the GFX repository's kmp and split the
driver from its libraries.

=cut

sub prepare_host {
  my ( $self, $plan ) = @_;
  Rex::Logger::info('  Removing any existing NVIDIA packages...');
  $self->run_cmd(q{rpm -e $(rpm -qa | grep -E '^(nvidia|libnvidia)' | grep -v 'container') 2>/dev/null || true},
    auto_die => 0);
}

=method prepare_source

(Re-)adds NVIDIA's GFX repository as C<nvidia-gfx> by its base URL (zypper
cannot parse the yum C<.repo> files) and refreshes it, importing its key.

=cut

sub prepare_source {
  my ( $self, $plan ) = @_;
  Rex::Logger::info('  Adding NVIDIA GFX repo (Leap '.$self->release.'): '.$plan->{repo_url});
  $self->run_cmd('zypper rr nvidia-gfx 2>/dev/null || true', auto_die => 0);
  $self->run_cmd('zypper addrepo --refresh '.$plan->{repo_url}.' nvidia-gfx 2>/dev/null', auto_die => 0);
  $self->run_cmd('zypper --gpg-auto-import-keys refresh nvidia-gfx 2>/dev/null', auto_die => 0);
}

=method install_packages

The rpm layer's C<zypper install -y>, then C<zypper addlock libnvidia-ml
libnvidia-cfg>, so a later C<zypper update> cannot pull the stale OSS
non-free libraries back in and cause the version mismatch again.

=cut

sub install_packages {
  my ( $self, $plan ) = @_;
  $self->SUPER::install_packages($plan);
  $self->run_cmd('zypper addlock libnvidia-ml libnvidia-cfg 2>/dev/null || true', auto_die => 0);
}

=method nvidia_repo_params

  my ($repo_url, $meta_pkg) = $self->nvidia_repo_params($release, $legacy);

Pure. C<$release> is the raw C<operating_system_release> (C<15.6>, C<16.0>),
C<$legacy> the pre-Turing requirement or C<undef>:

=over

=item * Pre-Turing: C<leap/15.x/> or C<leap/16.0/> with the proprietary
C<nvidia-driver-G06-kmp-meta> (branch 580); G07 is open-only.

=item * Leap 16: C<leap/16.0/>, C<nvidia-open-driver-G07-signed-kmp-meta>.

=item * Leap 15: C<leap/15.x/> (the minor kept),
C<nvidia-open-driver-G06-signed-kmp-meta>.

=back

=cut

sub nvidia_repo_params {
  my ( $self, $release, $legacy ) = @_;

  # Derive the major from the raw release string. operating_system_version()
  # strips dots ("15.6" -> "156"), which made int() see 156 and route every
  # Leap through the ">= 16" branch (karr #6).
  my $major = $self->_major_version($release);

  # Pre-Turing (karr #26): the PROPRIETARY G06 (= branch 580) meta package on
  # both Leap 15 and 16 -- the open G06/G07 metas do not support these GPUs,
  # and G07 (595) is open-only. NVIDIA's leap/15.6/ and leap/16.0/ repos both
  # carry nvidia-driver-G06-kmp-meta (x86_64 + aarch64, up to 580.178.04,
  # checked in their primary.xml 2026-09-23); it requires
  # nvidia-driver-G06-kmp and nvidia-userspace-meta-G06 at its own exact
  # version.
  if ($legacy) {
    my $leap_version = $major >= 16 ? '16.0' : ($release =~ /^(\d+\.\d+)/)[0] // $release;
    return ("https://download.nvidia.com/opensuse/leap/$leap_version/",
            "nvidia-driver-G06-kmp-meta");
  }

  if ($major >= 16) {
    return ("https://download.nvidia.com/opensuse/leap/16.0/",
            "nvidia-open-driver-G07-signed-kmp-meta");
  }

  # Leap 15.x: keep the full x.y version in the repo path (leap/15.6/).
  my ($leap_version) = $release =~ /^(\d+\.\d+)/;
  $leap_version //= $release;
  return ("https://download.nvidia.com/opensuse/leap/$leap_version/",
          "nvidia-open-driver-G06-signed-kmp-meta");
}

1;

=head1 DESCRIPTION

B<Experimental>, like L<Rex::GPU::NVIDIA::Setup>. The NVIDIA driver install
for openSUSE Leap 15 and 16: the signed kmp meta package from NVIDIA's GFX
repository, on the rpm layer L<Rex::GPU::NVIDIA::Setup::Rpm> with
C<zypper>. openSUSE is not a verified deploy target of Rex::GPU.

There is no separate zypper packaging layer: besides the install command
name (L</package_manager>) everything zypper-specific here -- the GFX
repository, the stale-package purge, the library lock -- belongs to this one
driver install.

=head1 SEE ALSO

L<Rex::GPU::NVIDIA::Setup>, L<Rex::GPU::NVIDIA/install_driver>

=cut
