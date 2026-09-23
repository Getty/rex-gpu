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

=method sources

One kmp meta package from NVIDIA's GFX repository for the Leap release
(key C<repo_url>, see L</leap_version>), in this order:

=over

=item * Leap 16: C<nvidia-gfx-G07-open> --
C<nvidia-open-driver-G07-signed-kmp-meta>, open kernel module, the newest
G07 branch (at least 595). Leap 15: C<nvidia-gfx-G06-open> --
C<nvidia-open-driver-G06-signed-kmp-meta>, open, branch 580.

=item * C<nvidia-gfx-G06> -- the proprietary C<nvidia-driver-G06-kmp-meta>,
branch 580 (G07 has no proprietary module), on Leap 15 and 16.

=back

A meta package co-installs the kernel module and the userspace at one
version, so C<nvidia-smi> never sees a C<Driver/library version mismatch>.
Pre-signed kmp packages need no kernel headers.

Only the proprietary C<nvidia-driver-G06-kmp-meta> is verified. The open
meta packages are B<not> verified -- that gap is known and kept as it was.

=method leap_version

C<16.0> on Leap 16 and later, the C<x.y> of the raw release string
(C<15.6>) before -- never C<operating_system_version>, which strips the dots
(C<156>, karr #6).

=method repo_url

  my $url = $self->repo_url('15.6');

C<https://download.nvidia.com/opensuse/leap/15.6/>.

=method plan

The base plan plus C<< $plan->{repo_url} >>, the chosen source's repository.

=cut

sub leap_version {
  my ( $self ) = @_;
  my $release = $self->release;
  return '16.0' if $self->_major_version($release) >= 16;
  my ($leap_version) = ($release // '') =~ /^(\d+\.\d+)/;
  return $leap_version // $release;
}

sub repo_url {
  my ( $self, $leap_version ) = @_;
  return "https://download.nvidia.com/opensuse/leap/$leap_version/";
}

# G06 is NVIDIA's series up to 580, G07 the open-only one after it. Checked
# 2026-09-23 in the repos' primary.xml: the G06 metas (open on leap/15.6,
# proprietary on 15.6 and 16.0) carry branches 570 and 580 only, zypper
# resolves the newest, so they install 580 -- branch 580 exactly; 590 never
# went into G06. The G07 open meta on leap/16.0 carries 594 and 595, newer
# branches land there: branch_at_least 595. NVIDIA's leap/15.6/ and leap/16.0/ repos
# both carry nvidia-driver-G06-kmp-meta (x86_64 + aarch64, up to 580.178.04,
# checked in their primary.xml 2026-09-23); it requires
# nvidia-driver-G06-kmp and nvidia-userspace-meta-G06 at its own exact
# version. The open G06/G07 metas do not support pre-Turing GPUs.
sub sources {
  my ( $self ) = @_;
  my $url = $self->repo_url($self->leap_version);
  my $open = $self->_major_version($self->release) >= 16
    ? { name => 'nvidia-gfx-G07-open', branch_at_least => 595,
        packages => [ 'nvidia-open-driver-G07-signed-kmp-meta' ] }
    : { name => 'nvidia-gfx-G06-open', branch => 580,
        packages => [ 'nvidia-open-driver-G06-signed-kmp-meta' ] };
  return (
    { %$open, kernel_module => 'open', verify => [], repo_url => $url },
    {
      name          => 'nvidia-gfx-G06',
      kernel_module => 'proprietary',
      branch        => 580,
      packages      => [ 'nvidia-driver-G06-kmp-meta' ],
      verify        => [ 'nvidia-driver-G06-kmp-meta' ],
      repo_url      => $url
    }
  );
}

sub plan {
  my ( $self ) = @_;
  my $plan = $self->SUPER::plan;
  $plan->{repo_url} = $plan->{source} && $plan->{source}{repo_url};
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
