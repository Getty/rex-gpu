# ABSTRACT: NVIDIA driver setup for Ubuntu (experimental)

package Rex::GPU::NVIDIA::Setup::Ubuntu;
our $VERSION = '0.002';
use Moo;
use Rex::Logger ();
use namespace::autoclean;

extends 'Rex::GPU::NVIDIA::Setup::Apt';

=method plan

Adds C<linux-headers-generic> and one driver package, which is also the one
verified:

=over

=item * Pre-Turing (Maxwell/Pascal/Volta): C<nvidia-driver-580-server>
(L</legacy_driver_package>), proprietary, no other branch substituted;
C<< $plan->{legacy_package} >> is set so L</prepare_source> checks its
candidate.

=item * Blackwell: the newest C<nvidia-driver-NNN-server-open> that
C<apt-cache search> finds, else C<nvidia-driver-570-server-open>.

=item * Every other GPU: the newest C<nvidia-driver-NNN-server> (C<-open>
filtered out), else C<nvidia-driver-570-server>.

=back

Never C<nvidia-smi>: on 24.04 it is a virtual package with no installation
candidate, and the driver metapackage pulls it in anyway.

=cut

sub plan {
  my ( $self ) = @_;
  my $plan = $self->SUPER::plan;
  push @{ $plan->{packages} }, 'linux-headers-generic';

  # Blackwell-architecture silicon (B200/GB200, GeForce RTX 50xx, RTX PRO
  # Blackwell, the GB10 / DGX Spark) ships with NO proprietary kernel module
  # -- only the -open variant binds, on x86_64 as on arm64 (karr
  # #14/#15/#16). Keyed on the PCI device ID only; any other GPU, or none,
  # keeps -server.
  #
  # Pre-Turing (Maxwell/Pascal/Volta, e.g. V100) (karr #26): the newest
  # -server is a branch that no longer supports them, so pin the last one
  # that does, proprietary. Its candidate is checked after apt-get update --
  # fail loud, never a silent fallback to another branch.
  my $legacy_pkg = $self->legacy_driver_package($self->gpu);
  if ($legacy_pkg) {
    Rex::Logger::info("  Pre-Turing GPU — pinning the proprietary $legacy_pkg");
    push @{ $plan->{packages} }, $legacy_pkg;
    $plan->{legacy_package} = $legacy_pkg;
  }
  else {
    my $open = $self->_needs_open_kernel_module($self->gpu);
    if ($open) {
      Rex::Logger::info('  Blackwell-class GPU on '.$self->arch.' — selecting the open-kernel-module driver');
    }
    my $search_pattern = $open
      ? '^nvidia-driver-[0-9].*-server-open$'
      : '^nvidia-driver-[0-9].*-server$';
    my $latest = $self->run_cmd("apt-cache search '$search_pattern' 2>/dev/null | sort -t- -k3 -n | tail -1 | awk '{print \$1}'",
      auto_die => 0);
    chomp $latest if $latest;
    unless ($open) {
      # Filter out *-open variants from auto-detect (use regular server driver)
      $latest = undef if $latest && $latest =~ /-open$/;
    }
    push @{ $plan->{packages} },
      ($latest || ($open ? 'nvidia-driver-570-server-open' : 'nvidia-driver-570-server'));
  }

  # The driver package actually chosen, e.g. nvidia-driver-590-server(-open)
  $plan->{verify} = [ $plan->{packages}[-1] ];
  return $plan;
}

=method prepare_source

After the apt layer's C<apt-get update>, for a pinned pre-Turing package:
dies unless C<apt-cache policy> shows an installation candidate for it. No
other branch is substituted and nothing has been installed yet.

=cut

sub prepare_source {
  my ( $self, $plan ) = @_;
  $self->SUPER::prepare_source($plan);
  my $legacy_pkg = $plan->{legacy_package} or return;
  my $policy = $self->run_cmd("LC_ALL=C apt-cache policy $legacy_pkg 2>/dev/null", auto_die => 0);
  die "$legacy_pkg has no installation candidate on this ".$self->os." host — it is the "
    . "newest driver that supports this pre-Turing GPU and no other branch is "
    . "substituted; no driver was installed\n"
    unless $self->_apt_candidate_present($policy);
}

=method legacy_driver_package

  my $pkg = $self->legacy_driver_package($gpu);

Pure. C<nvidia-driver-580-server> (the proprietary package: the C<-open>
variant does not support these chips) for a pre-Turing GPU, C<undef> for
every other. A Kepler-or-older GPU never gets here: L</plan> rejected it.

=cut

sub legacy_driver_package {
  my ( $self, $gpu ) = @_;
  my $legacy = $self->_legacy_requirement($gpu);
  return unless $legacy;
  return "nvidia-driver-$legacy->{max_branch}-server";
}

1;

=head1 DESCRIPTION

B<Experimental>, like L<Rex::GPU::NVIDIA::Setup>. The NVIDIA driver install
for Ubuntu: the C<-server> driver packages from Ubuntu's own archive on the
apt layer L<Rex::GPU::NVIDIA::Setup::Apt>.

=head1 SEE ALSO

L<Rex::GPU::NVIDIA::Setup>, L<Rex::GPU::NVIDIA/install_driver>

=cut
