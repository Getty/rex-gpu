# ABSTRACT: NVIDIA driver setup for Ubuntu (experimental)

package Rex::GPU::NVIDIA::Setup::Ubuntu;
our $VERSION = '0.002';
use Moo;
use Rex::Logger ();
use namespace::autoclean;

extends 'Rex::GPU::NVIDIA::Setup::Apt';

=method kernel_packages

The apt layer's running-kernel headers, plus C<linux-headers-generic>.

=cut

sub kernel_packages {
  my ( $self ) = @_;
  return ( $self->SUPER::kernel_packages, 'linux-headers-generic' );
}

=method sources

Ubuntu's own C<-server> driver packages, in this order; each installs one
package, which is also the one verified:

=over

=item * C<ubuntu-server> -- the newest C<nvidia-driver-NNN-server>
(proprietary kernel module) that C<apt-cache search> finds (C<-open>
filtered out), else C<nvidia-driver-570-server>.

=item * C<ubuntu-server-open> -- the newest
C<nvidia-driver-NNN-server-open> (open kernel module), else
C<nvidia-driver-570-server-open>.

=item * C<ubuntu-server-580> -- C<nvidia-driver-580-server>, proprietary,
branch 580 exactly. Its installation candidate is checked after
C<apt-get update> (L</prepare_source>); no other branch is substituted.

=back

Before the search, the first two count as "newest branch, at least 580":
580 is in the archive of every supported release, so they fit a GPU that
needs 570 or 580 or newer but never one that stops at 580. The search
(L</resolve_source>) then gives the exact branch, which is checked again: an
empty search falls back to 570, which a GPU needing 580 or newer rejects.

So a GPU without constraints (Turing to Hopper, no GPU) gets
C<ubuntu-server>, Blackwell C<ubuntu-server-open>, Maxwell/Pascal/Volta
C<ubuntu-server-580>.

Never C<nvidia-smi>: on 24.04 it is a virtual package with no installation
candidate, and the driver metapackage pulls it in anyway.

=cut

# 580 is published for jammy and noble (Launchpad, source
# nvidia-graphics-drivers-580-server, checked 2026-09-23: 580.178.04 on both,
# next to 590 and 595). The apt-cache search runs in plan, against the index
# of the last `apt-get update` -- stale on a fresh host (karr #35).
sub sources {
  my ( $self ) = @_;
  return (
    {
      name            => 'ubuntu-server',
      kernel_module   => 'proprietary',
      branch_at_least => 580,
      search          => '^nvidia-driver-[0-9].*-server$',
      fallback        => 'nvidia-driver-570-server'
    },
    {
      name            => 'ubuntu-server-open',
      kernel_module   => 'open',
      branch_at_least => 580,
      search          => '^nvidia-driver-[0-9].*-server-open$',
      fallback        => 'nvidia-driver-570-server-open'
    },
    {
      name            => 'ubuntu-server-580',
      kernel_module   => 'proprietary',
      branch          => 580,
      packages        => [ 'nvidia-driver-580-server' ],
      verify          => [ 'nvidia-driver-580-server' ],
      check_candidate => 'nvidia-driver-580-server'
    }
  );
}

=method resolve_source

For a source with a C<search> pattern: runs C<apt-cache search> (read-only)
for the newest matching package, else takes the C<fallback>, and returns the
source with that one package and the branch in its name.

=cut

sub resolve_source {
  my ( $self, $source ) = @_;
  return $source unless defined $source->{search};
  my $latest = $self->run_cmd("apt-cache search '$source->{search}' 2>/dev/null | sort -t- -k3 -n | tail -1 | awk '{print \$1}'",
    auto_die => 0);
  chomp $latest if $latest;
  # Filter out *-open variants from auto-detect (use regular server driver)
  $latest = undef if $latest && $source->{kernel_module} ne 'open' && $latest =~ /-open$/;
  my $pkg = $latest || $source->{fallback};
  my ($branch) = $pkg =~ /^nvidia-driver-(\d+)-server/;
  return {
    %$source,
    packages => [ $pkg ],
    verify   => [ $pkg ],
    defined $branch ? ( branch => $branch ) : ()
  };
}

=method prepare_source

After the apt layer's C<apt-get update>, for a source with
C<check_candidate> (C<ubuntu-server-580>): dies unless C<apt-cache policy>
shows an installation candidate for it. No other branch is substituted and
nothing has been installed yet.

=cut

sub prepare_source {
  my ( $self, $plan ) = @_;
  $self->SUPER::prepare_source($plan);
  my $pinned = $plan->{source} && $plan->{source}{check_candidate} or return;
  my $policy = $self->run_cmd("LC_ALL=C apt-cache policy $pinned 2>/dev/null", auto_die => 0);
  die "$pinned has no installation candidate on this ".$self->os." host — it is the "
    . "newest driver that supports this pre-Turing GPU and no other branch is "
    . "substituted; no driver was installed\n"
    unless $self->_apt_candidate_present($policy);
}

1;

=head1 DESCRIPTION

B<Experimental>, like L<Rex::GPU::NVIDIA::Setup>. The NVIDIA driver install
for Ubuntu: the C<-server> driver packages from Ubuntu's own archive on the
apt layer L<Rex::GPU::NVIDIA::Setup::Apt>.

=head1 SEE ALSO

L<Rex::GPU::NVIDIA::Setup>, L<Rex::GPU::NVIDIA/install_driver>

=cut
