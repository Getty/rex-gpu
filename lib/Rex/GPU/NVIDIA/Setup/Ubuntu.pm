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
filtered out).

=item * C<ubuntu-server-open> -- the newest
C<nvidia-driver-NNN-server-open> (open kernel module).

=item * C<ubuntu-server-580> -- C<nvidia-driver-580-server>, proprietary,
branch 580 exactly. Its installation candidate is checked after
C<apt-get update> (L</resolve_source>); no other branch is substituted.

=back

L<Rex::GPU::NVIDIA::Setup/plan> chooses among them without a package index:
the first two count as "newest branch, at least 580" -- 580 is in the
archive of every supported release -- so they fit a GPU that needs 570 or
580 or newer but never one that stops at 580. Which package that is, and
its exact branch, is looked up only after C<apt-get update>
(L</resolve_source>) and checked again; nothing found, or a branch the GPU
cannot use, dies before any driver package is installed. There is no
hard-coded fallback package, and no other source is tried then.

So a GPU without constraints (Turing to Hopper, no GPU) gets
C<ubuntu-server>, Blackwell C<ubuntu-server-open>, Maxwell/Pascal/Volta
C<ubuntu-server-580>.

Each names C<nvidia-fabricmanager-NNN> as its Fabric Manager (for a host
with NVSwitches, see L<Rex::GPU::NVIDIA::Setup/nvswitches>): NNN is the
branch found after C<apt-get update>, and it is installed at the upstream
version of the installed C<nvidia-driver-NNN-server(-open)>.

Never C<nvidia-smi>: on 24.04 it is a virtual package with no installation
candidate, and the driver metapackage pulls it in anyway.

=cut

# 580 is published for jammy and noble (Launchpad, source
# nvidia-graphics-drivers-580-server, checked 2026-09-23: 580.178.04 on both,
# next to 590 and 595). The apt-cache search runs in resolve_source, after
# `apt-get update` -- before it, a fresh image's index is stale or empty
# (karr #35).
#
# Fabric Manager (karr #23): Ubuntu's archive builds nvidia-fabricmanager-NNN
# (source fabric-manager-NNN) for each -server branch, one package for the
# proprietary and the -open driver; it Depends on the virtual
# nvidia-kernel-common-NNN-server-<exact upstream version>, and on noble and
# jammy it carries exactly the version string of nvidia-driver-NNN-server
# (packages.ubuntu.com, 580.178.04-0ubuntu0.24.04.1 / 22.04.1, checked
# 2026-09-24).
sub sources {
  my ( $self ) = @_;
  my %fm = ( fabric_manager => 'nvidia-fabricmanager-%s' );
  return (
    {
      name            => 'ubuntu-server',
      kernel_module   => 'proprietary',
      branch_at_least => 580,
      search          => '^nvidia-driver-[0-9].*-server$',
      %fm,
      fabric_manager_match => 'nvidia-driver-%s-server'
    },
    {
      name            => 'ubuntu-server-open',
      kernel_module   => 'open',
      branch_at_least => 580,
      search          => '^nvidia-driver-[0-9].*-server-open$',
      %fm,
      fabric_manager_match => 'nvidia-driver-%s-server-open'
    },
    {
      name            => 'ubuntu-server-580',
      kernel_module   => 'proprietary',
      branch          => 580,
      packages        => [ 'nvidia-driver-580-server' ],
      verify          => [ 'nvidia-driver-580-server' ],
      check_candidate => 'nvidia-driver-580-server',
      %fm,
      fabric_manager_match => 'nvidia-driver-580-server'
    }
  );
}

=method resolve_source

Runs after the apt layer's C<apt-get update>
(L<Rex::GPU::NVIDIA::Setup/resolve_plan>), read-only:

=over

=item * a source with a C<search> pattern: C<apt-cache search> for the
newest matching package; returns the source with that one package (installed
and verified) and the exact branch from its name. Nothing found, or a name
without a branch, makes it C<unavailable> -- there is no fallback package:
if the refreshed index does not list one, C<apt-get install> could not
install it either.

=item * a source with C<check_candidate>: C<apt-cache policy> must show an
installation candidate for that package, else the source is
C<unavailable>. No other package is substituted.

=back

Any other source is returned unchanged. A subclass that picks the package
another way overrides this method; the requirement check after it stays.

=cut

sub resolve_source {
  my ( $self, $source ) = @_;
  if (defined $source->{search}) {
    my $latest = $self->run_cmd("apt-cache search '$source->{search}' 2>/dev/null | sort -t- -k3 -n | tail -1 | awk '{print \$1}'",
      auto_die => 0);
    chomp $latest if $latest;
    # Filter out *-open variants from auto-detect (use regular server driver)
    $latest = undef if $latest && $source->{kernel_module} ne 'open' && $latest =~ /-open$/;
    return { %$source, unavailable => "apt-cache search '".$source->{search}."' finds no "
      .'package after apt-get update (did the update fail, or is the restricted '
      .'component missing from the apt sources?)' }
      unless $latest;
    my ($branch) = $latest =~ /^nvidia-driver-(\d+)-server/;
    return { %$source, unavailable => 'no driver branch in the package name '.$latest }
      unless defined $branch;
    my %resolved = ( %$source, packages => [ $latest ], verify => [ $latest ], branch => $branch );
    delete $resolved{branch_at_least};
    return \%resolved;
  }
  if (defined $source->{check_candidate}) {
    my $pinned = $source->{check_candidate};
    my $policy = $self->run_cmd("LC_ALL=C apt-cache policy $pinned 2>/dev/null", auto_die => 0);
    return { %$source, unavailable => $pinned.' has no installation candidate after '
      .'apt-get update, and no other package is substituted' }
      unless $self->_apt_candidate_present($policy);
  }
  return $source;
}

1;

=head1 DESCRIPTION

B<Experimental>, like L<Rex::GPU::NVIDIA::Setup>. The NVIDIA driver install
for Ubuntu: the C<-server> driver packages from Ubuntu's own archive on the
apt layer L<Rex::GPU::NVIDIA::Setup::Apt>.

=head1 SEE ALSO

L<Rex::GPU::NVIDIA::Setup>, L<Rex::GPU::NVIDIA/install_driver>

=cut
