# ABSTRACT: rpm packaging layer of the NVIDIA driver setups (experimental)

package Rex::GPU::NVIDIA::Setup::Rpm;
our $VERSION = '0.002';
use Moo;
use Rex::Logger ();
use namespace::autoclean;

extends 'Rex::GPU::NVIDIA::Setup';

=method package_manager

The command that installs packages on this layer: C<dnf> here,
C<zypper> in L<Rex::GPU::NVIDIA::Setup::SUSE>. It also names the package
manager in the L</verify_packages> error.

=cut

sub package_manager { 'dnf' }

=method install_packages

C<< <package_manager> install -y >> of C<< $plan->{packages} >> through
L<Rex::GPU::NVIDIA::Setup/run_cmd> with C<auto_die =E<gt> 0> -- B<never>
L<Rex::Commands::Pkg/pkg>. C<Rex::Pkg::Dnf> dies on any non-zero exit, and
the DKMS module build or initramfs regeneration in a driver package's
scriptlets routinely exits non-zero on success. Whether the install worked
is decided by L</verify_packages>, not by this exit code.

=cut

sub install_packages {
  my ( $self, $plan ) = @_;
  Rex::Logger::info('  Installing: '.join(', ', @{ $plan->{packages} }));
  my $pkg_str = join(' ', @{ $plan->{packages} });
  $self->run_cmd($self->package_manager.' install -y '.$pkg_str, auto_die => 0);
}

=method verify_packages

Dies unless L</verify_query> succeeds for every entry in
C<< $plan->{verify} >>. An empty list verifies nothing.

=method verify_query

  my $cmd = $self->verify_query('nvidia-driver');

The C<rpm> query L</verify_packages> runs for one entry: C<rpm -q NAME>, so
an entry is a package name. L<Rex::GPU::NVIDIA::Setup::SUSE> asks
C<rpm -q --whatprovides> instead, so its entries can be capabilities.

=cut

sub verify_query {
  my ( $self, $what ) = @_;
  return 'rpm -q '.$what;
}

sub verify_packages {
  my ( $self, $plan ) = @_;
  my $pm = $self->package_manager;
  for my $driver_pkg (@{ $plan->{verify} }) {
    my $check = $self->run_cmd($self->verify_query($driver_pkg).' 2>&1', auto_die => 0);
    die "$driver_pkg not installed after $pm install — check $pm output\n"
      if $? != 0;
  }
}

# Pure (karr #26): is this `rpm -q --qf '%{VERSION}'` output a version of
# driver branch $branch ("580.178.04" is branch 580)? Anything else -- another
# branch, "package ... is not installed", empty -- is false.
sub _rpm_version_in_branch {
  my ( $self, $version, $branch ) = @_;
  return 0 unless defined $version && defined $branch;
  return $version =~ /^\Q$branch\E\./ ? 1 : 0;
}

1;

=head1 DESCRIPTION

B<Experimental>, like L<Rex::GPU::NVIDIA::Setup>. The rpm half shared by
L<Rex::GPU::NVIDIA::Setup::RHEL> (C<dnf>) and
L<Rex::GPU::NVIDIA::Setup::SUSE> (C<zypper>): the package manager's
C<install -y> run directly and C<rpm -q> as the only evidence of an
install. The initramfs is rebuilt with the base class's C<dracut>.

=head1 SEE ALSO

L<Rex::GPU::NVIDIA::Setup>

=cut
