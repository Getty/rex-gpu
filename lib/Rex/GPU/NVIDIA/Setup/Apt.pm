# ABSTRACT: apt/dpkg packaging layer of the NVIDIA driver setups (experimental)

package Rex::GPU::NVIDIA::Setup::Apt;
our $VERSION = '0.002';
use Moo;
use Rex::Logger ();
use namespace::autoclean;

extends 'Rex::GPU::NVIDIA::Setup';

=attr apt_lock_timeout

Seconds C<apt-get> waits for the dpkg lock (C<-o DPkg::Lock::Timeout=>).
Default C<120>: on a fresh Hetzner boot cloud-init and unattended-upgrades
still hold it.

=cut

has apt_lock_timeout => ( is => 'ro', default => 120 );

sub _build_arch {
  my ( $self ) = @_;
  my $arch = $self->run_cmd('dpkg --print-architecture', auto_die => 0);
  chomp $arch;
  return $arch;
}

=method apt_get

  $self->apt_get           # "apt-get -o DPkg::Lock::Timeout=120"

The C<apt-get> invocation every command of this layer starts with.

=cut

sub apt_get {
  my ( $self ) = @_;
  return 'apt-get -o DPkg::Lock::Timeout='.$self->apt_lock_timeout;
}

=method kernel_packages

The running kernel's headers, C<linux-headers-$kernel>: enough for DKMS.
Never the C<linux-headers-$arch> metapackage, which pulls a new kernel whose
grub/initramfs post-install can exit non-zero. Reads the architecture first,
so C<dpkg --print-architecture> runs before any source is looked at, whether
or not the distro class needs it.

=cut

sub kernel_packages {
  my ( $self ) = @_;
  $self->arch;
  return 'linux-headers-'.$self->kernel;
}

=method prepare_host

Stops C<unattended-upgrades>, C<apt-daily> and C<apt-daily-upgrade>: on a
fresh boot they hold C</var/lib/dpkg/lock-frontend> and C<apt-get> fails at
once even with a lock timeout.

=cut

sub prepare_host {
  my ( $self, $plan ) = @_;
  $self->run_cmd('systemctl stop unattended-upgrades apt-daily.service apt-daily-upgrade.service 2>/dev/null || true',
    auto_die => 0);
}

=method prepare_source

C<apt-get update>, with C<auto_die =E<gt> 0>: it exits non-zero on snap/PPA
repository warnings that are no real failure. Whether it actually refreshed
the index shows in the next step, L<Rex::GPU::NVIDIA::Setup/resolve_plan>:
a driver source that reads the index finds nothing and dies there.

=cut

sub prepare_source {
  my ( $self, $plan ) = @_;
  $self->run_cmd($self->apt_get.' update -q', auto_die => 0);
}

=method install_packages

Logs the package list, then C<apt-get install -y> of
C<< $plan->{packages} >> through L<Rex::GPU::NVIDIA::Setup/run_cmd> with
C<auto_die =E<gt> 0> -- B<never> L<Rex::Commands::Pkg/pkg>. C<Rex::Pkg::Apt>
dies on any non-zero exit, and a DKMS module build, grub update or initramfs
regeneration routinely exits non-zero on success. Whether the install worked
is decided by L</verify_packages>, not by this exit code.

=cut

sub install_packages {
  my ( $self, $plan ) = @_;
  Rex::Logger::info('  Installing: '.join(', ', @{ $plan->{packages} }));
  my $pkg_str = join(' ', @{ $plan->{packages} });
  $self->run_cmd('DEBIAN_FRONTEND=noninteractive '.$self->apt_get.' install -y '.$pkg_str, auto_die => 0);
}

=method verify_packages

Dies unless every package in C<< $plan->{verify} >> is C<ii> in C<dpkg -l>.
A DKMS build that fails in postinst leaves the package half-configured (not
C<ii>), so a partial install dies here.

=cut

sub verify_packages {
  my ( $self, $plan ) = @_;
  for my $driver_pkg (@{ $plan->{verify} }) {
    my $check = $self->run_cmd("dpkg -l $driver_pkg 2>/dev/null | grep -q '^ii'", auto_die => 0);
    die "$driver_pkg not installed after apt-get install — check apt output\n"
      if $? != 0;
  }
}

=method initramfs_command

C<update-initramfs -u 2E<gt>/dev/null>.

=cut

sub initramfs_command { 'update-initramfs -u 2>/dev/null' }

# Pure (karr #26): does `apt-cache policy PKG` output (LC_ALL=C) show an
# installation candidate? An unknown package prints nothing; a known one with
# nothing installable prints "Candidate: (none)".
sub _apt_candidate_present {
  my ( $self, $policy ) = @_;
  return 0 unless defined $policy;
  my ($candidate) = $policy =~ /^\s*Candidate:\s*(\S+)/m;
  return (defined $candidate && $candidate ne '(none)') ? 1 : 0;
}

1;

=head1 DESCRIPTION

B<Experimental>, like L<Rex::GPU::NVIDIA::Setup>. The apt/dpkg half shared by
L<Rex::GPU::NVIDIA::Setup::Debian> and L<Rex::GPU::NVIDIA::Setup::Ubuntu>:
the lock timeout on every C<apt-get>, stopping the apt timers, C<apt-get
update>, C<apt-get install> run directly and C<dpkg -l ... ^ii> as the only
evidence of an install.

=head1 SEE ALSO

L<Rex::GPU::NVIDIA::Setup>

=cut
