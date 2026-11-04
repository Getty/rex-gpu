# ABSTRACT: AMD driver setup for Debian 12 and 13 (experimental)

package Rex::GPU::AMD::Setup::Debian;
our $VERSION = '0.006';
use Moo;
use namespace::autoclean;

extends 'Rex::GPU::AMD::Setup::Apt';

# Sources, checked 2026-10-30:
#   ROCm 10.1 compatibility matrix (Instinct): Debian 13 kernel 6.12, Debian
#     12 kernel 6.1.0; no Radeon and no Ryzen APU support on Debian.
#   amdgpu 31.60 install guide, Debian: the Ubuntu repository of
#     repo.radeon.com, suite noble for Debian 13 and jammy for Debian 12;
#     linux-headers-$K.
#   Debian's firmware for amdgpu: firmware-amd-graphics (component
#     non-free-firmware).
my %RELEASE = (
  '13' => { suite => 'noble', kernel => qr/\A6\.12\.\d+\+deb13(?:u\d+)?-amd64\z/,
            kernel_text => '6.12 (6.12.N+deb13-amd64)', rocm => 'debian13' },
  '12' => { suite => 'jammy', kernel => qr/\A6\.1\.0-\d+-amd64\z/,
            kernel_text => '6.1 (6.1.0-N-amd64)', rocm => 'debian12' },
);

=method release_data

The row of this Debian release (C<VERSION_ID> C<13> or C<12>), C<undef>
for another one: the C<amdgpu-dkms> suite (C<noble>, C<jammy>), the kernel
it is installed on (AMD's 6.12 and 6.1, as the release's own kernel of the
flavour C<amd64>: C<6.12.N+deb13-amd64>, C<6.1.0-N-amd64> -- not
C<cloud-amd64>, C<rt-amd64> or a backports kernel), the ROCm repository
(C<debian13>, C<debian12>). Only the C<amdgpu-dkms> path and
L<Rex::GPU::AMD/install_rocm> read it; the inbox path does not.

=cut

sub release_data { $RELEASE{ $_[0]->os_version } }

sub dkms_suite {
  my ( $self ) = @_;
  my $row = $self->release_data or return;
  return $row->{suite};
}

sub dkms_unsupported {
  my ( $self ) = @_;
  my $row = $self->release_data
    or return 'amdgpu-dkms '.$self->amdgpu_release.' supports Debian 12 and 13, not '.$self->os_label;
  return if $self->kernel =~ $row->{kernel};
  return 'amdgpu-dkms '.$self->amdgpu_release.' supports '.$self->os_label.' with kernel '
    .$row->{kernel_text}.'; this host runs '.$self->kernel;
}

sub kernel_header_packages { 'linux-headers-'.$_[0]->kernel }

sub firmware_packages { 'firmware-amd-graphics' }

sub rocm_repo_dir {
  my ( $self ) = @_;
  my $row = $self->release_data or return;
  return $row->{rocm};
}

1;

=head1 DESCRIPTION

B<Experimental.> The AMD driver on Debian:

=over

=item * B<amdgpu-dkms> on Debian 12 and 13, per L</release_data>: from
C<repo.radeon.com/amdgpu/31.60/ubuntu> with C<linux-headers-$(uname -r)>,
on the release's own C<amd64> kernel only.

=item * B<inbox>, which checks neither the release nor the kernel series
(L</release_data> is not read): the kernel's own C<amdgpu>, plus
C<firmware-amd-graphics> when it is not installed (on Debian 12 and 13 it
is in the C<non-free-firmware> component; it dies, before installing
anything, if apt has no candidate). No package is known that adds a
missing C<amdgpu.ko> (Debian's C<amd64> kernel carries it): it dies then,
before any change. The GPUs AMD supports only with the inbox driver (the
Ryzen APUs, rows with C<driver =E<gt> 'inbox'>) are not supported on
Debian: L<Rex::GPU::AMD/install_driver> dies before any change for them,
unless their driver already works, which it answers with C<present>
(C<method =E<gt> 'dkms'> dies then too).

=back

=head1 SEE ALSO

L<Rex::GPU::AMD::Setup>, L<Rex::GPU::AMD::Setup::Apt>

=cut
