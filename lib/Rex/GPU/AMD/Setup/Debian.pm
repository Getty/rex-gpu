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
AMD supports (the release's own C<amd64> kernel series, 6.12 and 6.1 -- a
backports kernel is not), the ROCm repository (C<debian13>, C<debian12>).

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

B<Experimental.> The AMD driver on Debian 12 and 13, per L</release_data>:

=over

=item * B<amdgpu-dkms> from C<repo.radeon.com/amdgpu/31.60/ubuntu> with
C<linux-headers-$(uname -r)>, on the release's own kernel only.

=item * B<inbox>: the kernel's own C<amdgpu>, plus C<firmware-amd-graphics>
when it is not installed (it needs the C<non-free-firmware> component; it
dies, before installing anything, if apt has no candidate). Debian's kernel
always carries C<amdgpu.ko>; there is no package to add it. The GPUs AMD
supports only with the inbox driver (the Ryzen APUs) are not supported on
Debian: it dies before any change.

=back

=head1 SEE ALSO

L<Rex::GPU::AMD::Setup>, L<Rex::GPU::AMD::Setup::Apt>

=cut
