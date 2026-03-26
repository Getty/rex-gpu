# ABSTRACT: GPU detection and driver management for Rex

package Rex::GPU;

use v5.14.4;
use warnings;

use Rex::GPU::Detect;
use Rex::GPU::NVIDIA;

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  gpu_detect
  gpu_setup
);

=head1 FUNCTIONS

=cut

=method gpu_detect

Detect GPUs on the current host. Returns a hashref with detected GPU
information:

  my $gpus = gpu_detect();
  # {
  #   nvidia => [ { name => "RTX 4090", pci_class => "0302", compute => 1 } ],
  #   amd    => [ { name => "Radeon RX 7900" } ],
  # }

=cut

sub gpu_detect {
  return Rex::GPU::Detect::detect();
}

=method gpu_setup

Detect GPUs and install appropriate drivers, container toolkit, and
configure the container runtime. One-stop function for making GPUs
available to Kubernetes.

Options:

  gpu_setup(
    containerd_config => 'rke2',  # 'rke2', 'k3s', 'containerd', or 'none'
  );

=cut

sub gpu_setup {
  my (%opts) = @_;

  my $gpus = gpu_detect();

  if ($gpus->{nvidia} && @{$gpus->{nvidia}}) {
    my @compute = grep { $_->{compute} } @{$gpus->{nvidia}};
    if (@compute) {
      Rex::Logger::info("CUDA-capable NVIDIA GPU: " . $compute[0]->{name});
      Rex::GPU::NVIDIA::install_driver();
      Rex::GPU::NVIDIA::install_container_toolkit();

      my $runtime = $opts{containerd_config} // 'rke2';
      if ($runtime ne 'none') {
        Rex::GPU::NVIDIA::configure_containerd($runtime);
      }
    }
  }

  if ($gpus->{amd} && @{$gpus->{amd}}) {
    Rex::Logger::info("AMD GPU detected — driver support not yet implemented", "warn");
  }

  return $gpus;
}

1;

=head1 SYNOPSIS

  use Rex::GPU;

  # Just detect
  my $gpus = gpu_detect();

  # Full setup (detect + install + configure)
  gpu_setup(containerd_config => 'rke2');

=head1 DESCRIPTION

L<Rex::GPU> provides GPU detection and driver management for L<Rex>.
It handles the complete stack needed to make GPUs available in Kubernetes:

=over

=item 1. GPU hardware detection via PCI class codes

=item 2. NVIDIA driver installation (Debian/Ubuntu, RHEL/Rocky)

=item 3. NVIDIA Container Toolkit installation

=item 4. Containerd runtime configuration (RKE2, K3s, standalone)

=back

=head1 SEE ALSO

L<Rex>, L<Rex::Rancher>, L<Rex::GPU::Detect>, L<Rex::GPU::NVIDIA>

=cut
