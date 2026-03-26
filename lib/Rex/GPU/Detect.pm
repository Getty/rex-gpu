# ABSTRACT: GPU hardware detection via PCI class codes

package Rex::GPU::Detect;

use v5.14.4;
use warnings;

use Rex::Commands::Pkg;
use Rex::Commands::Run;
use Rex::Logger;

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  detect
);

# PCI class codes for display controllers
# [0300] = VGA controller, [0302] = 3D controller (datacenter GPUs)
my $PCI_DISPLAY_RE = qr/\[03(?:00|02)\]/;

# Virtual GPU vendor IDs — skip these (no host driver needed)
my $VIRTUAL_GPU_RE = qr/\[(?:1af4|1b36|15ad|80ee):[0-9a-f]{4}\]/i;

# NVIDIA vendor ID
my $NVIDIA_VENDOR_RE = qr/\[10de:[0-9a-f]{4}\]/i;

# AMD vendor ID
my $AMD_VENDOR_RE = qr/\[1002:[0-9a-f]{4}\]/i;

=head1 FUNCTIONS

=cut

=method detect

Detect GPU hardware on the current host using PCI class codes.
Ensures C<pciutils> is installed, then parses C<lspci -nn> output.

Returns a hashref:

  {
    nvidia => [ { name => "...", pci_class => "0302", compute => 1 } ],
    amd    => [ { name => "...", pci_class => "0300", compute => 0 } ],
  }

=cut

sub detect {
  # Ensure lspci is available
  pkg ["pciutils"], ensure => "present" unless is_installed("pciutils");

  my $pci_output = run "lspci -nn 2>&1 | grep -E '\\[03(00|02)\\]'",
    auto_die => 0;

  my $result = { nvidia => [], amd => [] };

  return $result unless $pci_output;

  # Skip virtual GPUs
  if ($pci_output =~ $VIRTUAL_GPU_RE) {
    Rex::Logger::info("Virtual GPU detected (virtio/QEMU/VMware/VBox) — skipping");
    return $result;
  }

  for my $line (split /\n/, $pci_output) {
    if ($line =~ $NVIDIA_VENDOR_RE) {
      my $gpu = _parse_nvidia_line($line);
      push @{$result->{nvidia}}, $gpu if $gpu;
    }
    elsif ($line =~ $AMD_VENDOR_RE) {
      my $gpu = _parse_amd_line($line);
      push @{$result->{amd}}, $gpu if $gpu;
    }
  }

  return $result;
}

sub _parse_nvidia_line {
  my ($line) = @_;

  my ($pci_class) = $line =~ /\[(03\d{2})\]/;
  my ($name) = $line =~ /:\s+NVIDIA\s+Corporation\s+(.+?)\s*\[10de:/;
  $name //= 'Unknown NVIDIA GPU';
  $pci_class //= '0300';

  my $compute = _is_nvidia_compute($pci_class, $name);

  my $status = $compute ? 'ok' : 'skip';
  Rex::Logger::info("  [$status] NVIDIA: $name (PCI class $pci_class)");

  return {
    name      => $name,
    vendor    => 'nvidia',
    pci_class => $pci_class,
    compute   => $compute,
  };
}

sub _is_nvidia_compute {
  my ($pci_class, $name) = @_;

  # PCI class [0302] = 3D Controller — always compute/datacenter GPU
  return 1 if $pci_class eq '0302';

  # Known compute-capable families
  return 1 if $name =~ /\b(RTX|TITAN|Quadro)\b/i;
  return 1 if $name =~ /\bGTX\s*(1[0-9]\d{2}|16\d{2})\b/i;
  return 1 if $name =~ /\b(Tesla|[AHLVP]\d{1,3}[GSi]?)\b/;

  # Non-compute GPUs
  return 0 if $name =~ /\bMX\s*\d/i;
  return 0 if $name =~ /\b(GT\s*\d|GTS\s*\d|NVS\s*\d)/i;
  return 0 if $name =~ /\bGTX\s*[2-9]\d{2}\b/i;

  # Unknown — safe default
  Rex::Logger::info("    Unknown NVIDIA GPU model: $name — not in compute list", "warn");
  return 0;
}

sub _parse_amd_line {
  my ($line) = @_;

  my ($pci_class) = $line =~ /\[(03\d{2})\]/;
  my ($name) = $line =~ /:\s+(?:Advanced Micro Devices|AMD\/ATI)\s+.*?\s+(.+?)\s*\[1002:/;
  $name //= 'Unknown AMD GPU';
  $pci_class //= '0300';

  Rex::Logger::info("  [info] AMD: $name (PCI class $pci_class)");

  return {
    name      => $name,
    vendor    => 'amd',
    pci_class => $pci_class,
    compute   => 0,  # AMD compute support not yet implemented
  };
}

1;
