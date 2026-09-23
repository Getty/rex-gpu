# ABSTRACT: GPU hardware detection via PCI class codes

package Rex::GPU::Detect;
our $VERSION = '0.002';
use v5.14.4;
use warnings;

use Rex::Commands::Pkg;
use Rex::Commands::Run;
use Rex::Logger;
use Rex::GPU::NVIDIA::Requirement;

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

# Known compute-capable NVIDIA PCI device IDs (lowercase, from the
# [10de:XXXX] field). Grace-Blackwell parts such as the GB10 (10de:2e12,
# NVIDIA DGX Spark, aarch64) enumerate as a VGA controller [0300] and, on a
# host whose /usr/share/misc/pci.ids predates the silicon, lspci prints only
# "Device" with no marketing name — so the name-token rules in
# _is_nvidia_compute cannot recognise them. The device ID is the one signal
# always present in lspci output regardless of pci.ids freshness. Add ONLY
# desktop, workstation or datacenter IDs taken from NVIDIA's table, never a
# laptop chip; this does not change the unknown-model default (still
# compute => 0).
#
# This list only makes a device compute. Which driver it needs (open or
# proprietary kernel module, which branches) is NOT kept here: that is the
# generation table in Rex::GPU::NVIDIA::Requirement (karr #30), which also
# holds the GB10 open-kernel-module row (karr #15) this entry used to flag.
#
# Blackwell desktop and workstation/server cards (karr #21): GeForce RTX 50xx
# desktop and RTX PRO Blackwell (workstation, SFF, Max-Q, Server Edition)
# can enumerate as VGA [0300] too (a card at 3D [0302] is compute by class
# anyway), and a stale pci.ids ("Device [10de:2b85]") skips them the same
# way. IDs and names are taken verbatim from NVIDIA's supported-chips table,
# driver 615.71.09: README/supportedchips.html
# (us.download.nvidia.com/XFree86/Linux-x86_64/615.71.09/) and the identical
# table in the open-gpu-kernel-modules README at 615.71.09. One entry per
# device ID; subsystem-ID variants of the same card share it. Deliberately
# NOT listed, although in the same tables and the 2900-2FFF range:
#   * every "Laptop GPU" / "Generation Laptop GPU" (RTX 50xx mobile, RTX PRO
#     500-5000 Blackwell laptop): 2C18 2C19 2C38 2C39 2C58 2C59 2D18 2D19
#     2D39 2D58 2D59 2D98 2DB8 2DB9 2DD8 2F18 2F38 2F58;
#   * RTX PRO Blackwell "Embedded GPU" modules: 2C77 2C79 2D79 2DF9;
#   * RTX 6000D (2BB9), DRIVE P2021 (29BB), and B200/GB200/B300/GB300, which
#     enumerate as 3D controller [0302] and are compute by class anyway.
# There is no range match: a new card is compute by ID only once its ID is
# added here from NVIDIA's table.
my %NVIDIA_COMPUTE_DEVICE_IDS = (
  '2e12' => { name => 'GB10' },
  # NVIDIA GB10 (Grace-Blackwell, DGX Spark) — verified on aarch64.

  # GeForce RTX 50xx, desktop
  '2b85' => { name => 'GeForce RTX 5090' },
  '2b87' => { name => 'GeForce RTX 5090 D' },
  '2b8c' => { name => 'GeForce RTX 5090 D v2' },
  '2c02' => { name => 'GeForce RTX 5080' },
  '2c05' => { name => 'GeForce RTX 5070 Ti' },
  '2c09' => { name => 'GeForce RTX 5070' },
  '2f04' => { name => 'GeForce RTX 5070' },
  '2d04' => { name => 'GeForce RTX 5060 Ti' },
  '2d05' => { name => 'GeForce RTX 5060' },
  '2f06' => { name => 'GeForce RTX 5060' },
  '2d83' => { name => 'GeForce RTX 5050' },

  # RTX PRO Blackwell, workstation and server
  '2bb1' => { name => 'RTX PRO 6000 Blackwell Workstation Edition' },
  '2bb4' => { name => 'RTX PRO 6000 Blackwell Max-Q Workstation Edition' },
  '2bb5' => { name => 'RTX PRO 6000 Blackwell Server Edition' },
  '2bb3' => { name => 'RTX PRO 5000 Blackwell / RTX PRO 5000 72GB Blackwell' },
  '2c31' => { name => 'RTX PRO 4500 Blackwell' },
  '2c3a' => { name => 'RTX PRO 4500 Blackwell Server Edition' },
  '2c34' => { name => 'RTX PRO 4000 Blackwell' },
  '2c33' => { name => 'RTX PRO 4000 Blackwell SFF Edition' },
  '2d30' => { name => 'RTX PRO 2000 Blackwell' }
);

# Rex::GPU::Detect::open_kernel_module_required and legacy_driver_requirement
# below are wrappers over Rex::GPU::NVIDIA::Requirement, kept with their exact
# return values for Rex::GPU::NVIDIA's install paths (epic karr #25).

=head1 FUNCTIONS

=cut

=method detect

Detect GPU hardware on the remote host. Ensures C<pciutils> is installed,
then parses C<lspci -nn> output filtered to PCI display-class devices
(class codes C<03xx>).

Returns a hashref with C<nvidia> and C<amd> array refs. Each element is a
hashref describing one detected GPU:

  {
    nvidia => [
      {
        name      => "AD104GL [RTX 4000 SFF Ada Generation]",
        vendor    => "nvidia",
        pci_class => "0302",   # "0300" = VGA controller, "0302" = 3D controller
        compute   => 1,        # 1 if CUDA-capable, 0 otherwise
        device_id => "27b0",  # [10de:XXXX]; undef if lspci printed no vendor:device pair
      }
    ],
    amd => [
      {
        name      => "Navi 31 [Radeon RX 7900 XTX]",
        vendor    => "amd",
        pci_class => "0300",
        compute   => 0,        # AMD compute support not yet implemented
      }
    ],
  }

If no supported GPU is found, or if the only display devices are virtual,
both arrays are empty (C<[]>). A virtual display next to a real NVIDIA/AMD
card (GPU passthrough, cloud GPU VM) is skipped on its own line and the real
card is still reported.

=cut

sub detect {
  # Ensure lspci is available
  pkg ["pciutils"], ensure => "present" unless is_installed("pciutils");

  my $pci_output = run "lspci -nn 2>&1 | grep -E '\\[03(00|02)\\]'",
    auto_die => 0;

  my $result = { nvidia => [], amd => [] };

  return $result unless $pci_output;

  # Virtual displays are skipped PER LINE, not by matching the whole blob: a
  # passthrough host (vfio-pci) or cloud GPU VM shows an emulated console
  # (QXL, virtio-vga, ...) next to the real card, and a blob match hid the
  # real card (karr #17). Vendor checks run first, so a [10de:]/[1002:] line
  # is never classified virtual — only a line that is not NVIDIA/AMD can be.
  my $virtual = 0;
  for my $line (split /\n/, $pci_output) {
    if ($line =~ $NVIDIA_VENDOR_RE) {
      my $gpu = _parse_nvidia_line($line);
      push @{$result->{nvidia}}, $gpu if $gpu;
    }
    elsif ($line =~ $AMD_VENDOR_RE) {
      my $gpu = _parse_amd_line($line);
      push @{$result->{amd}}, $gpu if $gpu;
    }
    elsif ($line =~ $VIRTUAL_GPU_RE) {
      $virtual++;
      Rex::Logger::info("  [skip] virtual display: $line");
    }
  }

  Rex::Logger::info("Virtual GPU detected (virtio/QEMU/VMware/VBox) — skipping")
    if $virtual && !@{$result->{nvidia}} && !@{$result->{amd}};

  return $result;
}

sub _parse_nvidia_line {
  my ($line) = @_;

  my ($pci_class) = $line =~ /\[(03\d{2})\]/;
  my ($device_id) = $line =~ /\[10de:([0-9a-f]{4})\]/i;
  my ($name) = $line =~ /:\s+NVIDIA\s+Corporation\s+(.+?)\s*\[10de:/;
  $name //= 'Unknown NVIDIA GPU';
  $pci_class //= '0300';

  my $compute = _is_nvidia_compute($pci_class, $name, $device_id);

  my $status = $compute ? 'ok' : 'skip';
  Rex::Logger::info("  [$status] NVIDIA: $name (PCI class $pci_class)");

  return {
    name      => $name,
    vendor    => 'nvidia',
    pci_class => $pci_class,
    compute   => $compute,
    device_id => $device_id,   # e.g. "2e12"; undef if the line had no [10de:XXXX]
  };
}

sub _is_nvidia_compute {
  my ($pci_class, $name, $device_id) = @_;

  # PCI class [0302] = 3D Controller — always compute/datacenter GPU
  return 1 if $pci_class eq '0302';

  # Known compute-capable PCI device IDs. Covers Grace-Blackwell parts (e.g.
  # GB10), GeForce RTX 50xx desktop and RTX PRO Blackwell cards that
  # enumerate as VGA [0300] and whose marketing name lspci cannot resolve
  # from a stale pci.ids. This is a positive allowlist only; it never
  # changes the unknown-model default below (still 0).
  return 1 if defined $device_id
    && $NVIDIA_COMPUTE_DEVICE_IDS{lc $device_id};

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

=method open_kernel_module_required

  Rex::GPU::Detect::open_kernel_module_required($device_id);

Given an NVIDIA PCI device ID (the C<XXXX> in C<[10de:XXXX]>, lowercase or
uppercase), returns true if that device is known to have B<no> proprietary
kernel module at all — NVIDIA's I<open> GPU kernel modules are the only
option: every Blackwell-architecture part, on any CPU architecture. True for
an ID in the Blackwell device-ID ranges taken from NVIDIA's
open-gpu-kernel-modules supported-GPU table (C<2900>-C<2FFF>: B200, GB200,
GeForce RTX 50xx, RTX PRO Blackwell, GB10; plus B300 C<3182> and GB300
C<31C2>/C<31C3>). Returns false for C<undef>, a malformed ID, and every ID
outside those ranges — Turing/Ampere/Ada/Hopper parts and any future
generation keep the default proprietary C<-server> selection. The ranges only
choose the driver variant; they never make a GPU compute-capable.

A wrapper: true exactly when
L<Rex::GPU::NVIDIA::Requirement/for_device_id> gives C<kernel_module> C<open>.
The device-ID ranges live in that class's
L<generations|Rex::GPU::NVIDIA::Requirement/generations> table only, so the
driver installer carries no second hardcoded device list.

Not in C<@EXPORT> — this is a C<Rex::GPU::NVIDIA>-internal lookup, not a
Rexfile-facing command.

=cut

sub open_kernel_module_required {
  my ($device_id) = @_;
  return Rex::GPU::NVIDIA::Requirement->for_device_id($device_id)->kernel_module eq 'open'
    ? 1 : 0;
}

=method legacy_driver_requirement

  my $legacy = Rex::GPU::Detect::legacy_driver_requirement($device_id);
  # { generation => 'Maxwell/Pascal/Volta', max_branch => 580 } or undef

Given an NVIDIA PCI device ID (the C<XXXX> in C<[10de:XXXX]>, any case),
returns a hashref for a pre-Turing GPU that current NVIDIA drivers no longer
support: C<generation> (a label for messages) and C<max_branch>, the newest
driver branch that still does. These GPUs work only with NVIDIA's
I<proprietary> kernel module; the open module does not support them.

=over

=item * C<1340>-C<1DF6> — Maxwell, Pascal and Volta (Tesla M60/M40, P100, P40,
P4, V100, V100S, TITAN V, GeForce 9xx/10xx, ...): C<max_branch> C<580>.

=item * below C<1340> — Kepler (C<0FC6>-C<12BA>, Tesla K80/K40) and older
(Fermi and earlier): C<max_branch> C<470>.

=back

Returns C<undef> for C<undef>, a malformed ID, and every ID from C<1DF7> up
(Turing and every later or unknown generation), which keep the default driver
selection. The ranges are taken from the legacy sections of NVIDIA's
C<supportedchips> README (driver 615.71.09). Like
L</open_kernel_module_required> this only chooses the driver; it never makes a
GPU compute-capable.

A wrapper over L<Rex::GPU::NVIDIA::Requirement/for_device_id>: a hashref of
its C<generation> and C<max_branch> when the requirement has a
C<max_branch>, C<undef> otherwise.

Not in C<@EXPORT> — a C<Rex::GPU::NVIDIA>-internal lookup.

=cut

sub legacy_driver_requirement {
  my ($device_id) = @_;
  my $req = Rex::GPU::NVIDIA::Requirement->for_device_id($device_id);
  return unless defined $req->max_branch;
  return { generation => $req->generation, max_branch => $req->max_branch };
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

=head1 SYNOPSIS

  use Rex::GPU::Detect;

  my $gpus = detect();
  if (@{ $gpus->{nvidia} }) {
    for my $gpu (@{ $gpus->{nvidia} }) {
      printf "NVIDIA %s (class %s, compute: %s)\n",
        $gpu->{name}, $gpu->{pci_class}, $gpu->{compute} ? 'yes' : 'no';
    }
  }

=head1 DESCRIPTION

L<Rex::GPU::Detect> detects GPU hardware on a remote host by parsing
C<lspci -nn> output and matching PCI vendor and class codes.

=head2 Detection approach

PCI class codes C<0300> (VGA compatible controller) and C<0302> (3D
controller) identify display/GPU hardware. The module filters C<lspci -nn>
output for these class codes, then classifies devices by vendor ID:

=over

=item * C<10de> — NVIDIA

=item * C<1002> — AMD / ATI

=back

=head2 Virtual GPU filtering

Display devices with vendor IDs C<1af4> (virtio), C<1b36> (QEMU/QXL),
C<15ad> (VMware), or C<80ee> (VirtualBox) are skipped line by line; they need
no host driver. Skipping one does not end the scan: on a VM with a
passed-through GPU (vfio-pci) the emulated console display and the real card
appear side by side, and the real card is still detected. A VM whose display
devices are all virtual returns empty arrays, as before. The vendor checks
run first, so a C<10de>/C<1002> line is never treated as virtual — this also
means an NVIDIA vGPU guest device (vendor C<10de>) is detected like a
passed-through card; C<lspci -nn> cannot tell the two apart.

=head2 NVIDIA compute classification

NVIDIA GPUs are further classified as I<compute-capable>. Only compute-capable
GPUs trigger driver installation in L<Rex::GPU>. The classification rules:

=over

=item * PCI class C<0302> (3D controller) — always compute/datacenter. Datacenter
GPUs such as the A100, H100, and RTX 4000 Ada typically enumerate as class
C<0302>.

=item * Known compute-capable PCI device IDs — a positive allowlist keyed on the
C<[10de:XXXX]> field. This covers Grace-Blackwell parts such as the GB10
(C<10de:2e12>, NVIDIA DGX Spark, aarch64), which enumerate as a VGA controller
(class C<0300>) and whose marketing name C<lspci> cannot resolve on a host
whose C<pci.ids> predates the silicon — it prints only C<Device>, so the
name-token rules below cannot see it. The device ID is present in C<lspci>
output regardless of C<pci.ids> freshness. The same list holds the desktop
GeForce RTX 50xx cards and the RTX PRO Blackwell workstation and server cards
(e.g. C<10de:2b85> RTX 5090, C<10de:2bb1> RTX PRO 6000 Blackwell Workstation
Edition), one explicit ID each from NVIDIA's supported-chips table (driver
615.71.09). Laptop Blackwell chips (C<... Laptop GPU>) and the RTX PRO
"Embedded" modules are not on it: with an unresolved name they stay
C<compute =E<gt> 0>. A card NVIDIA publishes later is recognised by ID only
once it is added; there is no device-ID range match.

=item * Named product families: RTX, TITAN, Quadro, Tesla, GTX 10xx/16xx series

=item * Non-compute: NVS, GT/GTS low-end, GTX 2xx–9xx legacy, MX-series mobile

=back

Unrecognised NVIDIA GPU models default to C<compute =E<gt> 0> and emit a
warning. The device-ID allowlist is a positive-only override and never changes
that default. AMD GPU C<compute> is always C<0>; AMD driver support is not yet
implemented.

Each detected NVIDIA GPU also carries its raw C<device_id> (the C<[10de:XXXX]>
field, or C<undef> if lspci printed none). L<Rex::GPU> passes the whole GPU
hashref through to L<Rex::GPU::NVIDIA/install_driver>, which uses
L</open_kernel_module_required> on the device ID to pick the correct Ubuntu
driver package variant for Blackwell-architecture silicon (B200/GB200/B300,
GeForce RTX 50xx, RTX PRO Blackwell, GB10) that has no proprietary kernel
module at all, and L</legacy_driver_requirement> to keep a pre-Turing GPU
(Maxwell/Pascal/Volta, e.g. the V100) on the proprietary 580 branch and to
reject a Kepler-or-older one.

=head1 SEE ALSO

L<Rex::GPU>, L<Rex::GPU::NVIDIA>,
L<https://pci-ids.ucw.cz/> (PCI ID database)

=cut
