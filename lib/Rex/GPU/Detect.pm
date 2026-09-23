# ABSTRACT: GPU hardware detection via PCI class codes

package Rex::GPU::Detect;
our $VERSION = '0.002';
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

# Known compute-capable NVIDIA PCI device IDs (lowercase, from the
# [10de:XXXX] field). Grace-Blackwell parts such as the GB10 (10de:2e12,
# NVIDIA DGX Spark, aarch64) enumerate as a VGA controller [0300] and, on a
# host whose /usr/share/misc/pci.ids predates the silicon, lspci prints only
# "Device" with no marketing name — so the name-token rules in
# _is_nvidia_compute cannot recognise them. The device ID is the one signal
# always present in lspci output regardless of pci.ids freshness. Add ONLY
# verified datacenter/compute IDs here; this does not change the unknown-model
# default (still compute => 0).
#
# open_kernel_module (karr #15) marks an entry whose silicon has NO proprietary
# kernel module at all — only NVIDIA's open GPU kernel modules build/load for
# it, so Rex::GPU::NVIDIA's Ubuntu driver selection must pick the -open package
# variant instead of the default -server one. This is a property of the
# SILICON, not of "being in this allowlist": a future addition here that DOES
# support the proprietary module (e.g. a Hopper-class part reachable only by
# device ID) must NOT set it. Set it only for verified open-only parts.
my %NVIDIA_COMPUTE_DEVICE_IDS = (
  '2e12' => { name => 'GB10', open_kernel_module => 1 },
  # NVIDIA GB10 (Grace-Blackwell, DGX Spark) — verified on aarch64; Blackwell
  # architecture has no proprietary kernel module, open is the only option.
);

# Blackwell-architecture NVIDIA PCI device IDs (karr #16), inclusive ranges.
# Blackwell has NO proprietary kernel module — NVIDIA's open GPU kernel
# modules are the only ones that bind — on every architecture, x86_64
# included. This is ONLY an open-kernel-module signal for
# open_kernel_module_required; it does NOT make a device compute (a GPU still
# has to pass _is_nvidia_compute by class 0302, the allowlist above or its
# name) and it does not change the unknown-model default.
#
# Source: the supported-GPU table in NVIDIA's open-gpu-kernel-modules
# README.md (github.com/NVIDIA/open-gpu-kernel-modules, driver 615.71.09).
# In that table the last pre-Blackwell (Ada) ID is 28F8, and every listed ID
# from 2901 up to 2F58 is Blackwell: B200 (2901, 2909), GB200 (2941), GeForce
# RTX 50xx desktop/laptop and RTX PRO Blackwell (2B85..2F58), GB10 (2E12).
# 0x2900-0x2FFF is therefore taken as a block: an unlisted ID inside it is
# post-Ada silicon and gets the -open driver (which supports every GPU from
# Turing on). Blackwell Ultra (B300 3182, GB300 31C2/31C3) is listed
# explicitly, NOT as a block — whatever else lands at 0x3000+ is unknown.
# Any ID outside these ranges (every Turing/Ampere/Ada/Hopper part, and any
# future generation) returns false, i.e. today's -server selection.
my @NVIDIA_BLACKWELL_DEVICE_ID_RANGES = (
  [ 0x2900, 0x2fff ],   # GB100/GB102 (B200, GB200), GB20x (RTX 50xx, RTX PRO), GB10
  [ 0x3182, 0x3182 ],   # B300 SXM6 AC
  [ 0x31c2, 0x31c3 ]    # GB300
);

# Pre-Turing NVIDIA PCI device IDs (karr #26), inclusive ranges, with the
# newest driver branch that still supports them. Interim hotfix table; epic
# karr #25 folds it into a driver Requirement table. Like the Blackwell ranges
# above it ONLY picks the driver — it never makes a device compute.
#
# Source: the legacy sections of NVIDIA's supportedchips README (driver
# 615.71.09, us.download.nvidia.com/XFree86/Linux-x86_64/615.71.09/README/
# supportedchips.html), checked 2026-09-23:
#   * "current" list: lowest ID 1E02 (TITAN RTX, Turing). No current ID < 1E02.
#   * 580.xx legacy list (Maxwell/Pascal/Volta): exactly 1340..1DF6, e.g.
#     Tesla M60 13F2, M40 17FD, P100 15F7/15F8, P40 1B38, P4 1BB3, TITAN V
#     1D81, V100 1DB1/1DB4-1DB6, V100S 1DF6. Proprietary kernel module only —
#     the open module needs GSP, which these chips lack — and 580 is their last
#     branch (595+ dropped them).
#   * 470.xx list (Kepler): 0FC6..12BA. The 390.xx (Fermi) list interleaves
#     with it (1040..1251) and goes down to 06C0; older legacy lists reach
#     down to 0020. No list has an ID in 12BB..133F or 1DF7..1E01.
# So every ID below 1340 is Kepler or older and no driver newer than 470
# supports it: one block, not a Kepler-only range, so a Fermi Tesla (C2050
# 06D1, M2090 1091) is rejected too instead of getting today's broken install.
# 1340..1DF6 is taken as a block like the Blackwell one: an unlisted ID inside
# it is Maxwell..Volta silicon. IDs from 1DF7 on (Turing and later, unknown)
# return nothing here — today's selection, unchanged.
my @NVIDIA_LEGACY_DEVICE_ID_RANGES = (
  [ 0x0000, 0x133f, 'Kepler or older',      470 ],
  [ 0x1340, 0x1df6, 'Maxwell/Pascal/Volta', 580 ]
);

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
  # GB10) that enumerate as VGA [0300] and whose marketing name lspci cannot
  # resolve from a stale pci.ids. This is a positive allowlist only; it never
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
C<31C2>/C<31C3>), or for an entry of the C<%NVIDIA_COMPUTE_DEVICE_IDS>
allowlist that sets its C<open_kernel_module> flag. Both lists live in this
module only, so the driver installer carries no second hardcoded device
list. Returns false for C<undef>, a malformed ID, and every ID outside those
ranges — Turing/Ampere/Ada/Hopper parts and any future generation keep the
default proprietary C<-server> selection. The ranges only choose the driver
variant; they never make a GPU compute-capable.

Not in C<@EXPORT> — this is a C<Rex::GPU::NVIDIA>-internal lookup, not a
Rexfile-facing command.

=cut

sub open_kernel_module_required {
  my ($device_id) = @_;
  return 0 unless defined $device_id;
  my $entry = $NVIDIA_COMPUTE_DEVICE_IDS{lc $device_id};
  return 1 if $entry && ref $entry eq 'HASH' && $entry->{open_kernel_module};
  return 0 unless $device_id =~ /^[0-9a-f]{4}$/i;
  my $id = hex $device_id;
  for my $range (@NVIDIA_BLACKWELL_DEVICE_ID_RANGES) {
    return 1 if $id >= $range->[0] && $id <= $range->[1];
  }
  return 0;
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

Not in C<@EXPORT> — a C<Rex::GPU::NVIDIA>-internal lookup.

=cut

sub legacy_driver_requirement {
  my ($device_id) = @_;
  return unless defined $device_id && $device_id =~ /^[0-9a-f]{4}$/i;
  my $id = hex $device_id;
  for my $range (@NVIDIA_LEGACY_DEVICE_ID_RANGES) {
    return { generation => $range->[2], max_branch => $range->[3] }
      if $id >= $range->[0] && $id <= $range->[1];
  }
  return;
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
output regardless of C<pci.ids> freshness.

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
