# ABSTRACT: GPU hardware detection via PCI class codes

package Rex::GPU::Detect;
our $VERSION = '0.002';
use v5.14.4;
use warnings;

use Carp qw( croak );
use Rex::Commands::Gather ();
use Rex::Commands::Pkg;
use Rex::Commands::Run;
use Rex::Logger;
use Rex::GPU::NVIDIA ();
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

# NVSwitch (karr #23): an HGX baseboard's NVSwitches enumerate as NVIDIA
# (10de) "Bridge" devices, PCI class [0680] (PCI_CLASS_BRIDGE_OTHER, the class
# the NVSwitch kernel driver claims: open-gpu-kernel-modules
# kernel-open/nvidia/linux_nvswitch.c). A device counts as an NVSwitch only if
# its ID is listed here or pci.ids named it "... NVSwitch" -- NVIDIA also
# made other 10de:0680 devices (nForce chipset bridges), and an unknown one
# must not trigger a Fabric Manager install. IDs from the Fabric Manager user
# guide's baseboard topology listings (docs.nvidia.com/datacenter/tesla/
# fabric-manager-user-guide/, checked 2026-09-24) and pci.ids:
#   1ac2  HGX-2 (V100)             NVSwitch gen1
#   1af1  HGX A100                 NVSwitch gen2, "GA100 [A100 NVSwitch]"
#   22a3  HGX H100/H200/H800/H20   NVSwitch gen3, "GH100 [H100 NVSwitch]"
# NOT here, deliberately: HGX B200/B300/B100 (NVSwitch gen4). The guide says
# their NVSwitches "are not recognized as PCIe devices on the host system";
# the host sees ConnectX-7 bridge functions instead, so lspci cannot find them.
# GB200/GB300 NVL72 compute trays run no Fabric Manager at all (it runs on
# the NVLink switch trays).
my $NVSWITCH_CLASS_RE = qr/\[0680\]/;
my %NVSWITCH_DEVICE_IDS = (
  '1ac2' => { generation => 1 },
  '1af1' => { generation => 2 },
  '22a3' => { generation => 3 }
);

# Rex::GPU::Detect::open_kernel_module_required and legacy_driver_requirement
# below are wrappers over Rex::GPU::NVIDIA::Requirement, kept with their exact
# return values for Rex::GPU::NVIDIA's install paths (epic karr #25).

=head1 FUNCTIONS

=cut

=method detect

Detect GPU hardware on the remote host: parses C<lspci -nn> output filtered
to PCI display-class devices (class codes C<03xx>).

If C<lspci> is on the remote C<PATH> (C<command -v lspci>), nothing is
installed. Otherwise C<pciutils> is installed first: through
L<Rex::Commands::Pkg/pkg> (unless C<is_installed> says it already is), or,
on Rocky Linux, AlmaLinux and CentOS Stream under the names Rex reports when
C<lsb_release> is installed (C<Rocky>, C<RockyLinux>, C<AlmaLinux>,
C<CentOSStream>; C<Rex::Pkg> cannot handle those), with C<dnf install -y
pciutils> checked by C<rpm -q pciutils>. Dies if that check fails or
C<lspci> is still not found afterwards -- before C<lspci> runs, so a host
without it never reports "no GPU".

Returns a hashref with three array refs, always all present: C<nvidia> and
C<amd> (one hashref per detected GPU) and C<nvswitch> (one hashref per
detected NVSwitch, see below):

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
    nvswitch => [
      {
        name      => "GH100 [H100 NVSwitch]",
        vendor    => "nvidia",
        pci_class => "0680",
        device_id => "22a3",
      }
    ],
  }

C<nvswitch> lists the NVSwitch chips of an HGX baseboard (NVIDIA C<10de>
devices of PCI class C<0680>, "Bridge"), found by a second, read-only
C<lspci -nn -d 10de:> that runs only when an NVIDIA GPU was found; it is
C<[]> otherwise. A device counts only if its ID is a known NVSwitch
(C<1ac2> HGX-2, C<1af1> HGX A100, C<22a3> HGX H100/H200) or C<lspci> names
it C<... NVSwitch>; another NVIDIA bridge device is logged and skipped. An
NVSwitch host needs NVIDIA Fabric Manager, which L<Rex::GPU/gpu_setup>
installs with the driver. HGX B200/B300 are B<not> detected: their
NVSwitches are not PCI devices on the host (NVIDIA's Fabric Manager guide),
so C<nvswitch> stays C<[]> there. The key is additive; C<nvidia> and C<amd>
are unchanged.

If no supported GPU is found, or if the only display devices are virtual,
all three arrays are empty (C<[]>) -- C<nvswitch> too, since it is only
probed when an NVIDIA GPU was found. A virtual display next to a real
NVIDIA/AMD card (GPU passthrough, cloud GPU VM) is skipped on its own line
and the real card is still reported.

=cut

sub detect {
  _ensure_lspci();

  my $pci_output = run "lspci -nn 2>&1 | grep -E '\\[03(00|02)\\]'",
    auto_die => 0;

  my $result = { nvidia => [], amd => [], nvswitch => [] };

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

  # NVSwitch (karr #23): only where there is an NVIDIA GPU for it to connect,
  # so a host without one runs no extra command.
  $result->{nvswitch} = _detect_nvswitch() if @{$result->{nvidia}};

  return $result;
}

# karr #46: lspci present => install nothing (read-only; OCP needs no
# pciutils then). `command -v` through run, not can_run: can_run stats the
# path through the file interface, which needs SFTP on SSH/OpenSSH, and it
# answers under the same PATH the `lspci -nn` below runs with. Rex::Pkg dies
# "OS/Provider not supported" on the RHEL-family names lsb_release gives
# (karr #39), so those get dnf + rpm -q, as Setup::RHEL's install_helpers
# does; the name list is Rex::GPU::NVIDIA's, not a copy.
sub _ensure_lspci {
  return if _has_lspci();

  if (Rex::GPU::NVIDIA::_rhel_family_name(Rex::Commands::Gather::operating_system())) {
    Rex::Logger::info('lspci not found -- installing pciutils with dnf');
    run 'dnf install -y pciutils', auto_die => 0;
    run 'rpm -q pciutils 2>&1', auto_die => 0;
    croak 'pciutils not installed after dnf install -- check dnf output; '
      .'GPU detection needs lspci' if $? != 0;
  }
  else {
    pkg ["pciutils"], ensure => "present" unless is_installed("pciutils");
  }

  croak 'lspci not found on the host after installing pciutils -- '
    .'GPU detection needs lspci on the PATH' unless _has_lspci();
}

sub _has_lspci {
  run 'command -v lspci >/dev/null 2>&1', auto_die => 0;
  return $? == 0 ? 1 : 0;
}

# Read-only: `lspci -nn -d 10de:` filtered to class [0680]; one hashref per
# recognised NVSwitch.
sub _detect_nvswitch {
  my $out = run "lspci -nn -d 10de: 2>/dev/null | grep -F '[0680]'", auto_die => 0;
  my @switches;
  for my $line (split /\n/, $out // '') {
    my $switch = _parse_nvswitch_line($line);
    push @switches, $switch if $switch;
  }
  Rex::Logger::info('  [ok] NVSwitch: '.scalar(@switches).' ('.$switches[0]{name}.')')
    if @switches;
  return \@switches;
}

sub _parse_nvswitch_line {
  my ($line) = @_;
  return unless defined $line && $line =~ $NVSWITCH_CLASS_RE && $line =~ $NVIDIA_VENDOR_RE;
  my ($device_id) = $line =~ /\[10de:([0-9a-f]{4})\]/i;
  my ($name) = $line =~ /:\s+NVIDIA\s+Corporation\s+(.+?)\s*\[10de:/;
  $name //= 'Unknown NVIDIA bridge';
  unless ($NVSWITCH_DEVICE_IDS{lc $device_id} || $name =~ /\bNVSwitch\b/i) {
    Rex::Logger::info("  [skip] NVIDIA bridge device not known as an NVSwitch: $name [10de:$device_id]");
    return;
  }
  return {
    name      => $name,
    vendor    => 'nvidia',
    pci_class => '0680',
    device_id => lc $device_id
  };
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

  # The generation decides, not the marketing name (karr #45, #54; maintainer
  # decision: every GPU usable for AI counts, MX/GT/GTX 9xx included). The
  # rows of Rex::GPU::NVIDIA::Requirement cover every ID 0000-2FFF plus
  # Blackwell Ultra: Maxwell .. Blackwell Ultra => 1, Kepler or older => 0.
  # lspci prints the ID even when a stale pci.ids leaves the name as "Device".
  my $req = Rex::GPU::NVIDIA::Requirement->for_device_id($device_id);
  if (defined $req->compute) {
    return 1 if $req->compute;
    # Skipped, not died: gpu_setup (and Rex::Rancher's gpu => 1) go on
    # without a driver on a host whose old card is only a display.
    Rex::Logger::info('    NVIDIA GPU '.$name.' (10de:'.$req->device_id.') is '
      .$req->generation.' silicon'
      .( defined $req->max_branch
        ? ': it needs driver branch '.$req->max_branch.' or older, which current '
          .'distributions no longer package'
        : '' )
      .' -- skipped, no driver installed', 'warn');
    return 0;
  }

  # Name rules: reached only for an ID no generation row covers (0x3000 and
  # up, bar Blackwell Ultra: silicon newer than the table) or no ID at all.
  # Each one names only products of Maxwell or later: checked against every
  # name in NVIDIA's supportedchips lists (615.71.09), no Kepler-or-older
  # product matches. pci.ids names a few Kepler IDs like later products
  # (0FC5 "GK107 [GeForce GT 1030]", 11C7 "GK106 [GeForce GTX 750 Ti]", GK107
  # "...-A1" samples) -- the Kepler row catches those by ID before this. No
  # negative rules: anything else is the unknown default below, 0 either way.
  return 1 if $name =~ /\bRTX\b/i;                          # Turing and later only
  return 1 if $name =~ /\bGTX\s*1\d{3}\b/i;                 # GTX 10xx Pascal, 16xx Turing
  return 1 if $name =~ /\bGTX\s*(?:9\d{2}|745|750)(?!\d)/i; # Maxwell (GTX 76x-78x are Kepler)
  return 1 if $name =~ /\bGT\s*1\d{3}\b/i;                  # GT 1010/1030 Pascal
  return 1 if $name =~ /\bGeForce\s+MX\s*\d{3}\b/i;         # MX110..MX570; not GeForce2/4 MX
  return 1 if $name =~ /\bTITAN\s+(?:X|Xp|V|RTX)\b/i;       # not the Kepler GTX TITAN/Black/Z
  return 1 if $name =~ /\bQuadro\s+(?:GP|GV|[MPT])\s*\d/i;  # Quadro M/P/T/GP/GV; K is mixed
  return 1 if $name =~ /\bTesla\s+(?:[PV]\d|T4\b|M\d{1,2}\b)/; # not Fermi M20x0, Kepler K
  return 1 if $name =~ /\b[AHLVP]\d{1,3}[GSi]?\b/;          # A100, H100, L40, V100, P40, ...

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
generation keep the default proprietary C<-server> selection. This function
only answers the driver-variant question; which GPUs are compute-capable is
L</NVIDIA compute classification>.

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
C<supportedchips> README (driver 615.71.09). This only chooses the driver;
whether a GPU is compute-capable is L</NVIDIA compute classification>
(Maxwell/Pascal/Volta: yes, Kepler or older: no).

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
GPUs trigger driver installation in L<Rex::GPU>. Every GPU that can be used
for AI counts -- GeForce MX, GT and GTX 9xx with 2 GB of memory included --
as long as a current driver branch supports it: the criterion is the GPU
B<generation>, read from the PCI device ID, not the marketing name. The
rules, first match wins:

=over

=item * PCI class C<0302> (3D controller) — always compute/datacenter. Datacenter
GPUs such as the A100, H100, and RTX 4000 Ada typically enumerate as class
C<0302>. This holds for a Kepler Tesla (K80, K40) too; the driver installer
then refuses it (see L<Rex::GPU::NVIDIA/install_driver>).

=item * The PCI device ID's generation, from the
L<generations|Rex::GPU::NVIDIA::Requirement/generations> table of
L<Rex::GPU::NVIDIA::Requirement> (its
L<compute|Rex::GPU::NVIDIA::Requirement/compute> flag), whatever the PCI class
and whatever name C<lspci> prints. The table covers every ID from C<0000> to
C<2FFF> and the Blackwell Ultra IDs:

=over

=item * Maxwell, Pascal, Volta (C<1340>-C<1DF6>; GeForce GTX 750 Ti/9xx/10xx,
GT 1030, MX110-MX350, Tesla M/P/V100, ...): compute. They get the proprietary
580-branch driver.

=item * Turing, Ampere, Ada, Hopper (C<1DF7>-C<28FF>; MX450/MX550/MX570,
GTX 16xx, RTX 20xx-40xx, T4, A100, L40, H100, ...): compute.

=item * Blackwell and Blackwell Ultra (C<2900>-C<2FFF>, C<3182>,
C<31C2>/C<31C3>; GeForce RTX 50xx desktop and laptop, RTX PRO Blackwell,
B200/GB200/B300/GB300, the GB10 C<10de:2e12> of NVIDIA DGX Spark): compute.

=item * Kepler or older (below C<1340>; GeForce GT 710/730, GTX 6xx/7xx,
Quadro K4000, ...): B<not> compute. Their last driver branch is 470, which the
current distributions no longer package, so the GPU is skipped with a warning
("... is Kepler or older silicon: it needs driver branch 470 or older, which
current distributions no longer package -- skipped, no driver installed")
instead of making the driver installation die. A Kepler display card next to
a newer GPU does not stop the newer one's installation.

=back

Many GPUs enumerate as a VGA controller (class C<0300>), and on a host whose
C<pci.ids> predates the silicon C<lspci> prints only C<Device> as the name;
the device ID is present regardless.

=item * Name rules, only for an ID no table row covers (C<3000> and up, except
the Blackwell Ultra IDs -- silicon newer than the table): RTX, GTX 10xx/16xx,
GTX 9xx/745/750, GT 1xxx, GeForce MX1xx-5xx, TITAN X/Xp/V/RTX, Quadro
M/P/T/GP/GV, Tesla M/P/V/T4 and datacenter short codes (A100, H100, L40, ...).
Each names only Maxwell-or-later products.

=back

Unrecognised NVIDIA GPU models default to C<compute =E<gt> 0> and emit a
warning. AMD GPU C<compute> is always C<0>; AMD driver support is not yet
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
