use strict;
use warnings;
use Test::More;

# -----------------------------------------------------------------------------
# CHARACTERIZATION tests for Rex::GPU::Detect.
#
# These assert what the code does TODAY, not what it arguably should do. They
# exercise only the pure string functions (_parse_nvidia_line, _parse_amd_line,
# _is_nvidia_compute) and detect() with run()/is_installed() mocked out via a
# typeglob override. No hardware, no network, no package manager, no SSH.
#
# WHAT THESE TESTS DO NOT COVER — a maintainer MUST exercise the following on a
# real GPU node before a release; none of it runs here and a green `prove` is
# NOT evidence any of it works:
#   * real `lspci -nn` output on genuine hardware (these use hand-built
#     fixtures; a real card may emit a name format the regexes do not expect).
#   * install_driver on each distro family — Debian, Ubuntu, RHEL/Rocky/Alma,
#     openSUSE — including the per-family package lists and version branches.
#   * the Rex::Pkg-bypass verify seam (dpkg -l '^ii' / rpm -q) against a
#     partial/failed DKMS build.
#   * _blacklist_nouveau + initramfs regeneration (update-initramfs / dracut).
#   * _reboot_and_wait: the shutdown, the disconnect/reconnect polling loop,
#     and that the NVIDIA module binds after nouveau is unloaded.
#   * install_container_toolkit and `nvidia-ctk cdi generate` (CDI specs).
#   * configure_containerd for rke2 / k3s / containerd / none.
# -----------------------------------------------------------------------------

use Rex::GPU::Detect;

# Mock seam: is_installed => 1 skips the pkg() install; run => fixture feeds
# detect() the text that `lspci -nn | grep -E '[03(00|02)]'` would emit.
# local + dynamic scope means the overrides are live only while detect() runs.
sub detect_with {
  my ($output) = @_;
  no warnings 'redefine';
  local *Rex::GPU::Detect::is_installed = sub { 1 };
  local *Rex::GPU::Detect::run          = sub { $output };
  return Rex::GPU::Detect::detect();
}

#### _is_nvidia_compute — the highest-risk branch (wrong answer => wrong driver)

subtest '_is_nvidia_compute classification' => sub {
  # PCI class 0302 (3D controller) is always compute, whatever the name is.
  is(Rex::GPU::Detect::_is_nvidia_compute('0302', 'anything at all'), 1,
    'class 0302 => compute regardless of name');

  # Named compute families.
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'GA102 [GeForce RTX 3090]'), 1, 'RTX => compute');
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'TITAN V'),                  1, 'TITAN => compute');
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'Quadro P2000'),            1, 'Quadro => compute');
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'Tesla V100'),             1, 'Tesla => compute');

  # Datacenter short-codes via the /[AHLVP]\d{1,3}[GSi]?/ rule (note: the rule
  # is case-SENSITIVE — uppercase as real lspci emits).
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'A100'), 1, 'A100 => compute ([AHLVP]\d rule)');
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'H100'), 1, 'H100 => compute ([AHLVP]\d rule)');
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'L40'),  1, 'L40 => compute ([AHLVP]\d rule)');
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'V100'), 1, 'V100 => compute ([AHLVP]\d rule)');
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'P100'), 1, 'P100 => compute ([AHLVP]\d rule)');

  # GTX 10xx / 16xx are compute.
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'GeForce GTX 1080'), 1, 'GTX 1080 => compute');
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'GeForce GTX 1660'), 1, 'GTX 1660 => compute');

  # Non-compute consumer/low-end/legacy parts.
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'MX150'),           0, 'MX150 => not compute');
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'GT 710'),          0, 'GT 710 => not compute');
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'GeForce GTS 450'), 0, 'GTS => not compute');
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'NVS 310'),         0, 'NVS 310 => not compute');
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'GeForce GTX 960'), 0, 'GTX 960 (2-9xx) => not compute');

  # Unknown model at class 0300 => 0 is the safe, load-bearing default:
  # an unrecognised chip must NOT trigger a datacenter driver install.
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'FooBar 9000 Unknown Model'), 0,
    'unknown model at class 0300 => 0 (safe default, no install)');

  # Known-compute PCI device ID (3rd arg). GB10 (10de:2e12, DGX Spark, aarch64)
  # enumerates as VGA [0300] with the marketing name UNRESOLVED by a stale
  # pci.ids — lspci prints only "Device". The device-ID allowlist recognises it
  # as compute where the name-token rules cannot. Verified live on cortex.
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'Device', '2e12'), 1,
    'GB10 device id 2e12 at class 0300 with name "Device" => compute');
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'Device', '2E12'), 1,
    'device-id match is case-insensitive');
  # The allowlist is a positive-only override: it must NOT flip the unknown
  # default when the id is not on the list (still 0).
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'Device', 'ffff'), 0,
    'unlisted device id => unknown default 0 preserved');
  # 2-arg calls (no device id) keep the exact prior behaviour.
  is(Rex::GPU::Detect::_is_nvidia_compute('0300', 'Device'), 0,
    'no device id => unknown default 0 (back-compatible signature)');
};

#### _parse_nvidia_line

subtest '_parse_nvidia_line — datacenter (class 0302)' => sub {
  my $gpu = Rex::GPU::Detect::_parse_nvidia_line(
    '01:00.0 3D controller [0302]: NVIDIA Corporation AD104GL [RTX 4000 SFF Ada Generation] [10de:27b0] (rev a1)'
  );
  is($gpu->{vendor},    'nvidia', 'vendor nvidia');
  is($gpu->{pci_class}, '0302',   'pci_class 0302');
  is($gpu->{compute},   1,        'compute 1 (class 0302 short-circuit)');
  # The captured name keeps the codename AND the bracketed marketing name
  # verbatim (e.g. "AD104GL [RTX 4000 SFF Ada Generation]") — no "NVIDIA " prefix,
  # no de-bracketing. The POD SYNOPSIS in Detect.pm/GPU.pm documents this exact
  # form (karr #5); the name is a raw detection string and drives no branch
  # except the family-token match in _is_nvidia_compute.
  is($gpu->{name}, 'AD104GL [RTX 4000 SFF Ada Generation]',
    'name = codename + bracketed marketing string (matches POD SYNOPSIS)');
};

subtest '_parse_nvidia_line — consumer (class 0300)' => sub {
  my $gpu = Rex::GPU::Detect::_parse_nvidia_line(
    '65:00.0 VGA compatible controller [0300]: NVIDIA Corporation GA102 [GeForce RTX 3090] [10de:2204] (rev a1)'
  );
  is($gpu->{vendor},    'nvidia',                   'vendor nvidia');
  is($gpu->{pci_class}, '0300',                     'pci_class 0300');
  is($gpu->{compute},   1,                          'compute 1 (RTX name match)');
  is($gpu->{name},      'GA102 [GeForce RTX 3090]', 'name = codename + bracketed marketing string');
};

subtest '_parse_nvidia_line — GB10 aarch64 (name unresolved by pci.ids)' => sub {
  # EXACT class-03 line captured live from cortex (NVIDIA DGX Spark, GB10,
  # aarch64). pci.ids lacks 10de:2e12, so lspci renders the name as "Device";
  # the device ID drives the compute classification.
  my $gpu = Rex::GPU::Detect::_parse_nvidia_line(
    '000f:01:00.0 VGA compatible controller [0300]: NVIDIA Corporation Device [10de:2e12] (rev a1)'
  );
  is($gpu->{vendor},    'nvidia', 'vendor nvidia');
  is($gpu->{pci_class}, '0300',   'pci_class 0300 (GB10 enumerates as VGA, not 3D)');
  is($gpu->{name},      'Device', 'name = "Device" (pci.ids cannot resolve 10de:2e12)');
  is($gpu->{compute},   1,        'compute 1 via device-id allowlist — pipeline runs on a Spark');
};

#### _parse_amd_line

subtest '_parse_amd_line — standard lspci format' => sub {
  my $gpu = Rex::GPU::Detect::_parse_amd_line(
    '0a:00.0 VGA compatible controller [0300]: Advanced Micro Devices, Inc. [AMD/ATI] Navi 31 [Radeon RX 7900 XTX] [1002:744c] (rev c8)'
  );
  is($gpu->{vendor},    'amd',  'vendor amd');
  is($gpu->{pci_class}, '0300', 'pci_class 0300');
  is($gpu->{compute},   0,      'compute 0 (AMD never compute by decision)');
  # XXX characterization BUG: the name regex
  #   /:\s+(?:Advanced Micro Devices|AMD\/ATI)\s+.*?\s+(.+?)\s*\[1002:/
  # never matches the real lspci format, because "Advanced Micro Devices" is
  # followed by ", Inc." (comma, not whitespace), so the required \s+ after the
  # vendor literal fails; the "AMD/ATI" alternative is inside brackets and has
  # no ":\s+" immediately before it. Result: name falls back to the default
  # 'Unknown AMD GPU' for a perfectly ordinary AMD card. Detect-only today, so
  # it changes no install decision — but it is a real parse bug. Reported.
  is($gpu->{name}, 'Unknown AMD GPU',
    'name => "Unknown AMD GPU" (regex fails on standard format — XXX, see report)');
};

#### detect() end-to-end with run()/is_installed() mocked

subtest 'detect — NVIDIA only' => sub {
  my $r = detect_with(
    '65:00.0 VGA compatible controller [0300]: NVIDIA Corporation GA102 [GeForce RTX 3090] [10de:2204] (rev a1)'
  );
  is(scalar @{$r->{nvidia}}, 1,        'one nvidia gpu');
  is(scalar @{$r->{amd}},    0,        'no amd gpu');
  is($r->{nvidia}[0]{vendor}, 'nvidia', 'element vendor nvidia');
  is($r->{nvidia}[0]{compute}, 1,       'element compute 1');
};

subtest 'detect — GB10 aarch64 (real cortex string) => compute' => sub {
  my $r = detect_with(
    '000f:01:00.0 VGA compatible controller [0300]: NVIDIA Corporation Device [10de:2e12] (rev a1)'
  );
  is(scalar @{$r->{nvidia}},   1,      'one nvidia gpu');
  is($r->{nvidia}[0]{name},   'Device','name "Device" (unresolved by pci.ids)');
  is($r->{nvidia}[0]{compute}, 1,      'compute 1 — gpu_setup runs the full pipeline on a Spark');
};

subtest 'detect — AMD only' => sub {
  my $r = detect_with(
    '0a:00.0 VGA compatible controller [0300]: Advanced Micro Devices, Inc. [AMD/ATI] Navi 31 [Radeon RX 7900 XTX] [1002:744c] (rev c8)'
  );
  is(scalar @{$r->{nvidia}}, 0,     'no nvidia gpu');
  is(scalar @{$r->{amd}},    1,     'one amd gpu');
  is($r->{amd}[0]{vendor},  'amd',  'element vendor amd');
  is($r->{amd}[0]{compute}, 0,      'element compute 0');
};

subtest 'detect — virtual-only output => empty (unchanged)' => sub {
  # virtio [1af4] alone
  my $r = detect_with(
    '00:02.0 VGA compatible controller [0300]: Red Hat, Inc. Virtio GPU [1af4:1050] (rev 01)'
  );
  is(scalar @{$r->{nvidia}}, 0, 'virtio => no nvidia');
  is(scalar @{$r->{amd}},    0, 'virtio => no amd');

  # QEMU [1b36] alone
  my $q = detect_with(
    '00:01.0 VGA compatible controller [0300]: Device [1b36:0100] (rev 04)'
  );
  is(scalar @{$q->{nvidia}}, 0, 'qemu => no nvidia');
  is(scalar @{$q->{amd}},    0, 'qemu => no amd');

  # Several virtual displays and nothing else => still empty.
  my $vv = detect_with(
      "00:01.0 VGA compatible controller [0300]: Red Hat, Inc. QXL paravirtual graphic card [1b36:0100] (rev 05)\n"
    . "00:02.0 VGA compatible controller [0300]: Red Hat, Inc. Virtio 1.0 GPU [1af4:1050] (rev 01)"
  );
  is(scalar @{$vv->{nvidia}}, 0, 'qxl+virtio only => no nvidia');
  is(scalar @{$vv->{amd}},    0, 'qxl+virtio only => no amd');
};

# karr #17: a virtual line is skipped on its own; it no longer hides a real
# card elsewhere in the output. (Until k17 this block asserted the opposite —
# virtio+nvidia => empty — as a characterization of the blob-match bug.)
subtest 'detect — virtual console + passed-through NVIDIA (vfio / cloud GPU VM)' => sub {
  my $r = detect_with(
      "00:01.0 VGA compatible controller [0300]: Red Hat, Inc. QXL paravirtual graphic card [1b36:0100] (rev 05)\n"
    . "06:00.0 3D controller [0302]: NVIDIA Corporation AD102GL [L40S] [10de:26b9] (rev a1)"
  );
  is(scalar @{$r->{nvidia}},     1,      'QXL + L40S => one nvidia gpu');
  is(scalar @{$r->{amd}},        0,      'no amd gpu');
  is($r->{nvidia}[0]{name},      'AD102GL [L40S]', 'the real card is the one reported');
  is($r->{nvidia}[0]{pci_class}, '0302', 'pci_class 0302');
  is($r->{nvidia}[0]{device_id}, '26b9', 'device_id from [10de:26b9]');
  is($r->{nvidia}[0]{compute},   1,      'compute 1 — pipeline runs in the passthrough VM');

  # Order must not matter (virtual line after the real one).
  my $m = detect_with(
      "65:00.0 VGA compatible controller [0300]: NVIDIA Corporation GA102 [GeForce RTX 3090] [10de:2204] (rev a1)\n"
    . "00:02.0 VGA compatible controller [0300]: Red Hat, Inc. Virtio GPU [1af4:1050] (rev 01)"
  );
  is(scalar @{$m->{nvidia}}, 1, 'nvidia+virtio => one nvidia gpu');
  is(scalar @{$m->{amd}},    0, 'nvidia+virtio => no amd');
};

subtest 'detect — bare metal BMC VGA (ASPEED) + RTX 4000 => unchanged' => sub {
  # ASPEED [1a03] is neither virtual nor NVIDIA/AMD: ignored, as before k17.
  my $r = detect_with(
      "02:00.0 VGA compatible controller [0300]: ASPEED Technology, Inc. ASPEED Graphics Family [1a03:2000] (rev 41)\n"
    . "01:00.0 3D controller [0302]: NVIDIA Corporation AD104GL [RTX 4000 SFF Ada Generation] [10de:27b0] (rev a1)"
  );
  is(scalar @{$r->{nvidia}},   1, 'one nvidia gpu');
  is(scalar @{$r->{amd}},      0, 'no amd gpu (ASPEED ignored)');
  is($r->{nvidia}[0]{name}, 'AD104GL [RTX 4000 SFF Ada Generation]', 'RTX 4000 reported');
  is($r->{nvidia}[0]{compute}, 1, 'compute 1');

  my $bmc = detect_with(
    "02:00.0 VGA compatible controller [0300]: ASPEED Technology, Inc. ASPEED Graphics Family [1a03:2000] (rev 41)"
  );
  is(scalar @{$bmc->{nvidia}}, 0, 'ASPEED only => no nvidia');
  is(scalar @{$bmc->{amd}},    0, 'ASPEED only => no amd');
};

subtest 'detect — mixed NVIDIA + AMD' => sub {
  my $r = detect_with(
      "65:00.0 VGA compatible controller [0300]: NVIDIA Corporation GA102 [GeForce RTX 3090] [10de:2204] (rev a1)\n"
    . "0a:00.0 VGA compatible controller [0300]: Advanced Micro Devices, Inc. [AMD/ATI] Navi 31 [Radeon RX 7900 XTX] [1002:744c] (rev c8)"
  );
  is(scalar @{$r->{nvidia}}, 1, 'one nvidia gpu');
  is(scalar @{$r->{amd}},    1, 'one amd gpu');
};

subtest 'detect — empty run output' => sub {
  my $empty = detect_with('');
  is(scalar @{$empty->{nvidia}}, 0, "empty string => no nvidia");
  is(scalar @{$empty->{amd}},    0, "empty string => no amd");

  my $undef = detect_with(undef);
  is(scalar @{$undef->{nvidia}}, 0, 'undef output => no nvidia');
  is(scalar @{$undef->{amd}},    0, 'undef output => no amd');
};

done_testing;
