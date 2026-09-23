use strict;
use warnings;
use Test::More;

# -----------------------------------------------------------------------------
# Unit tests for the Ubuntu Blackwell/GB10 open-kernel-module driver selection
# (karr #15, part 2 of #14).
#
# karr #14 made Rex::GPU::Detect classify the GB10 (10de:2e12, NVIDIA DGX
# Spark, aarch64) as compute => 1 via a device-ID allowlist. That activated
# install_driver on a fresh Ubuntu arm64 Spark — and the Ubuntu branch used to
# always filter OUT *-open package candidates, which is correct for the
# verified x86_64 path (RTX 4000 Ada et al.) but wrong for Blackwell-class
# silicon: the GB10 has no proprietary kernel module at all, only the -open
# variant builds/loads for it.
#
# Both functions under test are pure (string/hash lookups only, no run/dpkg),
# so they are unit-testable offline:
#   * Rex::GPU::Detect::open_kernel_module_required   — the device-ID lookup
#   * Rex::GPU::NVIDIA::_ubuntu_needs_open_kernel_module — arch + GPU gate
#
# NOT covered here (needs a real Ubuntu arm64 Spark — none was available for
# this change; see the t/10-detect.t header for the wider "what prove cannot
# see"):
#   * that `apt-cache search '^nvidia-driver-[0-9].*-server-open$'` actually
#     finds a candidate on a real host, or that the fallback
#     "nvidia-driver-570-server-open" is installable (repo metadata checked,
#     not exercised against apt).
#   * that the -open package DKMS-builds against a stock Ubuntu kernel (cortex
#     uses DGX-OS prebuilt modules, not this code path — see karr #15).
#   * that the x86_64 RTX 4000 Ada install is unaffected end-to-end (only the
#     selection logic is asserted here, not a live apt-get run).
# -----------------------------------------------------------------------------

use Rex::GPU::Detect;
use Rex::GPU::NVIDIA;

#### Rex::GPU::Detect::open_kernel_module_required

subtest 'open_kernel_module_required' => sub {
  is(Rex::GPU::Detect::open_kernel_module_required('2e12'), 1,
    'GB10 device id 2e12 => open kernel module required');
  is(Rex::GPU::Detect::open_kernel_module_required('2E12'), 1,
    'lookup is case-insensitive');
  is(Rex::GPU::Detect::open_kernel_module_required('27b0'), 0,
    'RTX 4000 Ada device id (name-matched, not in the allowlist) => 0');
  is(Rex::GPU::Detect::open_kernel_module_required('ffff'), 0,
    'unlisted device id => 0');
  is(Rex::GPU::Detect::open_kernel_module_required(undef), 0,
    'undef device id => 0');
};

#### Rex::GPU::NVIDIA::_ubuntu_needs_open_kernel_module

sub needs_open { Rex::GPU::NVIDIA::_ubuntu_needs_open_kernel_module(@_) }

subtest 'arm64 + GB10 => open' => sub {
  my $gb10 = { name => 'Device', vendor => 'nvidia', pci_class => '0300',
               compute => 1, device_id => '2e12' };
  is(needs_open('arm64',   $gb10), 1, 'dpkg arch "arm64" + GB10 => open');
  is(needs_open('aarch64', $gb10), 1, '"aarch64" spelling also recognised (defensive)');
};

subtest 'x86_64 path is unaffected, whatever the GPU (the non-regression point)' => sub {
  my $gb10 = { name => 'Device', vendor => 'nvidia', pci_class => '0300',
               compute => 1, device_id => '2e12' };
  my $rtx4000 = { name => 'AD104GL [RTX 4000 SFF Ada Generation]', vendor => 'nvidia',
                  pci_class => '0302', compute => 1, device_id => '27b0' };
  is(needs_open('amd64',  $rtx4000), 0, 'x86_64 dpkg arch (amd64) + RTX 4000 Ada => not open');
  is(needs_open('amd64',  $gb10),    0, 'x86_64 dpkg arch (amd64) + GB10 GPU => still not open (arch gates first)');
  is(needs_open('x86_64', $rtx4000), 0, 'unexpected but non-arm arch string => not open');
};

subtest 'arm64 with a non-open-only GPU stays on -server' => sub {
  my $rtx4000 = { name => 'AD104GL [RTX 4000 SFF Ada Generation]', vendor => 'nvidia',
                  pci_class => '0302', compute => 1, device_id => '27b0' };
  is(needs_open('arm64', $rtx4000), 0,
    'arm64 + a GPU not in the open-only allowlist => not open');
};

subtest 'missing/malformed inputs default to false (safe: keeps -server)' => sub {
  is(needs_open('arm64', undef),          0, 'no GPU passed (install_driver called without gpu =>) => not open');
  is(needs_open('arm64', {}),             0, 'GPU hashref with no device_id => not open');
  is(needs_open(undef,   { device_id => '2e12' }), 0, 'undef arch => not open');
  is(needs_open('arm64', 'not-a-hashref'), 0, 'non-hashref $gpu => not open (no crash)');
};

done_testing;
