# ABSTRACT: NVIDIA GPU driver and container toolkit management

package Rex::GPU::NVIDIA;
our $VERSION = '0.002';
use v5.14.4;
use warnings;

use Rex::Commands::File;
use Rex::Commands::Gather;
use Rex::Commands::Pkg;
use Rex::Commands::Run;
use Rex::Logger;

# () — load only; Rex::GPU::Detect::open_kernel_module_required is called
# fully-qualified below and is deliberately NOT in this module's own @EXPORT
# (it is an internal lookup, not a Rexfile-facing command).
use Rex::GPU::Detect ();

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  install_driver
  install_container_toolkit
  configure_containerd
  verify_nvidia
  generate_cdi_specs
);

=method install_driver

Install NVIDIA GPU drivers appropriate for the detected OS using DKMS.
Blacklists the C<nouveau> driver and rebuilds the initramfs so the blacklist
takes effect on next boot.

After installation (and after reboot, if C<reboot =E<gt> 1>), calls
L</verify_nvidia> to confirm the kernel module loaded correctly.

Dies if the detected OS is not supported.

If a working NVIDIA driver is already loaded and functional (C<nvidia-smi -L>
lists a GPU) — for example on a host provisioned via the NVIDIA CUDA package
repository, or on a re-run — C<install_driver> logs this and returns
immediately without installing anything, and without blacklisting nouveau or
rebooting. This keeps the call idempotent and stops the per-distro package
selection from installing a second, version-conflicting (or lower) driver over
the one already present.

Options:

=over

=item C<reboot>

If true, the host is rebooted immediately after driver installation.
The function waits up to 5 minutes for the host to come back (polling
every 5 seconds via SSH reconnect), then continues with verification.
Default: C<0>.

Rebooting is required on the first deployment when the C<nouveau>
open-source driver was previously loaded, because nouveau must be
unloaded before the NVIDIA kernel module can bind to the device.

=item C<gpu>

Optional hashref — the detected GPU this driver install is for, in the same
shape L<Rex::GPU::Detect/detect> returns for one C<nvidia> array element
(C<name>, C<device_id>, ...). L<Rex::GPU> passes C<< $compute[0] >> here.
Used on Debian and Ubuntu to recognise Blackwell-architecture silicon
(B200/GB200/B300, GeForce RTX 50xx, RTX PRO Blackwell, the GB10 / NVIDIA DGX
Spark) by its C<device_id>. Blackwell has no proprietary kernel module at all,
on any CPU architecture (see
L<Rex::GPU::Detect/open_kernel_module_required>):

=over

=item * On Ubuntu it selects the C<-open> driver package variant instead of
the default C<-server> one.

=item * On Debian no Debian-packaged driver supports Blackwell (bookworm
ships 535, trixie 550), so the driver comes from NVIDIA's CUDA apt repository
instead of Debian C<non-free>: the C<cuda-keyring> package for C<debian12> or
C<debian13> (C<x86_64> for amd64, C<sbsa> for arm64) is installed, then the
compute-only open-module set C<nvidia-driver-cuda> +
C<nvidia-kernel-open-dkms>. Debian C<non-free> is not enabled on that path.
A Blackwell GPU on any other Debian release (11, testing/sid, a derivative's
own version) or architecture B<dies> before anything is changed on the host.

=back

Every other GPU keeps the previous selection (Ubuntu C<-server>, Debian
C<non-free> C<nvidia-driver>); RHEL and openSUSE ignore the option. Omit it
(or pass C<undef>) to keep the previous, GPU-agnostic package selection.

=back

  install_driver();              # install only, load module without reboot
  install_driver(reboot => 1);   # install, reboot, verify
  install_driver(gpu => $gpus->{nvidia}[0]);   # thread GPU identity through

=cut

sub install_driver {
  my (%opts) = @_;

  # Idempotency short-circuit (distro-neutral, BEFORE per-distro package
  # selection): if a working NVIDIA driver is already loaded and functional, do
  # NOT install a second driver source. A host provisioned via the NVIDIA CUDA
  # package repo (cuda-drivers / unversioned nvidia-driver userspace), or a
  # re-run of gpu_setup, already has the module bound; the per-distro
  # auto-selection would otherwise pick a DIFFERENT (possibly lower) version
  # whose versioned libs Conflict with the installed userspace — apt/dnf/zypper
  # then refuse and the install-verify seam dies. nvidia-smi -L lists a "GPU N:"
  # device only when the module is loaded and functional, so it is the safe,
  # OS-neutral signal. nouveau is already displaced by the loaded module, so the
  # blacklist and reboot are skipped too — a clean no-op on such a host.
  my $smi = run "nvidia-smi -L 2>&1", auto_die => 0;
  chomp $smi if defined $smi;
  if (_nvidia_driver_present($smi)) {
    Rex::Logger::info("NVIDIA driver already present and working — skipping driver install ($smi)");
    return;
  }

  my $os = operating_system();
  my $running_kernel = run "uname -r";
  chomp $running_kernel;

  Rex::Logger::info("Installing NVIDIA drivers on $os (kernel $running_kernel)");

  if (is_debian()) {
    _install_driver_debian($os, $running_kernel, $opts{gpu});
  }
  elsif (is_redhat()) {
    _install_driver_redhat($os, $running_kernel);
  }
  elsif (is_suse()) {
    _install_driver_suse($os, $running_kernel);
  }
  else {
    die "Unsupported OS for NVIDIA driver installation: $os\n";
  }

  _blacklist_nouveau();

  if ($opts{reboot}) {
    _reboot_and_wait();
  }
  else {
    run "modprobe nvidia", auto_die => 0;
  }

  verify_nvidia();

  Rex::Logger::info("NVIDIA driver installation complete");
}

# Pure predicate for the install_driver idempotency short-circuit: given the
# output of `nvidia-smi -L`, is a working NVIDIA driver already loaded? Only a
# functional, module-bound driver lists a "GPU N:" device line; every failure
# form (NVML init error, "No devices were found", "command not found") does not
# match. Same signal verify_nvidia() uses to confirm nvidia-smi works. Pure
# (regex only, no run/dpkg) so it is unit-testable offline.
sub _nvidia_driver_present {
  my ($smi) = @_;
  return 0 unless defined $smi;
  return $smi =~ /GPU \d+:/ ? 1 : 0;
}

=method install_container_toolkit

Install the NVIDIA Container Toolkit (C<nvidia-container-toolkit> package)
from the official NVIDIA package repository at
L<https://nvidia.github.io/libnvidia-container/>.

The repository GPG key is imported and the package repository is registered
before installing. On Debian/Ubuntu the signed APT source list is written;
on RHEL the C<.repo> file is fetched via C<curl>; on openSUSE Leap the
base repository URL is added directly (zypper cannot parse RPM C<.repo>
files directly).

Dies if the OS is not supported or if installation fails.

=cut

sub install_container_toolkit {
  my $os = operating_system();

  Rex::Logger::info("Installing NVIDIA Container Toolkit");

  if (is_debian()) {
    _install_toolkit_debian();
  }
  elsif (is_redhat()) {
    _install_toolkit_redhat();
  }
  elsif (is_suse()) {
    _install_toolkit_suse();
  }
  else {
    die "Unsupported OS for NVIDIA Container Toolkit: $os\n";
  }

  Rex::Logger::info("NVIDIA Container Toolkit installed");
}

=method configure_containerd($runtime)

Configure the containerd runtime to use the NVIDIA container runtime.
The C<nvidia-container-runtime> binary must already be installed
(L</install_container_toolkit> provides it); if it is not present this
function returns immediately without error.

C<$runtime> selects how containerd is configured:

=over

=item C<rke2> or C<k3s> (default: C<rke2>)

Registers the NVIDIA runtime C<additively>, without replacing the base
containerd config that RKE2/K3s generate. The mechanism is chosen from the
effective, generated C<config.toml> under
C</var/lib/rancher/{rke2,k3s}/agent/etc/containerd/>:

=over

=item * B<Already wired> — if that C<config.toml> already contains an
C<nvidia> runtime block (modern RKE2/K3s auto-detect
C<nvidia-container-runtime> on C<PATH> and wire it themselves), this is a
B<no-op>: nothing is written and the native config is left untouched.

=item * B<Modern (containerd 2.x / config v3)> — writes an additive drop-in
at C<config-v3.toml.d/99-nvidia.toml> (RKE2/K3s already import
C<config-v3.toml.d/*.toml>). The base config — C<SystemdCgroup>, the pinned
sandbox image, snapshotter options and the registry C<certs.d> path — is
preserved.

=item * B<Legacy (containerd 1.x / config v2)> — writes a C<config.toml.tmpl>
that begins with C<{{ template "base" . }}> and only I<adds> the nvidia
runtime, so the rendered base config is preserved.

=back

Both RKE2 and K3s use the same logic (only the C</var/lib/rancher/*> base
directory differs). If no generated C<config.toml> exists yet and no config
version marker is found, the modern v3 drop-in is written and a warning is
logged.

B<Healing an earlier clobber.> A host set up by the 0.001 release carries a
stale full-config C<config.toml.tmpl> — the bare C<imports = [...]> +
C<version = 2> template (B<no> C<{{ template "base" . }}>) that I<replaced> the
distribution's base config. RKE2/K3s render that stale template, so the
generated C<config.toml> already shows an C<nvidia> runtime and the
B<Already wired> check above would no-op and leave the clobber (missing
C<SystemdCgroup> / pinned sandbox / C<certs.d>) in place. Before that check,
C<configure_containerd> therefore removes that C<config.toml.tmpl> B<only> when
it matches the exact bare-clobber signature (never the base-extending template
above, never a user's own custom C<config.toml.tmpl>, never
C<config-v3.toml.d/>), then writes the additive v3 drop-in. Removing the
template lets the distribution regenerate its native config, but the live
C<config.toml> stays clobbered until then: this function does B<not> restart
RKE2/K3s (that would bounce the node's containerd and its workloads); it logs a
warning that the operator must restart the service or reboot the node for the
native config to regenerate.

=item C<containerd>

Calls C<nvidia-ctk runtime configure --runtime=containerd> and restarts
the C<containerd> systemd service. Suitable for standalone (non-Rancher)
containerd installations.

=back

=cut

sub configure_containerd {
  my ($runtime) = @_;
  $runtime //= 'rke2';

  return unless can_run("nvidia-container-runtime");

  Rex::Logger::info("Configuring containerd for NVIDIA GPU (runtime: $runtime)");

  if ($runtime eq 'rke2' || $runtime eq 'k3s') {
    _configure_containerd_rke2($runtime);
  }
  elsif ($runtime eq 'containerd') {
    _configure_containerd_standalone();
  }
  else {
    die "Unknown containerd runtime: $runtime\n";
  }

  Rex::Logger::info("Containerd configured with NVIDIA runtime");
}

=method verify_nvidia

Verify the current NVIDIA installation by checking three things:

=over

=item 1. C<nvidia> kernel module is loaded (C<lsmod | grep nvidia>)

=item 2. C<nvidia-smi -L> reports at least one GPU

=item 3. C<nvidia-ctk> binary is available (Container Toolkit present)

=back

Returns C<1> if all checks pass, C<0> if any check fails. A warning is
logged for each failure; the function does not die. A partial installation
(e.g. driver installed but host not yet rebooted) emits a summary warning
noting that features may not work until reboot.

=cut

sub verify_nvidia {
  Rex::Logger::info("Verifying NVIDIA installation...");
  my $ok = 1;

  my $lsmod = run "lsmod | grep '^nvidia '", auto_die => 0;
  if ($? != 0 || !$lsmod) {
    Rex::Logger::info("nvidia kernel module not loaded (reboot may be needed)", "warn");
    $ok = 0;
  }
  else {
    Rex::Logger::info("  [ok] nvidia kernel module loaded");
  }

  my $smi = run "nvidia-smi -L 2>&1", auto_die => 0;
  chomp $smi if defined $smi;
  if (defined $smi && $smi =~ /GPU \d+:/) {
    Rex::Logger::info("  [ok] $smi");
  }
  else {
    Rex::Logger::info("nvidia-smi not working: " . ($smi // 'no output'), "warn");
    $ok = 0;
  }

  if (can_run("nvidia-ctk")) {
    Rex::Logger::info("  [ok] nvidia-container-toolkit installed");
  }
  else {
    Rex::Logger::info("nvidia-container-toolkit not found", "warn");
    $ok = 0;
  }

  unless ($ok) {
    Rex::Logger::info("GPU verification incomplete — some features may not work until reboot", "warn");
  }

  return $ok;
}

# ============================================================
#  Debian / Ubuntu
# ============================================================

sub _install_driver_debian {
  my ($os, $running_kernel, $gpu) = @_;

  my $arch = run "dpkg --print-architecture", auto_die => 0;
  chomp $arch;

  # Debian + Blackwell (karr #18): no Debian-packaged driver supports Blackwell
  # (bookworm 535, trixie/sid 550; Blackwell needs >= 570 AND the open kernel
  # module), so this install comes from NVIDIA's CUDA apt repo instead. Decided
  # BEFORE anything is written to the host: an unsupported Debian release or
  # architecture dies here, untouched. Undef for every non-Blackwell GPU (and
  # always on Ubuntu) — the Debian non-free path below is then unchanged; the
  # release is only read (one more remote file read) when it can matter.
  my $cuda_repo = ($os ne 'Ubuntu' && _ubuntu_needs_open_kernel_module($gpu))
    ? _debian_nvidia_cuda_repo($gpu, Rex::Commands::Gather::operating_system_release(), $arch)
    : undef;

  # Ensure non-free repos are enabled (Debian only, Ubuntu has restricted by
  # default). Not on the CUDA-repo path: its package set resolves from NVIDIA's
  # repo plus Debian main alone, and Debian's own nvidia packages must not be
  # mixed in.
  if ($os ne 'Ubuntu' && !$cuda_repo) {
    _enable_debian_nonfree();
  }

  my @packages = ("linux-headers-$running_kernel");

  if ($os eq 'Ubuntu') {
    push @packages, "linux-headers-generic";
    # Ubuntu: use server variant for K8s, auto-detect latest available version.
    # Do NOT add nvidia-smi: on Ubuntu 24.04 it is a virtual package with no
    # installation candidate — it is pulled in automatically by the driver metapackage.
    #
    # Blackwell-architecture silicon (B200/GB200, GeForce RTX 50xx, RTX PRO
    # Blackwell, the GB10 / DGX Spark) ships with NO proprietary kernel module
    # at all — only the -open variant binds, on x86_64 as on arm64 (karr
    # #14/#15/#16). _ubuntu_needs_open_kernel_module keys on the detected PCI
    # device ID only; for any non-Blackwell GPU (RTX 4000 Ada et al.), or no
    # GPU passed, it returns false and this branch behaves exactly as before.
    my $open = _ubuntu_needs_open_kernel_module($gpu);
    if ($open) {
      Rex::Logger::info("  Blackwell-class GPU on $arch — selecting the open-kernel-module driver");
    }
    my $search_pattern = $open
      ? '^nvidia-driver-[0-9].*-server-open$'
      : '^nvidia-driver-[0-9].*-server$';
    my $latest = run "apt-cache search '$search_pattern' 2>/dev/null | sort -t- -k3 -n | tail -1 | awk '{print \$1}'",
      auto_die => 0;
    chomp $latest if $latest;
    unless ($open) {
      # Filter out *-open variants from auto-detect (use regular server driver)
      $latest = undef if $latest && $latest =~ /-open$/;
    }
    push @packages, ($latest || ($open ? "nvidia-driver-570-server-open" : "nvidia-driver-570-server"));
  }
  elsif ($cuda_repo) {
    # Debian + Blackwell: NVIDIA's compute-only (headless) open-module set
    # from the CUDA repo. nvidia-driver-cuda provides nvidia-smi itself.
    Rex::Logger::info("  Blackwell-class GPU on Debian — using NVIDIA's CUDA repo "
      . "($cuda_repo->{distro}/$cuda_repo->{arch}), open kernel module");
    push @packages, @{ $cuda_repo->{packages} };
  }
  else {
    # Debian: just the running kernel's headers (sufficient for DKMS) + driver
    # Do NOT install linux-headers-$arch meta-package — it pulls in a new kernel
    # image whose post-install scripts (grub, initramfs) can return non-zero
    push @packages, "nvidia-driver", "nvidia-smi";
  }

  Rex::Logger::info("  Installing: " . join(", ", @packages));
  # Stop automatic apt services before installing — on a fresh Hetzner boot,
  # unattended-upgrades and apt-daily hold /var/lib/dpkg/lock-frontend, which
  # causes apt-get to fail immediately even with DPkg::Lock::Timeout set.
  run "systemctl stop unattended-upgrades apt-daily.service apt-daily-upgrade.service 2>/dev/null || true",
    auto_die => 0;
  _add_nvidia_cuda_apt_repo($cuda_repo) if $cuda_repo;
  run "apt-get -o DPkg::Lock::Timeout=120 update -q", auto_die => 0;

  # Use apt-get directly: Rex::Pkg::Apt fails when apt exits non-zero due to
  # post-install scripts (DKMS build, grub update, initramfs). Verify via dpkg -l.
  my $pkg_str = join(" ", @packages);
  run "DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y $pkg_str", auto_die => 0;

  # On Ubuntu the driver package is e.g. nvidia-driver-590-server (or, for
  # Blackwell-architecture GPUs, nvidia-driver-590-server-open); on Debian it
  # is nvidia-driver. Check whichever name we actually installed. On the
  # Debian CUDA-repo path, NOT nvidia-driver: that name exists in Debian
  # non-free too, so a leftover Debian 535/550 install would pass it. Both
  # packages of the open set are checked instead — nvidia-kernel-open-dkms
  # exists only in NVIDIA's repo. A DKMS build that fails in postinst leaves
  # the package half-configured (not ii), so this still dies on it.
  my @verify = $cuda_repo              ? @{ $cuda_repo->{packages} }
             : ($os eq 'Ubuntu')       ? ($packages[-1])
             :                           ('nvidia-driver');
  for my $driver_pkg (@verify) {
    my $check = run "dpkg -l $driver_pkg 2>/dev/null | grep -q '^ii'", auto_die => 0;
    die "$driver_pkg not installed after apt-get install — check apt output\n"
      if $? != 0;
  }
}

# Pure selection (karr #18): should this Debian (non-Ubuntu) install come from
# NVIDIA's CUDA apt repo instead of Debian non-free, and with what parameters?
#
#   $gpu     — detected GPU hashref (Rex::GPU::Detect shape), may be undef
#   $release — operating_system_release(): /etc/debian_version, e.g. "13.1",
#              "12.11", "trixie/sid" (NOT operating_system_version(), which
#              strips the dots: "12.11" -> "1211")
#   $arch    — `dpkg --print-architecture`: amd64 / arm64
#
# Returns undef unless the GPU needs the open kernel module (Blackwell, see
# Rex::GPU::Detect::open_kernel_module_required; the "_ubuntu_" predicate is
# distro-neutral despite its name) — the caller then keeps the Debian
# non-free path, unchanged. Otherwise returns { distro, arch, keyring_url,
# packages }.
#
# Dies — fail loud, before any change on the host — for a Blackwell GPU on a
# Debian release NVIDIA publishes no repo for (only debian12/debian13 exist;
# 11, 14, testing/sid "forky/sid", a derivative's own version) or on an
# architecture other than amd64/arm64. Falling back to Debian non-free there
# would install a driver that dpkg reports as ii but whose module never binds
# — exactly the bug this path fixes; guessing a neighbouring repo would mix
# a foreign distro's libc/dkms into the host.
sub _debian_nvidia_cuda_repo {
  my ($gpu, $release, $arch) = @_;
  return unless _ubuntu_needs_open_kernel_module($gpu);

  my $major = _os_major_version($release // '');
  die "Blackwell-class NVIDIA GPU on Debian release '" . ($release // '') . "': "
    . "Debian's own nvidia packages cannot drive it and NVIDIA's CUDA repo only "
    . "covers Debian 12 and 13 — install the driver manually\n"
    unless $major == 12 || $major == 13;

  $arch //= '';
  die "Blackwell-class NVIDIA GPU on Debian architecture '$arch': NVIDIA's CUDA "
    . "repo only covers amd64 and arm64\n"
    unless $arch eq 'amd64' || $arch eq 'arm64';

  my $distro    = "debian$major";
  my $repo_arch = _cuda_repo_arch($arch);   # arm64 -> sbsa, amd64 -> x86_64
  return {
    distro      => $distro,
    arch        => $repo_arch,
    keyring_url => "https://developer.download.nvidia.com/compute/cuda/repos/$distro/$repo_arch/cuda-keyring_1.1-1_all.deb",
    packages    => [ 'nvidia-driver-cuda', 'nvidia-kernel-open-dkms' ]
  };
}

# Register NVIDIA's CUDA apt repo via its cuda-keyring package (installs the
# signing key and the sources.list.d entry). curl is an inert helper, so pkg
# is fine for it; the keyring itself goes through apt-get (lock timeout) like
# every other package here. Dies if the keyring did not end up installed —
# without it the following apt-get install can only fail with a misleading
# "unable to locate package".
sub _add_nvidia_cuda_apt_repo {
  my ($repo) = @_;
  Rex::Logger::info("  Adding NVIDIA CUDA repo ($repo->{distro}/$repo->{arch})...");
  pkg ["curl"], ensure => "present";
  run q{t=$(mktemp -d) && curl -fsSL -o "$t/cuda-keyring.deb" }
    . $repo->{keyring_url}
    . q{ && DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y "$t/cuda-keyring.deb"; rm -rf "$t"},
    auto_die => 0;
  my $check = run "dpkg -l cuda-keyring 2>/dev/null | grep -q '^ii'", auto_die => 0;
  die "cuda-keyring not installed — cannot add NVIDIA's CUDA repo ($repo->{keyring_url})\n"
    if $? != 0;
}

# Pure predicate (karr #15, generalised in #16): given the detected GPU
# hashref (Rex::GPU::Detect shape: name/device_id/...), should Ubuntu driver
# selection pick the -open package variant instead of the default -server
# one? True only for a device ID Rex::GPU::Detect::open_kernel_module_required
# marks open-only (Blackwell architecture — no proprietary kernel module
# exists for it). No CPU-architecture gate: an RTX 50xx or B200 on x86_64
# needs -open exactly like the GB10 on arm64. The device-ID judgement is NOT
# duplicated here — it lives in Detect.pm only. No GPU, a non-hashref, a
# missing device_id or any non-Blackwell ID => false => -server as before.
#
# Pure (string/hash access only, no run/dpkg) so it is unit-testable offline,
# like _nvidia_driver_present / _cuda_repo_arch.
sub _ubuntu_needs_open_kernel_module {
  my ($gpu) = @_;
  return 0 unless $gpu && ref $gpu eq 'HASH';
  return Rex::GPU::Detect::open_kernel_module_required($gpu->{device_id});
}

sub _enable_debian_nonfree {
  # Add contrib non-free non-free-firmware to all deb lines
  my $sources = run "cat /etc/apt/sources.list 2>/dev/null", auto_die => 0;
  return unless $sources;

  if ($sources !~ /non-free/) {
    Rex::Logger::info("  Enabling non-free repos for NVIDIA drivers");
    run "sed -i 's/^deb \\(.*\\) main/deb \\1 main contrib non-free non-free-firmware/' /etc/apt/sources.list",
      auto_die => 0;
  }
}

# ============================================================
#  RHEL / Rocky / AlmaLinux / CentOS Stream
# ============================================================

sub _install_driver_redhat {
  my ($os, $running_kernel) = @_;

  my $major = _os_major_version();

  # Enable required repos
  Rex::Logger::info("  Enabling EPEL and extra repos...");
  pkg ["epel-release"], ensure => "present";

  if ($major >= 9) {
    run "dnf config-manager --set-enabled crb 2>/dev/null || true", auto_die => 0;
  }
  else {
    run "dnf config-manager --set-enabled powertools 2>/dev/null || true", auto_die => 0;
  }

  # Add NVIDIA CUDA repo — arch-aware: aarch64 server/datacenter parts (Grace,
  # Hopper, Blackwell) are published under the "sbsa" tree, not "x86_64".
  my $distro  = "rhel$major";
  my $machine = run "uname -m", auto_die => 0;
  chomp $machine if defined $machine;
  my $arch = _cuda_repo_arch($machine);
  Rex::Logger::info("  Adding NVIDIA CUDA repo ($distro/$arch)...");
  run "dnf config-manager --add-repo https://developer.download.nvidia.com/compute/cuda/repos/$distro/$arch/cuda-$distro.repo 2>/dev/null",
    auto_die => 0;
  run "dnf clean expire-cache", auto_die => 0;

  # Kernel headers
  my @packages;
  if ($major >= 9) {
    @packages = ("kernel-devel-matched", "kernel-headers");
  }
  else {
    @packages = ("kernel-devel-$running_kernel", "kernel-headers");
  }

  # Driver packages — different for v10 (no module streams, dkms variant)
  if ($major >= 10) {
    push @packages, "kmod-nvidia-open-dkms", "nvidia-driver", "nvidia-driver-cuda";
  }
  else {
    run "dnf module enable nvidia-driver:open-dkms -y 2>/dev/null || true", auto_die => 0;
    push @packages, "nvidia-open";
  }

  Rex::Logger::info("  Installing: " . join(", ", @packages));

  # Use run() directly: Rex::Pkg::Dnf fails when dnf exits non-zero due to
  # DKMS post-install scripts (kernel module build). Verify via rpm -q instead.
  my $pkg_str = join(" ", @packages);
  run "dnf install -y $pkg_str", auto_die => 0;

  my $check = run "rpm -q nvidia-driver 2>&1", auto_die => 0;
  die "nvidia-driver not installed after dnf install — check dnf output\n"
    if $? != 0;
}

# Map the machine hardware name (`uname -m`) to the architecture token NVIDIA
# uses in its CUDA package repositories:
#   developer.download.nvidia.com/compute/cuda/repos/<distro>/<arch>/
# aarch64 server/datacenter parts (Grace, Hopper, Blackwell) are published as
# "sbsa" — NOT "aarch64" or "arm64" (verified: repos/rhel9/sbsa and
# repos/rhel10/sbsa resolve, repos/.../aarch64 does not). Everything else keeps
# the previous behaviour and maps to "x86_64", including an empty string when
# `uname -m` could not be read. Pure (string map only) so it is unit-testable
# offline. NB: this token is specific to the CUDA repos. The
# libnvidia-container toolkit repo uses "aarch64" for the same machine, so do
# NOT reuse this helper for the toolkit path.
sub _cuda_repo_arch {
  my ($machine) = @_;
  $machine //= '';
  return 'sbsa' if $machine eq 'aarch64' || $machine eq 'arm64';
  return 'x86_64';
}

sub _os_major_version {
  # Rex::Commands::Gather::operating_system_version() strips dots,
  # so "10.1" becomes "101". Use the raw operating_system_release() string
  # and extract the major version ourselves. An explicit $release may be
  # passed so callers stay pure and unit-testable.
  my ($release) = @_;
  $release //= Rex::Commands::Gather::operating_system_release();
  my ($major) = $release =~ /^(\d+)/;
  return ($major // 0) + 0;
}

# ============================================================
#  openSUSE Leap
# ============================================================

sub _install_driver_suse {
  my ($os, $running_kernel) = @_;

  my $release = Rex::Commands::Gather::operating_system_release();
  my ($repo_url, $meta_pkg) = _suse_nvidia_repo_params($release);

  # Remove any stale NVIDIA packages first — avoids kmp/userspace version mismatch
  # caused by libnvidia-ml/libnvidia-cfg from the standard OSS non-free repo lagging
  # behind the NVIDIA GFX repo packages.
  Rex::Logger::info("  Removing any existing NVIDIA packages...");
  run q{rpm -e $(rpm -qa | grep -E '^(nvidia|libnvidia)' | grep -v 'container') 2>/dev/null || true},
    auto_die => 0;

  # Add NVIDIA GFX repo (use direct baseurls — zypper cannot parse yum .repo files)
  Rex::Logger::info("  Adding NVIDIA GFX repo (Leap $release): $repo_url");
  run "zypper rr nvidia-gfx 2>/dev/null || true", auto_die => 0;
  run "zypper addrepo --refresh $repo_url nvidia-gfx 2>/dev/null", auto_die => 0;
  run "zypper --gpg-auto-import-keys refresh nvidia-gfx 2>/dev/null", auto_die => 0;

  # Use the meta package — it co-installs kmp-default + userspace at the same version,
  # preventing the split that causes "Driver/library version mismatch" with nvidia-smi.
  # Pre-signed kmp packages don't need kernel-devel/headers. The repo URL and meta
  # package (G06 for Leap 15.x, G07 for 16.x) come from _suse_nvidia_repo_params.
  Rex::Logger::info("  Installing $meta_pkg...");
  run "zypper install -y $meta_pkg", auto_die => 0;

  # Lock the OSS non-free standalone packages so future zypper updates don't
  # pull in a stale libnvidia-ml / libnvidia-cfg and cause a mismatch again.
  run "zypper addlock libnvidia-ml libnvidia-cfg 2>/dev/null || true", auto_die => 0;
}

sub _suse_nvidia_repo_params {
  my ($release) = @_;

  # Derive the major from the raw release string. operating_system_version()
  # strips dots ("15.6" -> "156"), which made int() see 156 and route every
  # Leap through the ">= 16" branch (karr #6).
  my $major = _os_major_version($release);

  if ($major >= 16) {
    return ("https://download.nvidia.com/opensuse/leap/16.0/",
            "nvidia-open-driver-G07-signed-kmp-meta");
  }

  # Leap 15.x: keep the full x.y version in the repo path (leap/15.6/).
  my ($leap_version) = $release =~ /^(\d+\.\d+)/;
  $leap_version //= $release;
  return ("https://download.nvidia.com/opensuse/leap/$leap_version/",
          "nvidia-open-driver-G06-signed-kmp-meta");
}

# ============================================================
#  Nouveau blacklisting
# ============================================================

sub _blacklist_nouveau {
  file "/etc/modprobe.d/blacklist-nouveau.conf",
    content => "blacklist nouveau\noptions nouveau modeset=0\n";

  if (is_debian()) {
    run "update-initramfs -u 2>/dev/null", auto_die => 0;
  }
  elsif (is_redhat()) {
    run "dracut --force 2>/dev/null", auto_die => 0;
  }
  elsif (is_suse()) {
    run "dracut --force 2>/dev/null", auto_die => 0;
  }
}

# ============================================================
#  Container toolkit installation
# ============================================================

sub _install_toolkit_debian {
  pkg ["curl", "gnupg"], ensure => "present";

  run "curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg 2>/dev/null",
    auto_die => 0;

  file "/etc/apt/sources.list.d/nvidia-container-toolkit.list",
    content => 'deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://nvidia.github.io/libnvidia-container/stable/deb/$(ARCH) /' . "\n";

  run "apt-get -o DPkg::Lock::Timeout=120 update -q", auto_die => 0;
  # DPkg::Lock::Timeout=120: wait for apt-daily.timer lock that fires after reboot.
  run "DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y nvidia-container-toolkit", auto_die => 0;
  my $check = run "dpkg -l nvidia-container-toolkit 2>/dev/null | grep -q '^ii'", auto_die => 0;
  die "nvidia-container-toolkit not installed\n" if $? != 0;
}

sub _install_toolkit_redhat {
  run "curl -s -L https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo | tee /etc/yum.repos.d/nvidia-container-toolkit.repo",
    auto_die => 0;
  run "dnf clean expire-cache", auto_die => 0;
  run "dnf install -y nvidia-container-toolkit", auto_die => 0;
  my $check = run "rpm -q nvidia-container-toolkit 2>&1", auto_die => 0;
  die "nvidia-container-toolkit not installed\n" if $? != 0;
}

sub _install_toolkit_suse {
  # The .repo file URL is yum/dnf format — zypper needs the baseurl directly.
  # Remove any stale entry (possibly added with the wrong URL) before re-adding.
  my $arch = run "uname -m", auto_die => 0;
  chomp $arch;
  $arch ||= 'x86_64';

  run "zypper rr nvidia-container-toolkit 2>/dev/null || true", auto_die => 0;
  run "rpm --import https://nvidia.github.io/libnvidia-container/gpgkey 2>/dev/null",
    auto_die => 0;
  run "zypper addrepo --refresh https://nvidia.github.io/libnvidia-container/stable/rpm/$arch nvidia-container-toolkit 2>/dev/null",
    auto_die => 0;
  run "zypper --gpg-auto-import-keys refresh nvidia-container-toolkit 2>/dev/null",
    auto_die => 0;

  run "zypper install -y nvidia-container-toolkit", auto_die => 0;
}

# ============================================================
#  Containerd configuration
# ============================================================

sub _rke2_base_dir {
  my ($runtime) = @_;
  $runtime //= 'rke2';
  my $dist = ($runtime eq 'k3s') ? 'k3s' : 'rke2';
  return "/var/lib/rancher/$dist/agent/etc/containerd";
}

# Decide, from the effective containerd state, HOW to register the nvidia
# runtime. Pure (regex + booleans only, no I/O) so it is unit-testable offline.
#
#   config      => contents of the RKE2/K3s-generated config.toml (or undef)
#   has_v3_tmpl => a config-v3.toml.tmpl base template is present
#   has_v3_dir  => a config-v3.toml.d/ drop-in directory is present
#
# Returns one of:
#   'present' — the distro already wired an nvidia runtime (leave it alone)
#   'v3'      — modern containerd 2.x / config v3: use an additive drop-in
#   'v2'      — legacy containerd 1.x / config v2: extend the base template
#
# Ordering is load-bearing: a distro that auto-detected nvidia-container-runtime
# on PATH wires the runtime itself, so 'present' must win before any write path.
sub _containerd_nvidia_action {
  my (%s) = @_;
  my $config = $s{config} // '';

  # Already wired (RKE2/K3s auto-detect, or a prior additive drop-in) — no-op.
  return 'present' if $config =~ /runtimes\.'?nvidia'?[.\]]/;

  # Modern config v3: additive drop-in in config-v3.toml.d/.
  return 'v3' if $s{has_v3_tmpl} || $s{has_v3_dir};
  return 'v3' if $config =~ /^\s*version\s*=\s*3\b/m;
  return 'v3' if $config =~ /config-v3\.toml\.d/;

  # Legacy config v2 (containerd 1.x): base-extending config.toml.tmpl.
  return 'v2'
    if $config =~ /^\s*version\s*=\s*2\b/m
    || $config =~ /io\.containerd\.grpc\.v1\.cri/;

  # No generated config yet and no version markers: default to the modern
  # v3 drop-in (the current RKE2/K3s norm). Caller warns; see POD.
  return 'v3';
}

# Modern (containerd 2.x / config v3) additive drop-in. RKE2/K3s import
# config-v3.toml.d/*.toml into their generated config.toml, so this ADDS the
# nvidia runtime without touching the base — SystemdCgroup, the pinned sandbox
# image, snapshotter opts and the certs.d config_path all survive. Uses the
# v3 CRI plugin path (io.containerd.cri.v1.runtime), matching what the distro
# auto-wires. SystemdCgroup=true keeps the cgroup driver aligned with kubelet.
sub _nvidia_containerd_dropin_v3 {
  return <<'TOML';
version = 3

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'nvidia']
  runtime_type = "io.containerd.runc.v2"

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'nvidia'.options]
  BinaryName = "/usr/bin/nvidia-container-runtime"
  SystemdCgroup = true
TOML
}

# Legacy (containerd 1.x / config v2) base-extending template. RKE2/K3s render
# config.toml.tmpl if present; {{ template "base" . }} emits the full default
# config first, then we ADD the nvidia runtime under the v2 CRI plugin path.
# NEVER a bare full-config tmpl (that replaced the base and was karr #9).
sub _nvidia_containerd_tmpl_v2 {
  return <<'TOML';
{{ template "base" . }}

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."nvidia"]
  runtime_type = "io.containerd.runc.v2"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."nvidia".options]
  BinaryName = "/usr/bin/nvidia-container-runtime"
  SystemdCgroup = true
TOML
}

sub _path_exists {
  my ($flag, $path) = @_;
  run "test $flag $path", auto_die => 0;
  return $? == 0 ? 1 : 0;
}

# Write the modern (config v3) additive nvidia drop-in under $base. Shared by
# the normal 'v3' action and the karr #13 clobber-heal path so both emit the
# exact same additive wiring. RKE2/K3s import config-v3.toml.d/*.toml into the
# config.toml they generate, so this ADDS the nvidia runtime without touching
# the base.
sub _write_nvidia_v3_dropin {
  my ($base) = @_;
  file "$base/config-v3.toml.d", ensure => 'directory';
  file "$base/config-v3.toml.d/99-nvidia.toml",
    content => _nvidia_containerd_dropin_v3();
  Rex::Logger::info(
    "  wrote additive nvidia drop-in: $base/config-v3.toml.d/99-nvidia.toml");
}

# Pure predicate (karr #13): does this config.toml.tmpl content match the EXACT
# full-config clobber that rex-gpu 0.002 wrote (pre-karr #9)? That code wrote a
# bare template — literally:
#
#     imports = ["/etc/containerd/conf.d/*.toml"]
#     version = 2
#
# which REPLACED the RKE2/K3s base config (no `{{ template "base" . }}`, hence
# no SystemdCgroup / pinned sandbox image / certs.d config_path in the rendered
# config.toml). Matching this — and ONLY this — is what lets the heal remove it
# so the distro regenerates its native config.
#
# Removing a file on a live remote root shell is the top risk here, so the match
# is deliberately narrow. Returns 1 ONLY when, ignoring blank lines and #
# comments, the content is exactly an `imports =` line PLUS a `version = 2` line
# and nothing else. Any `{{ template "base" ... }}` directive (the karr #9
# base-extending tmpl, or any base-rendering template) => 0. Any other
# substantive line — a [plugins...] section, a real base key, any further
# content — means this carries actual config (a user's own tmpl, or something
# that is not the bare clobber) => 0. When in doubt, 0.
#
# Pure (regex/string only, no run/file) so it is unit-testable offline, like
# _containerd_nvidia_action / _nvidia_driver_present / _cdi_managed_source_present.
sub _is_rke2_clobber_tmpl {
  my ($content) = @_;
  return 0 unless defined $content && length $content;

  # The base-extending tmpl (#9) and any base-rendering template carry the
  # `{{ template "base" . }}` directive — the signature of the SAFE tmpl.
  return 0 if $content =~ /\{\{\s*template\s+["']base["']/;

  my @lines = grep { /\S/ && !/^\s*#/ } split /\n/, $content;
  return 0 unless @lines;

  my ($imports, $version2) = (0, 0);
  for my $l (@lines) {
    if    ($l =~ /^\s*imports\s*=/)         { $imports  = 1 }
    elsif ($l =~ /^\s*version\s*=\s*2\s*$/) { $version2 = 1 }
    else                                    { return 0 }
  }
  return ($imports && $version2) ? 1 : 0;
}

sub _configure_containerd_rke2 {
  my ($runtime) = @_;
  $runtime //= 'rke2';

  my $base        = _rke2_base_dir($runtime);
  my $config_file = "$base/config.toml";
  my $tmpl_file   = "$base/config.toml.tmpl";

  # Heal an EARLIER clobber (karr #13). rex-gpu 0.002 (pre-karr #9) wrote a bare
  # full-config config.toml.tmpl that REPLACED the RKE2/K3s base config. Detect
  # and remove THAT exact artifact BEFORE trusting the generated config.toml
  # below: the generated config IS the clobber's output — it already carries an
  # nvidia runtime, so the 'already-wired' (present) check would no-op and leave
  # the clobber (missing SystemdCgroup / pinned sandbox / certs.d) in place
  # forever. Removing the tmpl is what lets the distro regenerate its native
  # config on the next restart. _is_rke2_clobber_tmpl matches ONLY the bare
  # clobber, never the #9 base-extending tmpl or a user's own custom tmpl.
  my $tmpl = run "cat $tmpl_file 2>/dev/null", auto_die => 0;
  if (_is_rke2_clobber_tmpl($tmpl)) {
    Rex::Logger::info(
      "  removing legacy rex-gpu full-config clobber $tmpl_file so $runtime "
      . "regenerates its native containerd config (karr #13)", "warn");
    run "rm -f $tmpl_file", auto_die => 0;

    # The live config.toml is STILL the clobber's output until $runtime restarts
    # and regenerates it. We deliberately do NOT restart rke2/k3s here: that
    # bounces the node's containerd and its workloads as a side effect of GPU
    # setup, and the node is no worse than before (it was already clobbered).
    # The heal completes on the next $runtime restart / node reboot — warn so
    # the operator triggers it. (config.toml is NOT self-healing.)
    Rex::Logger::info(
      "  restart $runtime (or reboot the node) to regenerate the native "
      . "containerd config — config.toml stays clobbered until then", "warn");

    # Wire nvidia additively into the config $runtime will regenerate. The
    # real-world clobber target is modern RKE2/K3s (containerd 2.x / config v3),
    # whose native config imports config-v3.toml.d/*.toml; a base-extending
    # config.toml.tmpl would just recreate the file we just removed.
    _write_nvidia_v3_dropin($base);
    return;
  }

  # RKE2/K3s regenerate config.toml on every startup; it reflects the effective
  # merged runtime config, including any nvidia runtime the distro auto-wired
  # after finding nvidia-container-runtime on PATH.
  my $config = run "cat $config_file 2>/dev/null", auto_die => 0;

  my $action = _containerd_nvidia_action(
    config      => $config,
    has_v3_tmpl => _path_exists("-f", "$base/config-v3.toml.tmpl"),
    has_v3_dir  => _path_exists("-d", "$base/config-v3.toml.d"),
  );

  if ($action eq 'present') {
    Rex::Logger::info(
      "  $runtime already wired the nvidia runtime natively — leaving containerd config untouched");
    return;
  }

  if ($action eq 'v3') {
    Rex::Logger::info(
      "  no generated $config_file yet and no config version markers — "
      . "assuming modern (config v3) $runtime", "warn")
      unless defined $config && length $config;

    _write_nvidia_v3_dropin($base);
  }
  else {
    file $base, ensure => 'directory';
    file "$base/config.toml.tmpl", content => _nvidia_containerd_tmpl_v2();
    Rex::Logger::info(
      "  wrote base-extending config.toml.tmpl (legacy v2): $base/config.toml.tmpl");
  }
}

sub _configure_containerd_standalone {
  run "nvidia-ctk runtime configure --runtime=containerd 2>&1", auto_die => 0;
  run "systemctl restart containerd 2>/dev/null", auto_die => 0;
}

# ============================================================
#  CDI spec generation
# ============================================================

=method generate_cdi_specs

Generate CDI (Container Device Interface) specifications for the detected
NVIDIA GPUs so the Kubernetes NVIDIA device plugin can enumerate GPU resources
without requiring a privileged container.

If a B<managed CDI source> already owns the runtime scan dir, this function
does B<not> also write a static C</etc/cdi/nvidia.yaml>. Modern
C<nvidia-container-toolkit> ships C<nvidia-cdi-refresh.path>/C<.service>, which
regenerate C</run/cdi/nvidia.yaml> and keep it fresh across driver updates.
Because C</etc/cdi> and C</run/cdi> are both default CDI scan dirs, a second
static copy would define the same device kind (C<nvidia.com/gpu>) twice — a
duplicate-device load error in CDI consumers — and would drift against the
refreshed copy over driver updates. In that case the managed generator is
triggered once (so C</run/cdi> is populated immediately) and left to own CDI.

Otherwise — no managed refresh unit and no existing C</run/cdi/nvidia.yaml> —
output is written to C</etc/cdi/nvidia.yaml> via C<nvidia-ctk cdi generate>, and
the C</etc/cdi/> directory is created if it does not exist. Only one of the two
scan dirs is ever populated.

The managed-source check keys on the C<nvidia-cdi-refresh.path> systemd unit
state (installed/armed) rather than only on the presence of
C</run/cdi/nvidia.yaml>, because C</run> is tmpfs and is empty right after the
first-deploy reboot even though the refresh unit owns CDI from then on.

This step must be run after L</install_container_toolkit> (which provides
C<nvidia-ctk> and the refresh unit) and, on first deploy, after the reboot that
activates the NVIDIA kernel module (so the tool can enumerate physical devices).

B<MIG.> The spec reflects the MIG layout at the time it is generated (MIG
instances are included by default). Neither the static C</etc/cdi/nvidia.yaml>
nor C<nvidia-cdi-refresh> regenerates it when MIG mode or instances are
reconfigured. After changing MIG, run
C<systemctl restart nvidia-cdi-refresh.service>, or on a host without that unit
C<nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml>. The MIG strategy
Kubernetes exposes (C<single> / C<mixed>) is configured in the NVIDIA device
plugin or GPU Operator, not here.

=cut

sub generate_cdi_specs {
  Rex::Logger::info("Generating NVIDIA CDI specs...");

  # Hand off to a managed CDI source if one owns the runtime scan dir. Modern
  # nvidia-container-toolkit ships nvidia-cdi-refresh.path/.service, which keep
  # /run/cdi/nvidia.yaml fresh across driver updates. /etc/cdi and /run/cdi are
  # BOTH default CDI scan dirs, so writing a static /etc/cdi/nvidia.yaml
  # alongside the managed /run/cdi copy defines the same device kind
  # (nvidia.com/gpu) twice — a duplicate-device load error in CDI consumers —
  # and the static copy drifts against the refreshed one over driver updates.
  # See _cdi_managed_source_present for the signal choice (karr #11).
  my $enabled = run "systemctl is-enabled nvidia-cdi-refresh.path 2>/dev/null", auto_die => 0;
  chomp $enabled if defined $enabled;
  my $active = run "systemctl is-active nvidia-cdi-refresh.path 2>/dev/null", auto_die => 0;
  chomp $active if defined $active;

  if (_cdi_managed_source_present(
      enabled_state => $enabled,
      active_state  => $active,
      run_cdi       => _path_exists("-f", "/run/cdi/nvidia.yaml"),
  )) {
    Rex::Logger::info(
      "  nvidia-cdi-refresh manages CDI in /run/cdi — not writing a static "
      . "/etc/cdi/nvidia.yaml (avoids a duplicate nvidia.com/gpu across scan dirs)");
    # Kick the managed generator once so /run/cdi is populated NOW: /run is
    # tmpfs and empty after the first-deploy reboot, and the .path watcher may
    # not have fired yet (no driver-file change since it was armed). Best-effort
    # — the unit re-runs itself on the next driver change; if the unit name
    # differs (detected via the /run/cdi file), this is a harmless no-op.
    run "systemctl start nvidia-cdi-refresh.service 2>/dev/null", auto_die => 0;
    return;
  }

  run "mkdir -p /etc/cdi", auto_die => 0;
  run "nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml 2>/dev/null", auto_die => 0;
  Rex::Logger::info("  [ok] CDI specs written to /etc/cdi/nvidia.yaml");
}

# Pure predicate for the generate_cdi_specs managed-source short-circuit: is a
# MANAGED CDI source already present that owns /run/cdi/nvidia.yaml? Modern
# nvidia-container-toolkit ships nvidia-cdi-refresh.path/.service, which
# regenerate a CDI spec into the /run/cdi runtime scan dir and keep it fresh
# across driver updates. When it is present, generate_cdi_specs must NOT also
# write a static /etc/cdi/nvidia.yaml (both are default scan dirs → duplicate
# nvidia.com/gpu + drift; karr #11).
#
# Signals (gathered impurely by generate_cdi_specs, matched here):
#   enabled_state => `systemctl is-enabled nvidia-cdi-refresh.path` output
#   active_state  => `systemctl is-active  nvidia-cdi-refresh.path` output
#   run_cdi       => a /run/cdi/nvidia.yaml already exists (boolean)
#
# The systemd unit state is the PRIMARY signal, not the file. /run is tmpfs and
# is wiped on every boot, so on a first deploy (right after the nouveau reboot)
# the managed source may not have fired yet and /run/cdi/nvidia.yaml is absent
# even though the refresh unit owns CDI from here on. The unit being installed
# (enabled/enabled-runtime/static/indirect/alias) or armed (active/activating)
# is durable across that reboot and answers the real question — "will this host
# keep /run/cdi fresh?" — which a bare file check cannot. run_cdi is a
# belt-and-suspenders confirmation: this code only ever writes /etc/cdi, so a
# /run/cdi/nvidia.yaml can only have come from some OTHER producer — unambiguous
# evidence of a second CDI source for the same kind (catches a producer under a
# different unit name, or a host with no systemctl). disabled/masked/not-found
# (opted out, or no such unit) do NOT count as managed.
#
# Pure (regex/string/boolean only, no run/systemctl/test) so it is unit-testable
# offline, like _nvidia_driver_present / _containerd_nvidia_action.
sub _cdi_managed_source_present {
  my (%s) = @_;
  my $enabled = $s{enabled_state} // '';
  my $active  = $s{active_state}  // '';
  return 1 if $enabled =~ /^(?:enabled|enabled-runtime|static|indirect|alias)\b/;
  return 1 if $active  =~ /^(?:active|activating)\b/;
  return 1 if $s{run_cdi};
  return 0;
}

# ============================================================
#  Reboot
# ============================================================

sub _reboot_and_wait {
  Rex::Logger::info("Rebooting host to activate NVIDIA driver (replacing nouveau)...");

  # Schedule reboot 2 s from now so the run() call can return cleanly
  run "nohup sh -c 'sleep 2 && shutdown -r now' >/dev/null 2>&1 &", auto_die => 0;

  # Wait long enough for the system to actually go down
  sleep 20;

  # Poll until SSH comes back (up to 5 minutes)
  my $conn = Rex::get_current_connection()->{conn};
  my $back = 0;
  for my $i (1..60) {
    eval { $conn->disconnect() };
    eval { $conn->reconnect() };
    unless ($@) {
      # Verify we can actually run a command
      my $test = eval { run "echo ok", auto_die => 0; "ok" };
      if (defined $test && $test =~ /ok/) {
        Rex::Logger::info("  Host is back online (after ~" . ($i * 5 + 20) . "s)");
        $back = 1;
        last;
      }
    }
    Rex::Logger::info("  Waiting for host to come back... ($i/60)");
    sleep 5;
  }

  die "Host did not come back after reboot\n" unless $back;
}

1;

=head1 SYNOPSIS

  use Rex::GPU::NVIDIA;

  # Step 1: Install driver (with reboot on first deploy)
  install_driver(reboot => 1);

  # Step 2: Install NVIDIA Container Toolkit
  install_container_toolkit();

  # Step 3: Generate CDI specs for the device plugin
  generate_cdi_specs();

  # Step 4: Configure containerd for Kubernetes
  configure_containerd('rke2');   # 'rke2', 'k3s', or 'containerd'

  # Verify the current installation status
  my $ok = verify_nvidia();

=head1 DESCRIPTION

L<Rex::GPU::NVIDIA> manages the full NVIDIA software stack needed to run
GPU-accelerated workloads in Kubernetes: driver installation, the Container
Toolkit, CDI spec generation, and containerd runtime configuration.

Each step is OS-aware and handles Debian/Ubuntu, RHEL/Rocky/CentOS, and
openSUSE Leap without further configuration.

=head2 Driver installation

Drivers are installed via DKMS, so they survive kernel upgrades without
needing reinstallation. The C<nouveau> open-source driver is blacklisted
and the initramfs is regenerated to prevent it from loading at boot.

On Debian, C<contrib>, C<non-free>, and C<non-free-firmware> components
are added to C</etc/apt/sources.list> automatically if not already present.

On Ubuntu, the newest available C<nvidia-driver-NNN-server> package is
auto-detected and installed. On aarch64 (C<dpkg --print-architecture>
C<arm64>) for a GPU whose PCI device ID L<Rex::GPU::Detect> marks
open-kernel-module-only — the GB10 / NVIDIA DGX Spark, which has no
proprietary kernel module at all — the C<-server-open> variant is selected
instead. This requires the caller (L<Rex::GPU/gpu_setup> does this
automatically) to pass the detected GPU via the C<gpu> option to
L</install_driver>; without it, or on x86_64, the plain C<-server> package is
used exactly as before.

On RHEL/Rocky/AlmaLinux/CentOS Stream, the NVIDIA CUDA repository is added
and the open-kernel DKMS variant is used. For RHEL 10+ the module streams
approach is not available; C<kmod-nvidia-open-dkms> is installed directly.
The CUDA repository URL is architecture-aware: aarch64 hosts use the C<sbsa>
tree (C<repos/rhelN/sbsa/>), x86_64 hosts the C<x86_64> tree.

On openSUSE Leap, the signed kmp-meta package (C<nvidia-open-driver-G06-signed-kmp-meta>
for Leap 15.x, C<nvidia-open-driver-G07-signed-kmp-meta> for Leap 16.x) is
used to ensure the kernel module and userspace libraries are always at the
same version. Stale OSS non-free packages are removed before installation
and locked afterwards to prevent C<nvidia-smi> from reporting a
C<Driver/library version mismatch>.

=head2 Container Toolkit

C<nvidia-container-toolkit> is installed from the official NVIDIA GitHub
package repository (L<https://nvidia.github.io/libnvidia-container/>).

=head2 CDI specs

Container Device Interface specifications let the Kubernetes device plugin
enumerate GPU resources without requiring privileged container access. When a
managed CDI source — the C<nvidia-cdi-refresh> systemd unit shipped by modern
C<nvidia-container-toolkit> — already keeps C</run/cdi/nvidia.yaml> fresh, that
source is left to own CDI; otherwise a static spec is written to
C</etc/cdi/nvidia.yaml> by C<nvidia-ctk cdi generate>. Only one of the two
default scan dirs (C</etc/cdi>, C</run/cdi>) is populated, so C<nvidia.com/gpu>
is never defined twice.

=head2 Containerd configuration

For RKE2 and K3s, the NVIDIA runtime is registered additively and
version-aware, without clobbering the config that the distribution generates:
a no-op when RKE2/K3s already wired the runtime natively, a
C<config-v3.toml.d/> drop-in on modern (containerd 2.x / config v3) hosts, or
a base-extending (C<{{ template "base" . }}>) C<config.toml.tmpl> on legacy
(containerd 1.x / config v2) hosts. A stale full-config C<config.toml.tmpl>
left by the 0.001 release is detected by its exact bare-clobber signature and
removed so the distribution regenerates its native config (the operator must
restart the service or reboot for that to take effect). For standalone
containerd, C<nvidia-ctk runtime configure> is used.

Supported distributions:

=over

=item * Debian 11 (bullseye), 12 (bookworm), 13 (trixie)

=item * Ubuntu 22.04 (jammy), 24.04 (noble)

=item * RHEL / Rocky Linux / AlmaLinux 8, 9, 10 — CentOS Stream 9, 10

=back

The verified target set is the RKE2 Linux family above. B<openSUSE Leap / SLES
is unverified and unsupported> — SUSE is not a deploy target for the
GPU-on-Rancher pipeline. The C<_install_driver_suse> path exists but is not
exercised; do not treat a SUSE run as evidence.

Tested on Hetzner dedicated servers with NVIDIA RTX 4000 SFF Ada Generation.

=head1 SEE ALSO

L<Rex::GPU>, L<Rex::GPU::Detect>,
L<https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/>

=cut
