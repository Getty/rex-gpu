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

use Rex::GPU::NVIDIA::Setup;
use Rex::GPU::NVIDIA::Setup::Debian;
use Rex::GPU::NVIDIA::Setup::RHEL;
use Rex::GPU::NVIDIA::Setup::SUSE;
use Rex::GPU::NVIDIA::Setup::Ubuntu;

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

It also recognises pre-Turing silicon (see
L<Rex::GPU::Detect/legacy_driver_requirement>). Current NVIDIA drivers no
longer support it, and the open kernel module never did:

=over

=item * B<Kepler or older> (device ID below C<1340>, e.g. Tesla K80/K40): the
newest driver that supports it is the end-of-life 470 branch. C<install_driver>
B<dies> on every distro before anything on the host is changed. A host whose
driver was installed by hand (C<nvidia-smi -L> lists the GPU) passes the
already-installed check above instead.

=item * B<Maxwell, Pascal, Volta> (C<1340>-C<1DF6>, e.g. Tesla M60, P100, P40,
V100): the proprietary driver of the 580 branch. On Ubuntu that is
C<nvidia-driver-580-server>. If apt has no candidate for it, C<install_driver>
dies before installing and does not fall back to another branch. On
RHEL/Rocky/Alma 8 and 9 it enables module stream C<nvidia-driver:580-dkms>. On
RHEL 10 it installs C<python3-dnf-plugin-versionlock> and locks C<*nvidia*580*>
(C<dnf versionlock>). Both RHEL paths then install C<kmod-nvidia-latest-dkms>
+ C<nvidia-driver> + C<nvidia-driver-cuda>, and verify the kmod and a 580
C<nvidia-driver>. On openSUSE Leap 15 and 16 it installs
C<nvidia-driver-G06-kmp-meta> and verifies it with C<rpm -q>. Debian is
unchanged: its C<non-free> 535/550 driver supports these GPUs.

=back

Every other GPU keeps the previous selection (Ubuntu C<-server>, Debian
C<non-free> C<nvidia-driver>, RHEL C<open-dkms>, openSUSE open C<G06>/C<G07>).
Omit the option (or pass C<undef>) to keep the previous, GPU-agnostic package
selection.

=back

  install_driver();              # install only, load module without reboot
  install_driver(reboot => 1);   # install, reboot, verify
  install_driver(gpu => $gpus->{nvidia}[0]);   # thread GPU identity through

=cut

sub install_driver {
  my (%opts) = @_;

  # Every supported OS runs through its Setup class (epic karr #25, T2/T3): the
  # already-installed short-circuit, the Kepler rejection, package selection,
  # install, verification and the nouveau blacklist are its steps.
  my $setup_class = Rex::GPU::NVIDIA->setup_class_for_os;
  unless ($setup_class) {
    # No class for this OS. Same order as before the move: a working driver
    # still short-circuits and a Kepler still gets its own message (both via
    # the base class, read-only), then the OS is refused.
    my $setup = Rex::GPU::NVIDIA::Setup->new(gpu => $opts{gpu});
    return if $setup->already_installed;
    $setup->plan;
    die "Unsupported OS for NVIDIA driver installation: ".$setup->os."\n";
  }
  return unless $setup_class->new(gpu => $opts{gpu})->install;

  if ($opts{reboot}) {
    _reboot_and_wait();
  }
  else {
    run "modprobe nvidia", auto_die => 0;
  }

  verify_nvidia();

  Rex::Logger::info("NVIDIA driver installation complete");
}

=method setup_class_for_os

  my $class = Rex::GPU::NVIDIA->setup_class_for_os;

B<Experimental.> The L<Rex::GPU::NVIDIA::Setup> class L</install_driver> uses
on this host: L<Rex::GPU::NVIDIA::Setup::Ubuntu> on Ubuntu,
L<Rex::GPU::NVIDIA::Setup::Debian> on every other Debian-family host,
L<Rex::GPU::NVIDIA::Setup::RHEL> on the RHEL family,
L<Rex::GPU::NVIDIA::Setup::SUSE> on openSUSE, and C<undef> elsewhere
(L</install_driver> then dies). There is no option yet to choose a class of
your own.

=cut

# Ubuntu is recognised by its OS name exactly as the old $os eq 'Ubuntu'
# branch of install_driver did; every other is_debian host (Debian,
# derivatives) gets the Debian class. is_debian, is_redhat, is_suse are asked
# in the order the old install_driver branches asked them (epic karr #25;
# user selection is T5).
sub setup_class_for_os {
  my ( $class ) = @_;
  if (is_debian()) {
    return operating_system() eq 'Ubuntu'
      ? 'Rex::GPU::NVIDIA::Setup::Ubuntu'
      : 'Rex::GPU::NVIDIA::Setup::Debian';
  }
  return 'Rex::GPU::NVIDIA::Setup::RHEL' if is_redhat();
  return 'Rex::GPU::NVIDIA::Setup::SUSE' if is_suse();
  return;
}

# The helpers below moved into the Setup classes (karr #31, #32). The old
# private names stay as thin wrappers: t/ calls them.

sub _nvidia_driver_present {
  Rex::GPU::NVIDIA::Setup->_driver_present(@_);
}

sub _legacy_driver_requirement {
  Rex::GPU::NVIDIA::Setup->_legacy_requirement(@_);
}

sub _reject_unsupported_legacy_gpu {
  Rex::GPU::NVIDIA::Setup->_reject_unsupported_gpu(@_);
}

sub _apt_candidate_present {
  Rex::GPU::NVIDIA::Setup::Apt->_apt_candidate_present(@_);
}

sub _rpm_version_in_branch {
  Rex::GPU::NVIDIA::Setup::Rpm->_rpm_version_in_branch(@_);
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
#  Debian / Ubuntu — Rex::GPU::NVIDIA::Setup::Debian / ::Ubuntu
# ============================================================

# Thin wrappers over the pure helpers that moved into the Setup classes
# (karr #31); t/ calls them by these names.

sub _debian_nvidia_cuda_repo {
  Rex::GPU::NVIDIA::Setup::Debian->nvidia_cuda_repo(@_);
}

sub _ubuntu_needs_open_kernel_module {
  Rex::GPU::NVIDIA::Setup->_needs_open_kernel_module(@_);
}

sub _ubuntu_legacy_driver_package {
  Rex::GPU::NVIDIA::Setup::Ubuntu->legacy_driver_package(@_);
}

sub _sources_list_enable_nonfree {
  Rex::GPU::NVIDIA::Setup::Debian->_sources_list_enable_nonfree(@_);
}

sub _deb822_enable_nonfree {
  Rex::GPU::NVIDIA::Setup::Debian->_deb822_enable_nonfree(@_);
}

# ============================================================
#  RHEL / openSUSE — Rex::GPU::NVIDIA::Setup::RHEL / ::SUSE
# ============================================================

# Thin wrappers over the pure helpers that moved into the Setup classes
# (karr #32); t/ calls them by these names.

sub _rhel_legacy_driver_plan {
  Rex::GPU::NVIDIA::Setup::RHEL->legacy_driver_plan(@_);
}

sub _suse_nvidia_repo_params {
  Rex::GPU::NVIDIA::Setup::SUSE->nvidia_repo_params(@_);
}

# `uname -m` -> NVIDIA's CUDA repo arch token ("sbsa" for aarch64/arm64,
# else "x86_64"). NOT the libnvidia-container toolkit repo's token, which is
# "aarch64" for the same machine: do not reuse it for the toolkit path.
sub _cuda_repo_arch {
  Rex::GPU::NVIDIA::Setup->_cuda_repo_arch(@_);
}

sub _os_major_version {
  # Rex::Commands::Gather::operating_system_version() strips dots, so "10.1"
  # becomes "101": the raw operating_system_release() string is read instead.
  # An explicit $release may be passed so callers stay pure and unit-testable.
  my ($release) = @_;
  $release //= Rex::Commands::Gather::operating_system_release();
  return Rex::GPU::NVIDIA::Setup->_major_version($release);
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

On Debian, whichever of C<contrib>, C<non-free> and C<non-free-firmware>
is missing is added to each Debian archive entry, in both source formats:
active C<deb> lines of C</etc/apt/sources.list> (appended after the last
component; C<non-free-firmware> alone, as the Debian 12 installer writes it,
does not count as C<non-free>), and the C<Components:> field of stanzas in the
deb822 format (C</etc/apt/sources.list.d/*.sources>, e.g. C<debian.sources> on
Debian 13 and Debian cloud images). An entry is a Debian archive when it is
of type C<deb> (not C<deb-src>, not commented out or C<Enabled: no>), its
components include C<main>, every URI is a C<*.debian.org> host, Hetzner's
C<mirror.hetzner.com/debian/> mirror or the cloud images'
C<mirror+file:/etc/apt/mirrors/debian*.list>, and C<Signed-By> /
C<[signed-by=...]> (if set) names only C<debian-archive-*> keyrings. Third-party
sources and unknown mirrors are left untouched, and a file with nothing to
add is not rewritten; if no Debian archive entry is recognised in either
format, a warning is logged.

The install is done by L<Rex::GPU::NVIDIA::Setup::Debian>,
L<Rex::GPU::NVIDIA::Setup::Ubuntu>, L<Rex::GPU::NVIDIA::Setup::RHEL> and
L<Rex::GPU::NVIDIA::Setup::SUSE> (experimental classes, see
L<Rex::GPU::NVIDIA::Setup>); the steps and commands are the ones described
here.

The package choice also depends on the GPU generation, read from the PCI
device ID of the GPU passed as C<gpu> to L</install_driver>
(L<Rex::GPU/gpu_setup> passes it automatically). Without that option every
host gets the default selection below.

=over

=item * B<Turing, Ampere, Ada, Hopper> and unknown IDs: the default per-distro
selection.

=item * B<Blackwell> (B200/GB200/B300, GeForce RTX 50xx, RTX PRO Blackwell,
GB10), on any CPU architecture: it has no proprietary kernel module. Ubuntu
selects the C<-server-open> variant. Debian 12/13 installs the open-module set
from NVIDIA's CUDA repository instead of C<non-free>.

=item * B<Maxwell, Pascal, Volta> (e.g. V100, P100): only the proprietary
module of the 580 branch supports them. Ubuntu pins
C<nvidia-driver-580-server>, RHEL pins branch 580 (module stream or
versionlock) with C<kmod-nvidia-latest-dkms>, and openSUSE uses
C<nvidia-driver-G06-kmp-meta>.

=item * B<Kepler or older>: no supported branch is installed and
L</install_driver> dies before changing the host.

=back

See the C<gpu> option of L</install_driver> for the exact packages.

On Ubuntu, the newest available C<nvidia-driver-NNN-server> package is
auto-detected and installed by default.

On RHEL/Rocky/AlmaLinux/CentOS Stream, the NVIDIA CUDA repository is added
and the open-kernel DKMS variant is used by default. For RHEL 10+ the module
streams approach is not available; C<kmod-nvidia-open-dkms> is installed
directly. The CUDA repository URL is architecture-aware: aarch64 hosts use the
C<sbsa> tree (C<repos/rhelN/sbsa/>), x86_64 hosts the C<x86_64> tree.

On openSUSE Leap, a kmp-meta package is used (by default
C<nvidia-open-driver-G06-signed-kmp-meta> for Leap 15.x,
C<nvidia-open-driver-G07-signed-kmp-meta> for Leap 16.x) to ensure the kernel
module and userspace libraries are always at the same version. Stale OSS
non-free packages are removed before installation and locked afterwards to
prevent C<nvidia-smi> from reporting a C<Driver/library version mismatch>.

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
GPU-on-Rancher pipeline. The L<Rex::GPU::NVIDIA::Setup::SUSE> path exists but
is not exercised; do not treat a SUSE run as evidence.

Tested on Hetzner dedicated servers with NVIDIA RTX 4000 SFF Ada Generation.

=head1 SEE ALSO

L<Rex::GPU>, L<Rex::GPU::Detect>,
L<https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/>

=cut
