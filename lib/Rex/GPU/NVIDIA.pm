# ABSTRACT: NVIDIA GPU driver and container toolkit management

package Rex::GPU::NVIDIA;

use v5.14.4;
use warnings;

use Rex::Commands::File;
use Rex::Commands::Gather;
use Rex::Commands::Pkg;
use Rex::Commands::Run;
use Rex::Logger;

require Rex::Exporter;
use base qw(Rex::Exporter);

use vars qw(@EXPORT);

@EXPORT = qw(
  install_driver
  install_container_toolkit
  configure_containerd
  verify_nvidia
);

=method install_driver

Install NVIDIA GPU drivers appropriate for the detected OS.

Supported: Debian 11-13, Ubuntu 22.04/24.04, RHEL/Rocky/Alma 8-10,
CentOS Stream 9-10, openSUSE Leap 15.6/16.0.

=cut

sub install_driver {
  my $os = operating_system();
  my $running_kernel = run "uname -r";
  chomp $running_kernel;

  Rex::Logger::info("Installing NVIDIA drivers on $os (kernel $running_kernel)");

  if (is_debian()) {
    _install_driver_debian($os, $running_kernel);
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

  run "modprobe nvidia", auto_die => 0;

  verify_nvidia();

  Rex::Logger::info("NVIDIA driver installation complete");
}

=method install_container_toolkit

Install the NVIDIA Container Toolkit.

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

Configure the containerd runtime for NVIDIA GPU access.
C<$runtime>: C<rke2>, C<k3s>, or C<containerd>.

=cut

sub configure_containerd {
  my ($runtime) = @_;
  $runtime //= 'rke2';

  return unless can_run("nvidia-container-runtime");

  Rex::Logger::info("Configuring containerd for NVIDIA GPU (runtime: $runtime)");

  if ($runtime eq 'rke2' || $runtime eq 'k3s') {
    _configure_containerd_rke2();
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

Verify the NVIDIA installation. Returns 1 if all checks pass.

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
  my ($os, $running_kernel) = @_;

  my $arch = run "dpkg --print-architecture", auto_die => 0;
  chomp $arch;

  # Ensure non-free repos are enabled (Debian only, Ubuntu has restricted by default)
  if ($os ne 'Ubuntu') {
    _enable_debian_nonfree();
  }

  my @packages = ("linux-headers-$running_kernel");

  if ($os eq 'Ubuntu') {
    push @packages, "linux-headers-generic";
    # Ubuntu: use server variant for K8s, auto-detect latest
    my $latest = run "apt-cache search '^nvidia-driver-[0-9].*-server\$' 2>/dev/null | sort -t- -k3 -n | tail -1 | awk '{print \$1}'",
      auto_die => 0;
    chomp $latest if $latest;
    push @packages, ($latest || "nvidia-driver-570-server");
  }
  else {
    # Debian: arch-specific headers meta + driver meta
    push @packages, "linux-headers-$arch";
    push @packages, "nvidia-driver";
  }

  Rex::Logger::info("  Installing: " . join(", ", @packages));
  update_package_db;
  pkg \@packages, ensure => "present";
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

  my $major = _rhel_major_version();

  # Enable required repos
  Rex::Logger::info("  Enabling EPEL and extra repos...");
  pkg ["epel-release"], ensure => "present";

  if ($major >= 9) {
    run "dnf config-manager --set-enabled crb 2>/dev/null || true", auto_die => 0;
  }
  else {
    run "dnf config-manager --set-enabled powertools 2>/dev/null || true", auto_die => 0;
  }

  # Add NVIDIA CUDA repo
  my $distro = "rhel$major";
  Rex::Logger::info("  Adding NVIDIA CUDA repo ($distro)...");
  run "dnf config-manager --add-repo https://developer.download.nvidia.com/compute/cuda/repos/$distro/x86_64/cuda-$distro.repo 2>/dev/null",
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

  # Driver packages — different for v10 (no module streams)
  if ($major >= 10) {
    push @packages, "kmod-nvidia-open", "nvidia-driver", "nvidia-driver-cuda";
  }
  else {
    run "dnf module enable nvidia-driver:open-dkms -y 2>/dev/null || true", auto_die => 0;
    push @packages, "nvidia-open";
  }

  Rex::Logger::info("  Installing: " . join(", ", @packages));
  update_package_db;
  pkg \@packages, ensure => "present";
}

sub _rhel_major_version {
  my $version = operating_system_version();
  return int($version);
}

# ============================================================
#  openSUSE Leap
# ============================================================

sub _install_driver_suse {
  my ($os, $running_kernel) = @_;

  my $version = operating_system_version();
  my $major = int($version);

  # Add NVIDIA repos (use direct baseurls — zypper cannot parse yum .repo files)
  if ($major >= 16) {
    Rex::Logger::info("  Adding NVIDIA repos (suse16)...");
    run "zypper rr nvidia-gfx cuda 2>/dev/null || true", auto_die => 0;
    run "zypper addrepo --refresh https://download.nvidia.com/opensuse/leap/16.0/ nvidia-gfx 2>/dev/null",
      auto_die => 0;
    run "zypper addrepo --refresh https://developer.download.nvidia.com/compute/cuda/repos/suse16/x86_64 cuda 2>/dev/null",
      auto_die => 0;
  }
  else {
    my $leap_version = sprintf("%.1f", $version / 10);  # 156 -> 15.6
    Rex::Logger::info("  Adding NVIDIA repos (opensuse15, Leap $leap_version)...");
    run "zypper rr nvidia-gfx cuda 2>/dev/null || true", auto_die => 0;
    run "zypper addrepo --refresh https://download.nvidia.com/opensuse/leap/$leap_version/ nvidia-gfx 2>/dev/null",
      auto_die => 0;
    run "zypper addrepo --refresh https://developer.download.nvidia.com/compute/cuda/repos/opensuse15/x86_64 cuda 2>/dev/null",
      auto_die => 0;
  }
  run "zypper --gpg-auto-import-keys refresh 2>/dev/null", auto_die => 0;

  # Kernel devel
  my $kernel_version = $running_kernel;
  $kernel_version =~ s/-default$//;
  my @packages = ("kernel-default-devel=$kernel_version", "kernel-syms");

  # Driver packages — G07 for 16.x, G06 for 15.x
  if ($major >= 16) {
    push @packages, "nvidia-open-driver-G07-signed-kmp-default",
                    "nvidia-video-G07", "nvidia-compute-utils-G07";
  }
  else {
    push @packages, "nvidia-open-driver-G06-signed-kmp-default",
                    "nvidia-video-G06", "nvidia-compute-utils-G06";
  }

  Rex::Logger::info("  Installing: " . join(", ", @packages));
  run "zypper install -y " . join(" ", @packages), auto_die => 0;
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

  update_package_db;
  pkg ["nvidia-container-toolkit"], ensure => "present";
}

sub _install_toolkit_redhat {
  run "curl -s -L https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo | tee /etc/yum.repos.d/nvidia-container-toolkit.repo",
    auto_die => 0;

  pkg ["nvidia-container-toolkit"], ensure => "present";
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

sub _configure_containerd_rke2 {
  file "/var/lib/rancher/rke2/agent/etc/containerd", ensure => 'directory';
  file "/var/lib/rancher/rke2/agent/etc/containerd/config.toml.tmpl",
    content => "imports = [\"/etc/containerd/conf.d/*.toml\"]\nversion = 2\n";

  _write_nvidia_containerd_config();
}

sub _configure_containerd_standalone {
  run "nvidia-ctk runtime configure --runtime=containerd 2>&1", auto_die => 0;
  run "systemctl restart containerd 2>/dev/null", auto_die => 0;
}

sub _write_nvidia_containerd_config {
  file "/etc/containerd/conf.d", ensure => 'directory';
  file "/etc/containerd/conf.d/99-nvidia.toml", content => <<'TOML';
version = 2

[plugins]
  [plugins."io.containerd.grpc.v1.cri"]
    [plugins."io.containerd.grpc.v1.cri".containerd]
      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]
        [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.nvidia]
          privileged_without_host_devices = false
          runtime_engine = ""
          runtime_root = ""
          runtime_type = "io.containerd.runc.v2"
          [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.nvidia.options]
            BinaryName = "/usr/bin/nvidia-container-runtime"
TOML
}

1;

=head1 SEE ALSO

L<Rex::GPU>, L<Rex::GPU::Detect>

=cut
