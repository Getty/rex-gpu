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

=head1 FUNCTIONS

=cut

=method install_driver

Install NVIDIA GPU drivers appropriate for the detected OS.

Handles:

=over

=item Kernel headers installation

=item Nouveau blacklisting

=item NVIDIA driver package installation (DKMS)

=item Kernel module loading

=back

Supported OS: Debian, Ubuntu, Rocky, CentOS, RedHat, AlmaLinux, Fedora.

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
  else {
    die "Unsupported OS for NVIDIA driver installation: $os\n";
  }

  # Blacklist nouveau
  _blacklist_nouveau();

  # Load nvidia kernel module
  run "modprobe nvidia", auto_die => 0;

  verify_nvidia();

  Rex::Logger::info("NVIDIA driver installation complete");
}

=method install_container_toolkit

Install the NVIDIA Container Toolkit from the official nvidia.github.io
repository. This is a separate repository from the driver packages.

Installs: C<nvidia-container-toolkit> (includes nvidia-container-runtime,
libnvidia-container, nvidia-ctk).

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
  else {
    die "Unsupported OS for NVIDIA Container Toolkit: $os\n";
  }

  Rex::Logger::info("NVIDIA Container Toolkit installed");
}

=method configure_containerd($runtime)

Configure the containerd runtime for NVIDIA GPU access.

C<$runtime> can be:

=over

=item C<rke2> — RKE2's containerd (config.toml.tmpl + conf.d import)

=item C<k3s> — K3s containerd (same socket path as RKE2)

=item C<containerd> — Standalone containerd (uses nvidia-ctk)

=back

=cut

sub configure_containerd {
  my ($runtime) = @_;
  $runtime //= 'rke2';

  return unless can_run("nvidia-container-runtime");

  Rex::Logger::info("Configuring containerd for NVIDIA GPU (runtime: $runtime)");

  if ($runtime eq 'rke2') {
    _configure_containerd_rke2();
  }
  elsif ($runtime eq 'k3s') {
    _configure_containerd_rke2();  # K3s uses same paths as RKE2
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

Verify the NVIDIA installation: kernel module, nvidia-smi, libcuda,
container toolkit. Logs warnings for any missing components.

Returns 1 if all checks pass, 0 otherwise.

=cut

sub verify_nvidia {
  Rex::Logger::info("Verifying NVIDIA installation...");
  my $ok = 1;

  # Kernel module
  my $lsmod = run "lsmod | grep '^nvidia '", auto_die => 0;
  if ($? != 0 || !$lsmod) {
    Rex::Logger::info("nvidia kernel module not loaded (reboot may be needed)", "warn");
    my $dkms = run "dkms status 2>&1 | grep nvidia", auto_die => 0;
    Rex::Logger::info("DKMS: $dkms") if $dkms;
    $ok = 0;
  }
  else {
    Rex::Logger::info("  [ok] nvidia kernel module loaded");
  }

  # nvidia-smi
  my $smi = run "nvidia-smi -L 2>&1", auto_die => 0;
  chomp $smi if defined $smi;
  if (defined $smi && $smi =~ /GPU \d+:/) {
    Rex::Logger::info("  [ok] $smi");
  }
  else {
    Rex::Logger::info("nvidia-smi not working: " . ($smi // 'no output'), "warn");
    $ok = 0;
  }

  # libcuda
  my $libcuda = run "ldconfig -p | grep 'libcuda.so '", auto_die => 0;
  if ($? == 0 && $libcuda) {
    Rex::Logger::info("  [ok] libcuda available");
  }
  else {
    Rex::Logger::info("libcuda.so not found", "warn");
    $ok = 0;
  }

  # Container toolkit
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

#
# Debian/Ubuntu driver installation
#

sub _install_driver_debian {
  my ($os, $running_kernel) = @_;

  my @packages;
  if ($os eq 'Ubuntu') {
    @packages = (
      "linux-headers-$running_kernel",
      "linux-headers-generic",
      "nvidia-driver-535",
    );
  }
  else {
    # Debian
    @packages = (
      "linux-headers-$running_kernel",
      "linux-headers-amd64",
      "nvidia-driver",
      "nvidia-smi",
      "libcuda1",
    );
  }

  Rex::Logger::info("  Installing driver packages: " . join(", ", @packages));
  update_package_db;
  pkg \@packages, ensure => "present";
}

#
# RHEL/Rocky driver installation
#

sub _install_driver_redhat {
  my ($os, $running_kernel) = @_;

  my $version = operating_system_version();

  # Enable required repos
  Rex::Logger::info("  Enabling EPEL and CRB/PowerTools...");
  pkg ["epel-release"], ensure => "present";

  if ($version >= 9) {
    run "dnf config-manager --set-enabled crb 2>/dev/null || true", auto_die => 0;
  }
  else {
    run "dnf config-manager --set-enabled powertools 2>/dev/null || true", auto_die => 0;
  }

  # Add NVIDIA CUDA repo
  Rex::Logger::info("  Adding NVIDIA CUDA repository...");
  my $distro = _rhel_distro_string($os, $version);
  run "dnf config-manager --add-repo https://developer.download.nvidia.com/compute/cuda/repos/$distro/x86_64/cuda-$distro.repo 2>/dev/null",
    auto_die => 0;
  run "dnf clean expire-cache", auto_die => 0;

  # Install kernel headers and driver
  my @packages;
  if ($version >= 9) {
    @packages = ("kernel-devel-matched", "kernel-headers");
  }
  else {
    @packages = ("kernel-devel-$running_kernel", "kernel-headers");
  }

  # Enable DKMS module stream and install driver
  run "dnf module enable nvidia-driver:open-dkms -y 2>/dev/null || true", auto_die => 0;
  push @packages, "nvidia-open";

  Rex::Logger::info("  Installing driver packages: " . join(", ", @packages));
  update_package_db;
  pkg \@packages, ensure => "present";
}

sub _rhel_distro_string {
  my ($os, $version) = @_;

  my $major = int($version);
  if ($os =~ /Rocky|Alma|CentOS/) {
    return "rhel$major";
  }
  return "rhel$major";
}

#
# Nouveau blacklisting
#

sub _blacklist_nouveau {
  file "/etc/modprobe.d/blacklist-nouveau.conf",
    content => "blacklist nouveau\noptions nouveau modeset=0\n";

  if (is_debian()) {
    run "update-initramfs -u 2>/dev/null", auto_die => 0;
  }
  elsif (is_redhat()) {
    run "dracut --force 2>/dev/null", auto_die => 0;
  }
}

#
# Container toolkit installation
#

sub _install_toolkit_debian {
  pkg ["curl", "gnupg"], ensure => "present";

  # GPG key (modern signed-by approach)
  run "curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg 2>/dev/null",
    auto_die => 0;

  file "/etc/apt/sources.list.d/nvidia-container-toolkit.list",
    content => 'deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://nvidia.github.io/libnvidia-container/stable/deb/$(ARCH) /' . "\n";

  update_package_db;

  pkg ["nvidia-container-toolkit"], ensure => "present";
}

sub _install_toolkit_redhat {
  pkg ["curl"], ensure => "present";

  run "curl -s -L https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo | tee /etc/yum.repos.d/nvidia-container-toolkit.repo",
    auto_die => 0;

  pkg ["nvidia-container-toolkit"], ensure => "present";
}

#
# Containerd configuration
#

sub _configure_containerd_rke2 {
  # RKE2 auto-generates containerd config — use template with imports
  file "/var/lib/rancher/rke2/agent/etc/containerd", ensure => 'directory';
  file "/var/lib/rancher/rke2/agent/etc/containerd/config.toml.tmpl",
    content => "imports = [\"/etc/containerd/conf.d/*.toml\"]\nversion = 2\n";

  # Drop nvidia runtime config in conf.d
  _write_nvidia_containerd_config();
}

sub _configure_containerd_standalone {
  # Use nvidia-ctk to configure system containerd
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
