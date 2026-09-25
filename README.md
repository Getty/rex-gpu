# Rex::GPU

GPU detection and driver management for [Rex](https://www.rexify.org/). Automates the complete software stack to make NVIDIA GPUs available to Kubernetes workloads.

## What it does

The full pipeline, driven by a single `gpu_setup()` call:

1. **GPU detection** — scans PCI devices via `lspci -nn`, identifies NVIDIA and AMD hardware, filters out virtual GPUs (virtio, QEMU, VMware). Only CUDA-capable NVIDIA GPUs trigger installation, decided by the GPU generation read from the PCI device ID, not by name or PCI class (see [Supported GPUs](#supported-gpus)).
2. **NVIDIA driver installation** — distribution-appropriate packages via DKMS for kernel-version independence, one driver chosen to fit every detected GPU. Blacklists `nouveau`, regenerates initramfs. Skipped if a working driver (`nvidia-smi -L` lists a GPU and `libcuda.so.1` is in the linker cache) is already there.
3. **NVIDIA Container Toolkit** — installs from the official NVIDIA repository for all supported distributions; an already installed toolkit is left as it is, not upgraded.
4. **CDI spec generation** — writes `/etc/cdi/nvidia.yaml` so the Kubernetes device plugin enumerates GPU resources without privileged containers.
5. **Containerd runtime configuration** — injects the NVIDIA runtime into the containerd config for the target Kubernetes distribution (`rke2`, `k3s`, or standalone `containerd`).

## Synopsis

```perl
use Rex::GPU;

# Detect GPUs — returns a hashref
my $gpus = gpu_detect();
if (@{ $gpus->{nvidia} }) {
    say "NVIDIA GPU: ", $gpus->{nvidia}[0]{name};
}

# Full setup for an RKE2 cluster
gpu_setup(
    containerd_config => 'rke2',  # 'rke2', 'k3s', 'containerd', or 'none'
    reboot            => 1,       # reboot after driver install (first deploy)
);

# K3s cluster
gpu_setup(containerd_config => 'k3s');

# Just drivers + toolkit, skip containerd config
gpu_setup(containerd_config => 'none');
```

## Supported platforms

Tested on Hetzner dedicated servers running:

- Debian 11 (bullseye), 12 (bookworm), 13 (trixie)
- Ubuntu 22.04 (jammy), 24.04 (noble)
- RHEL / Rocky Linux / AlmaLinux 8, 9, 10 — CentOS Stream 9, 10

The verified target set is the RKE2 Linux family above. **openSUSE Leap / SLES is unverified and unsupported** — SUSE is not a deploy target for the GPU-on-Rancher pipeline.

GPUs tested include the **NVIDIA RTX 4000 SFF Ada Generation** (PCI class `0302`, datacenter compute profile).

Every `apt-get` waits up to 120 seconds for the dpkg lock and every `zypper` up to 120 seconds for the zypp lock, so a fresh boot where cloud-init or unattended-upgrades still holds it does not fail the install (`apt_lock_timeout` / `zypper_lock_timeout` in a setup class of your own change it).

On Debian, `contrib non-free non-free-firmware` is added only to entries recognised as Debian's own archive: signed with Debian's archive keyring, or without `signed-by` on a `*.debian.org` host, Hetzner's `mirror.hetzner.com`/`.de` Debian mirror or the cloud images' `mirror+file:` list. A mirror of your own is left alone, so `nvidia-driver` has no candidate there; teach it by overriding `is_debian_archive_uri` (see `eg/custom-setup/lib/My/GPU/DebianMirror.pm`).

### Supported GPUs

Decided by generation (PCI device ID), whatever the marketing name or PCI class:

| Generation | Compute | Driver |
|---|---|---|
| Turing, Ampere, Ada, Hopper | yes | the distro's default (Ubuntu newest `-server`, Debian `non-free`, RHEL CUDA-repo open DKMS, openSUSE open `G06`/`G07`) |
| Blackwell, Blackwell Ultra (B200/GB200/B300, RTX 50xx, RTX PRO Blackwell, GB10) | yes | open kernel module only: Ubuntu `-server-open`, Debian 12/13 NVIDIA's CUDA repository (other Debian releases die before any driver package is installed) |
| Maxwell, Pascal, Volta (V100, P100, GTX 9xx/10xx, GT 1030, MX1xx–MX3xx) | yes | proprietary 580 branch, their last: Ubuntu `nvidia-driver-580-server`, RHEL pinned 580 kmod, openSUSE `G06` proprietary, Debian `non-free` |
| Kepler and older (K80/K40/K20, GT 710, GTX 7xx) | no | none — last branch 470 is no longer packaged; skipped with a warning at any PCI class, a newer GPU on the same host still gets its driver |

GPUs that cannot share one driver (a V100 next to a B200) make `gpu_setup` die before any driver package is installed, unless a working driver is already installed. Such a die (like the vGPU and HGX ones below) is known without a refreshed package index: by then no package source has been added and nothing installed, except `pciutils` when `lspci` was missing for detection. An unrecognised NVIDIA model beyond the table defaults to no install, with a warning. AMD GPUs are detected and logged; no AMD driver is installed.

### NVIDIA vGPU guests

On a VM with an NVIDIA vGPU (Azure NVadsA10 v5, AWS G6f, a vGPU on VMware or KVM) `lspci -nn` shows the physical GPU's device ID; `gpu_detect` tells the vGPU apart by its PCI subsystem ID and reports `vgpu => 1` and `vgpu_type` (e.g. `NVIDIA A10-2Q`). Such a guest needs NVIDIA's licensed vGPU guest (GRID) driver, which Rex::GPU does not install. If that driver already works, `gpu_setup` goes on as on any host with a working driver: container toolkit, CDI specs, containerd. If not, it dies before any driver package is installed, naming the vGPU type — also when a non-vGPU GPU sits next to it. Not tested on a vGPU guest.

### NVSwitch / HGX (Fabric Manager)

On an HGX baseboard whose NVSwitches are PCI devices on the host (HGX-2, HGX A100, HGX H100/H200), `gpu_detect` lists them under `nvswitch`, and `gpu_setup` installs NVIDIA Fabric Manager together with the driver, at exactly the driver's version, and enables `nvidia-fabricmanager.service`. Without it CUDA does not initialise on those hosts. Debian's `non-free` has no Fabric Manager, so Debian 12/13 takes NVIDIA's CUDA repository instead; Debian 11 and openSUSE die before any driver package is installed. On a host whose driver is already installed, Fabric Manager is added only if the host's own package sources offer it at exactly the running driver's version (asked after an `apt-get update` on Debian/Ubuntu); otherwise `gpu_setup` warns and installs nothing. No package source is added and the driver is not touched either way. **HGX B200/B300:** their NVSwitches are not visible on the host PCI bus, so `gpu_setup` recognises them by the GPU device IDs (B200 `2901`/`2909`, B300 `3182`). It installs Fabric Manager with the driver as above, then the NVLink Subnet Manager `nvlsm`, `infiniband-diags` and `libibumad3`/`libibumad` unversioned (plus `linux-modules-extra` of the running kernel on Ubuntu), loads `ib_umad` persistently, warns on a kernel older than 5.17 (not on the RHEL family), and after Fabric Manager starts checks that `nvidia-smi -q` reports `Fabric State: Completed` on every GPU -- a loud warning if not, never a failure. With the driver already installed, the missing ones of these packages are installed from the host's own package sources (after an `apt-get update` on Debian/Ubuntu; no source is added, one not offered only warns) and `ib_umad` is loaded. `nvlsm` comes from NVIDIA's CUDA repository: on Debian 12/13 and RHEL/Rocky/Alma 9/10 the driver's own; on Ubuntu 22.04/24.04 (amd64) it is added for these hosts only, after the driver, with an apt pin that lets nothing but `nvlsm` come from it, so the driver stays Ubuntu's. Elsewhere (other Ubuntu releases, RHEL 8, openSUSE) `gpu_setup` dies before any driver package is installed. GB200/GB300 NVL72 compute trays run no Fabric Manager (it runs on the switch trays); they get a note that multi-node NVLink needs `nvidia-imex`, which Rex::GPU does not set up. None of this has been tested on HGX hardware.

### MIG (A100 / H100 / B200)

The CDI spec captures the MIG layout as it was when the spec was generated. Neither the static `/etc/cdi/nvidia.yaml` nor the `nvidia-cdi-refresh` unit regenerates it when MIG is reconfigured. After changing MIG mode or instances, regenerate the spec: run `systemctl restart nvidia-cdi-refresh.service`, or on hosts without that unit, `nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml`. The MIG strategy that Kubernetes exposes (`single` / `mixed`) is configured in the NVIDIA device plugin or GPU Operator, which writes its own CDI spec. MIG has not been tested on hardware with Rex::GPU.

## Your own driver setup (experimental)

The driver install is a Moo class per distro (`Rex::GPU::NVIDIA::Setup::Debian`, `::Ubuntu`, `::RHEL`, `::SUSE`). To change it — pin a driver package, add a local mirror, support another distro — subclass one and put it in your project's `lib/` next to the Rexfile (Rex puts that directory on `@INC`); Rex::GPU needs no patch:

```perl
# lib/My/GPU/Setup.pm
package My::GPU::Setup;
use Moo;
extends 'Rex::GPU::NVIDIA::Setup::Ubuntu';
sub sources { my ( $self ) = @_; return ( { name => 'pinned-580-open', kernel_module => 'open', branch => 580,
  packages => [ 'nvidia-driver-580-server-open' ], verify => [ 'nvidia-driver-580-server-open' ] }, $self->SUPER::sources ) }
1;
```

Choose it per call with `gpu_setup(setup => 'My::GPU::Setup')` (a class name or an object), or for the whole Rexfile with `set gpu_nvidia_setup => 'My::GPU::Setup'`, which also applies to Rex::Rancher's `gpu => 1`. Without either, Rex::GPU chooses the class by OS. The detected GPUs' requirements still apply: a source the GPUs cannot use is skipped. `gpu_setup(requirement => { kernel_module => 'open', min_branch => 580 })` narrows the choice further, but cannot override what the GPUs need. See `eg/custom-setup/` and the `WRITING YOUR OWN SETUP` section of `Rex::GPU::NVIDIA::Setup`.

On Ubuntu, the built-in `Rex::GPU::NVIDIA::Setup::UbuntuDrivers` (opt-in, same two ways to choose it) lets `ubuntu-drivers list --gpgpu` name the driver package instead of `apt-cache search`; it is still installed with `apt-get` and verified with `dpkg -l`, and dies before any driver install when `ubuntu-drivers` names nothing.

## Examples

- `eg/Rexfile` — `detect`, `setup` and Rex::Rancher node/server/agent tasks
- `eg/hetzner-gpu.pl` — full Hetzner deploy through Rex::Rancher
- `eg/custom-setup/` — a setup class of your own (`My::GPU::Setup`), and `My::GPU::DebianMirror` for a Debian mirror
- `eg/ubuntu-drivers/` — the Ubuntu package chosen by `ubuntu-drivers list --gpgpu` (`Rex::GPU::NVIDIA::Setup::UbuntuDrivers`); `install_driver` alone with a GPU found without `lspci`

## Requirements

This module requires [Rex::LibSSH](https://metacpan.org/pod/Rex::LibSSH) (or SFTP) on the connection backend. Hetzner servers don't enable SFTP by default:

```perl
use Rex::LibSSH;
set connection => 'LibSSH';
```

### Host-key verification (Rex::LibSSH ≥ 0.004)

Rex::LibSSH 0.004 and later verify the server's host key against `known_hosts` by default. A freshly provisioned host has no entry yet, so the **first** connect fails with `host key is not in known_hosts and strict_hostkeycheck is on`. Either scan the key in first — recommended, keeps verification:

```
ssh-keyscan <host> >> ~/.ssh/known_hosts
```

(`eg/Rexfile` and `eg/hetzner-gpu.pl` do this in a `before 'ALL'` hook), or disable the check Rexfile-wide for first-contact provisioning (a deliberate security tradeoff):

```perl
use Rex -feature => ['1.4', 'disable_strict_host_key_checking'];
```

## Installation

```
cpanm Rex::GPU
```

Or from this repository:

```
cpanm --installdeps .
dzil build
cpanm Rex-GPU-*.tar.gz
```

## See Also

- [Rex::LibSSH](https://metacpan.org/pod/Rex::LibSSH)
- [Rex::Rancher](https://metacpan.org/pod/Rex::Rancher)
- [Rex::GPU::Detect](https://metacpan.org/pod/Rex::GPU::Detect)
- [Rex::GPU::NVIDIA](https://metacpan.org/pod/Rex::GPU::NVIDIA)
- [Rex](https://metacpan.org/pod/Rex)

## Author

Torsten Raudssus `<getty@cpan.org>`

## License

This software is copyright (c) 2026 by Torsten Raudssus. This is free software; you can redistribute it and/or modify it under the same terms as the Perl 5 programming language system itself.
