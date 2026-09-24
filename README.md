# Rex::GPU

GPU detection and driver management for [Rex](https://www.rexify.org/). Automates the complete software stack to make NVIDIA GPUs available to Kubernetes workloads.

## What it does

The full pipeline, driven by a single `gpu_setup()` call:

1. **GPU detection** — scans PCI devices via `lspci -nn`, identifies NVIDIA and AMD hardware, filters out virtual GPUs (virtio, QEMU, VMware). Only CUDA-capable NVIDIA GPUs trigger installation: every datacenter GPU (PCI class `0302`) and, by the generation read from the PCI device ID, every Maxwell or newer GPU — GeForce MX, GT 1030 and GTX 9xx included. Kepler and older GPUs (last driver branch 470, no longer packaged) are skipped with a warning.
2. **NVIDIA driver installation** — distribution-appropriate packages via DKMS for kernel-version independence. Blacklists `nouveau`, regenerates initramfs.
3. **NVIDIA Container Toolkit** — installs from the official NVIDIA repository for all supported distributions.
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

### NVSwitch / HGX (Fabric Manager)

On an HGX baseboard whose NVSwitches are PCI devices on the host (HGX-2, HGX A100, HGX H100/H200), `gpu_detect` lists them under `nvswitch`, and `gpu_setup` installs NVIDIA Fabric Manager together with the driver, at exactly the driver's version, and enables `nvidia-fabricmanager.service`. Without it CUDA does not initialise on those hosts. Debian 11 and openSUSE have no Fabric Manager source and die before the host is changed. On a host whose driver is already installed, Fabric Manager is added only if the host's own package sources offer it at exactly the running driver's version; otherwise `gpu_setup` warns and changes nothing (no package source is added, the driver is not touched). **HGX B200/B300 are not covered:** their NVSwitches are not visible on the host PCI bus, and they also need NVIDIA's NVLink Subnet Manager (`nvlsm`), so install Fabric Manager there yourself. GB200/GB300 NVL72 compute trays run no Fabric Manager; it runs on the switch trays. None of this has been tested on HGX hardware.

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

or disable the check Rexfile-wide, as the bundled `eg/` examples do for first-contact provisioning (a deliberate security tradeoff):

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
