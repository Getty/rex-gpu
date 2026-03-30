# Rex::GPU

GPU detection and driver management for [Rex](https://www.rexify.org/). Automates the complete software stack to make NVIDIA GPUs available to Kubernetes workloads.

## What it does

The full pipeline, driven by a single `gpu_setup()` call:

1. **GPU detection** — scans PCI devices via `lspci -nn`, identifies NVIDIA and AMD hardware, filters out virtual GPUs (virtio, QEMU, VMware). Only CUDA-capable NVIDIA GPUs (PCI class `0302`) trigger installation.
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
- openSUSE Leap 15.6, 16.0

GPUs tested include the **NVIDIA RTX 4000 SFF Ada Generation** (PCI class `0302`, datacenter compute profile).

## Requirements

This module requires [Rex::LibSSH](https://metacpan.org/pod/Rex::LibSSH) (or SFTP) on the connection backend. Hetzner servers don't enable SFTP by default:

```perl
use Rex::LibSSH;
set connection => 'LibSSH';
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
