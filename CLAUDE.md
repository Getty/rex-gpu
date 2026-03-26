# Rex::GPU

GPU detection and driver management for Rex. Distribution-agnostic — works with
any Kubernetes setup (RKE2, K3s, kubeadm, standalone containerd).

## Module Structure

```
Rex::GPU              — gpu_detect(), gpu_setup() orchestration
Rex::GPU::Detect      — PCI-based GPU hardware detection (NVIDIA, AMD)
Rex::GPU::NVIDIA      — NVIDIA driver, container toolkit, containerd config
```

## Usage

```perl
use Rex::GPU;

# Just detect
my $gpus = gpu_detect();

# Full setup: drivers + toolkit + containerd config
gpu_setup(containerd_config => 'rke2');  # or 'k3s', 'containerd', 'none'
```

## Used By

- `Rex::Rancher` — optional GPU support via `gpu => 1`
- `kubernetes-ocp` — OCP cluster deployment

## Testing

```bash
prove -l t/
```

## Build

Uses `[@Author::GETTY]` Dist::Zilla plugin bundle.
