# Rex::GPU

GPU detection and driver management for Rex.

## What This Is

A Rex module that provides reusable functions for:
1. GPU hardware detection via PCI class codes (NVIDIA, AMD)
2. NVIDIA driver installation (Debian/Ubuntu + RHEL/Rocky)
3. NVIDIA Container Toolkit installation
4. Containerd runtime configuration for Kubernetes (RKE2, K3s, standalone)

## Module Structure

- `Rex::GPU` — Main module, exports `gpu_detect()` and `gpu_setup()`
- `Rex::GPU::Detect` — PCI-based GPU detection, vendor/model classification
- `Rex::GPU::NVIDIA` — Driver install, container toolkit, containerd config, verification

## Usage in OCP

This module is used by `kubernetes-ocp` to prepare GPU nodes. The OCP Rexfile
calls `gpu_setup(containerd_config => 'rke2')` instead of inline GPU logic.

## Testing

```bash
prove -l t/          # Unit tests (no remote host needed)
```

## Build

Uses `[@Author::GETTY]` Dist::Zilla plugin bundle.
