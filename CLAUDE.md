# Rex::Rancher

Rancher Kubernetes (RKE2/K3s) deployment automation for Rex, with GPU support.

## Module Structure

```
Rex::Rancher               — Main module, rancher_deploy_server/agent one-stop functions
Rex::Rancher::Node          — Node preparation (hostname, NTP, sysctl, swap, kernel modules)
Rex::Rancher::Server        — Control plane installation (RKE2 + K3s)
Rex::Rancher::Agent         — Worker node join (RKE2 + K3s)
Rex::Rancher::Cilium        — Cilium CNI installation and upgrades
Rex::GPU                    — GPU detection + full setup orchestration
Rex::GPU::Detect            — PCI-based GPU hardware detection
Rex::GPU::NVIDIA            — NVIDIA driver, container toolkit, containerd config
```

## Usage

All modules support `distribution => 'rke2'` (default) or `distribution => 'k3s'`.

```perl
use Rex -feature => ['1.4'];
use Rex::Rancher;

task "deploy_cp", sub {
  rancher_deploy_server(
    distribution => 'rke2',
    hostname     => 'cp-01',
    domain       => 'k8s.example.com',
    token        => 'my-token',
    tls_san      => 'k8s.example.com',
  );
};
```

## Used By

`kubernetes-ocp` — the OCP Rexfile can be simplified to use these modules instead of inline logic.

## Testing

```bash
prove -l t/          # Unit tests
```

## Build

Uses `[@Author::GETTY]` Dist::Zilla plugin bundle.
Distribution name: `Rex-Rancher`.
