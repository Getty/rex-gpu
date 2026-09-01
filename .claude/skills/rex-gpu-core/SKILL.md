---
name: rex-gpu-core
description: Load before editing Rex::GPU — the detect→driver→toolkit→CDI→containerd pipeline, PCI-class detection, the per-distro driver matrix, why every install bypasses Rex::Pkg, and the RKE2/K3s containerd include mechanism.
---

# Rex::GPU — core

A Rex distribution that makes an NVIDIA GPU on a bare-metal host usable by Kubernetes
workloads. `gpu_setup()` is the single entry point; everything else is one stage of one
pipeline. AMD is *detected* but never installed — `compute => 0` always, a warning, no
driver path. Do not add AMD install code without a ticket that says to.

Consumes `Rex::LibSSH` (`recommends`, not a pin) because the target hosts — Hetzner
dedicated servers — ship without an SFTP subsystem. Every file op in this distribution
therefore has to survive on exec channels; Rex idioms and the SFTP question live in skill
`rex`. Downstream, `Rex::Rancher` calls `gpu_setup` via its optional `gpu => 1`.

## The pipeline — order is load-bearing

`gpu_setup(%opts)` in `lib/Rex/GPU.pm`:

1. `_check_connection` — die early if the backend is neither LibSSH nor SFTP-capable.
2. `gpu_detect` → `Rex::GPU::Detect::detect`.
3. Only if a **CUDA-capable** NVIDIA GPU is present (`grep { $_->{compute} }`):
   `install_driver` → `install_container_toolkit` → `generate_cdi_specs` →
   `configure_containerd($runtime)` unless `containerd_config eq 'none'`.

The order is not cosmetic. CDI generation runs `nvidia-ctk cdi generate`, which
enumerates *physical* devices — so it must come after the toolkit provides `nvidia-ctk`
**and**, on a first deploy, after the reboot that unloads nouveau and binds the NVIDIA
module. Reorder these and CDI writes an empty spec on a cold host. `containerd_config`
default is `rke2`; values `rke2` | `k3s` | `containerd` | `none`.

## Detection — PCI class codes, not nvidia-smi

`Rex::GPU::Detect` parses `lspci -nn`, never a driver tool (detection must work on a host
with no driver yet). The compiled regexes at the top of the file are the contract:

- Display class `[0300]` (VGA) or `[0302]` (3D/datacenter). `0302` ⇒ compute, always.
- Vendor IDs: `10de` NVIDIA, `1002` AMD.
- **Virtual GPUs short-circuit the whole scan**: `1af4` virtio, `1b36` QEMU, `15ad`
  VMware, `80ee` VirtualBox → log and return empty arrays. A VM needs no host driver.

`_is_nvidia_compute` classifies by name when class is `0300`: RTX/TITAN/Quadro/Tesla and
GTX 10xx/16xx are compute; MX, GT/GTS/NVS, GTX 2xx–9xx are not; **unknown defaults to
`0`** (safe: no install) with a warning. Changing that default from 0 to 1 means an
unrecognised laptop chip triggers a datacenter driver install — keep it 0.

## The driver matrix — one dispatch, three families

`install_driver` branches on `is_debian` / `is_redhat` / `is_suse`, else dies. Each
family has a trap that is already solved in the code; do not "simplify" these away:

- **Debian** — enable `contrib non-free non-free-firmware` first; install `nvidia-driver`
  + `nvidia-smi` + the *running* kernel's headers only. Never the `linux-headers-$arch`
  metapackage — it pulls a new kernel whose grub/initramfs post-install returns non-zero.
- **Ubuntu** — auto-detect the newest `nvidia-driver-NNN-server` via `apt-cache search`,
  filtering out `-open`. **Do not add `nvidia-smi` to the package list**: on 24.04 it is a
  virtual package with no install candidate and the driver metapackage pulls it anyway.
- **RHEL/Rocky/Alma/CentOS** — EPEL + `crb`(≥9)/`powertools`(<9) + the CUDA repo. **v10+
  has no module streams**: install `kmod-nvidia-open-dkms` + `nvidia-driver` +
  `nvidia-driver-cuda` directly; <10 uses `dnf module enable nvidia-driver:open-dkms` +
  `nvidia-open`. Get the major version from `_rhel_major_version` — see the trap below.
- **openSUSE Leap** — `rpm -e` any stale `nvidia*`/`libnvidia*` first, add the GFX repo by
  **baseurl** (zypper can't parse yum `.repo` files), install the `signed-kmp-meta` package
  (`G06` for 15.x, `G07` for 16.x), then `zypper addlock libnvidia-ml libnvidia-cfg`. The
  meta package co-installs kmp + userspace at one version; the lock stops a later update
  re-splitting them into a `Driver/library version mismatch`.

After the branch: `_blacklist_nouveau` (write the blacklist, regenerate initramfs via
`update-initramfs`/`dracut`), then reboot-and-verify or `modprobe nvidia`.

## Never Rex::Pkg for the driver/toolkit — the load-bearing invariant

Driver and toolkit installs call `run "apt-get/dnf/zypper install -y …", auto_die => 0`
directly, then verify with `dpkg -l | grep '^ii'` / `rpm -q`. **Not `pkg`.**
`Rex::Pkg::{Apt,Dnf}` dies on any non-zero exit, and DKMS module builds, grub updates and
initramfs regeneration routinely exit non-zero on success. `pkg` is fine only for
inert helpers (`pciutils`, `curl`, `gnupg`, `epel-release`). Route a real driver package
through `pkg` and every install "fails" on a working host.

Two more resilience rules baked into every apt path, both for **fresh-boot** Hetzner
hosts where cloud-init/unattended-upgrades still hold the dpkg lock:
- `-o DPkg::Lock::Timeout=120` on every `apt-get`.
- `systemctl stop unattended-upgrades apt-daily* || true` before the first install.
- `apt-get update` runs `auto_die => 0` — it returns non-zero on snap/PPA repo warnings
  that are not real failures.

## Version-string trap — dots are stripped

`operating_system_version()` returns `101` for RHEL `10.1` (dots removed) — so the RHEL
path reads `operating_system_release()` and takes `/^(\d+)/` in `_rhel_major_version`.
The SUSE path *relies* on the stripping: `156 → 15.6` via `sprintf("%.1f", $version/10)`.
Know which function you are holding before you branch on a version.

## Kubernetes integration — CDI + the containerd include

- **CDI** (`generate_cdi_specs`): `nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml`.
  This is how the k8s device plugin enumerates GPUs *without a privileged container*.
- **RKE2 and K3s share one mechanism** (`_configure_containerd_rke2`): write
  `…/rke2/agent/etc/containerd/config.toml.tmpl` importing `/etc/containerd/conf.d/*.toml`,
  then drop `99-nvidia.toml` registering runtime `nvidia` as `io.containerd.runc.v2` with
  `BinaryName=/usr/bin/nvidia-container-runtime`. `k3s` deliberately falls through to the
  same code — do not fork it.
- **Standalone** (`containerd`): `nvidia-ctk runtime configure --runtime=containerd` +
  restart the service. `configure_containerd` returns early and silently if
  `nvidia-container-runtime` is not installed — a guard, not a bug.

## Reboot-and-wait

`_reboot_and_wait` schedules `shutdown -r now` 2s out (so `run` returns cleanly), sleeps
20s, then polls `disconnect`/`reconnect` on the live connection up to 60×5s, dying if the
host never returns. Reboot is required on first deploy only, to unload a previously-loaded
nouveau; without it the NVIDIA module can't bind. `verify_nvidia` (module loaded +
`nvidia-smi -L` shows a GPU + `nvidia-ctk` present) never dies — it warns and returns 0/1.

## Housekeeping

`$VERSION` is repeated in all three modules under `lib/` (`GPU.pm`, `Detect.pm`,
`NVIDIA.pm`) — bump them together. A change to what a Rexfile author sees (a new option, a
detection outcome, a package choice) wants a `Changes` `{{$NEXT}}` entry naming the effect
and its POD updated in the same edit. Perl house style and dist mechanics: skills
`getty-perl-core`, `getty-perl-release-author-getty`, `perl-release-dist-ini`.
