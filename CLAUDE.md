# Rex::GPU

GPU detection and NVIDIA driver management for [Rex](https://www.rexify.org/). A single
`gpu_setup()` call takes a bare-metal host from bare PCI to GPU-ready for Kubernetes:
detect → NVIDIA driver → container toolkit → CDI specs → containerd runtime config. Works
with RKE2, K3s, standalone containerd, or drivers-only. Targets SFTP-less Hetzner dedicated
servers via `Rex::LibSSH`.

Full architecture, the per-distro driver matrix, the detection contract and the
Rex::Pkg-bypass invariant live in skill `rex-gpu-core` (force-loaded for the agents).
README.md is the user-facing overview; POD in `lib/` is the API reference.

## Delegation

Delegate behavior-relevant code to the right agent instead of touching it yourself —
principle and lane are in `.claude/rules/rex-gpu-rules.md`.

| Task | Agent |
|---|---|
| Implement / refactor / debug anything under `lib/` | `rex-gpu-worker` (default) |
| Pre-release audit | `rex-gpu-release-checker` |

The agents carry their skills via `briefing.skills` (see `.claude/agents/`); the main agent
delegates rather than loading them. Skill sources live under `.claude/skills/` —
`rex-gpu-core` is owned here, the rest are hardlinks (`manage-skills sync` after a clone).

## Build and test

```bash
prove -lr t/     # today only t/00-load.t — compile check, no hardware exercised
dzil build
dzil test
```

No detection, install, containerd or reboot path runs without a real GPU host; a green
`prove` is a compile check, not proof a behavior change works.
