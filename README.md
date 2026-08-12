# Osprey

![language](https://img.shields.io/badge/language-C-informational.svg)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)
![status](https://img.shields.io/badge/status-v0.1%20skeleton-orange.svg)
![twin](https://img.shields.io/badge/twin%20of-Kestrel-blue.svg)

> ### Kestrel reads what's already inside one AD domain. Osprey reads what's reachable across a subnet's DCOM.

DCOM is contract-based trust without verification, projected onto the network. Every host hands out the right to *activate and call* code along a chain -

```
network principal → endpoint mapper → OXID / binding → activation ACL
                  → RunAs identity → binary → interface / method surface
```

- and at every seam that trust is granted by **registry configuration**, with no cryptographic or behavioural check. Osprey walks that chain across a whole subnet and finds the paths through it. It never exploits them.

Same DNA as Kestrel: pure C, Windows SDK only, a strictly read-only static core, no evasion, on-prem. Where Kestrel is one domain deep, Osprey is one subnet wide.

---

## Status - v0.1 (skeleton)

Honest about what exists. **Working today:** the Tier-0 sweep harness - CIDR expansion, a lock-free worker pool, per-host liveness against the RPC endpoint mapper (TCP/135). Everything below the sweep is **designed and on the roadmap, not yet implemented.**

The sweep is the load-bearing part and it went in first on purpose: the concurrency model (I/O-bound worker pool, `InterlockedIncrement` work dispenser, per-target timeout) is written once and every later collector rides on it unchanged.

---

## The tiered model

Osprey never demands one privilege level. It **degrades across tiers** and tags every fact with where it came from, so a report always says whether something was seen on the wire, read from the registry, or merely declared by policy.

| Tier | Access needed | What it yields |
|------|---------------|----------------|
| **0 - wire** | none, remote | EPM enumeration · OXID / `ServerAlive2` - reachability, registered interfaces/bindings, host-leaked addresses |
| **1 - registry** | RemoteRegistry up (usually no admin) | activation ACLs · RunAs · topology · auth posture from HKLM |
| **2 - privileged** | `SeSecurityPrivilege` / local admin | raw hive · SACL / audit posture |
| **intended** | domain read (via Kestrel) | DCOM config as *declared* by GPO / SYSVOL |

**Provenance** on every node: `observed` (wire) · `authoritative` (registry) · `intended` (policy).

---

## Roadmap (module map)

| Module | Tier | What it does | State |
|--------|------|--------------|-------|
| `sweep.c` | 0 | CIDR expansion + lock-free liveness pool | **done - v0.1** |
| `epm.c` | 0 | endpoint-mapper enumeration (`ept_lookup`) - *has RPC surface* → *has DCOM interfaces* | planned |
| `oxid.c` | 0 | `IOXIDResolver` / `ServerAlive2` - host address leak | planned |
| `registry.c` | 1 | winreg-RPC transport | planned |
| `activation.c` | 1 | plan A - principal × server × {launch, access} + RunAs (*"ADeleg for DCOM"*) | planned |
| `topology.c` | 1 | plan B - CLSID → AppID → binary → signature → path (writable?) | planned |
| `posture.c` | 1 | plan D - `EnableDCOM`, `LegacyAuthenticationLevel`, 2021–2023 hardening keys | planned |
| `path.c` | - | fleet correlation graph: reachability → activation ACL → RunAs → binary trust → method surface @ auth-level; replicated-config & outliers | planned |
| `report.c` | - | HTML / JSON / YAML with provenance tags | planned |
| `probe.c` · `methods.c` | opt-in | plan E - activation up to typelib, **no method calls**, over a narrowed target | planned |

Persistence (rewritten CLSID config, HKLM divergence, `script:` paths) is **not** a module - it's a *view* over `activation` + `topology` nodes.

---

## Design invariants (promises, not preferences)

- **Read-only static core.** Tier 0/1 never activate anything; EPM, OXID, and registry are query-only.
- **Opt-in probe layer.** Any activation is a separate, explicit second step over a *narrowed* target - never a fan-out across the subnet - and it stops before invoking methods.
- **No evasion.** A subnet sweep is loud by nature; Osprey is honest about it - rate-limited and declared, never stealthy.
- **Tiered provenance.** Every fact carries its source tier. No silent mixing of *observed* and *intended*.
- **Pure C, Windows SDK only.** No .NET, no managed runtime, no third-party dependencies.

---

## Build

Visual Studio (v143+) / MSBuild, x64, Unicode:

```
git clone https://github.com/ssteelfactor-oss/Osprey.git
cd Osprey
msbuild Osprey.vcxproj /p:Configuration=Release /p:Platform=x64
```

Or straight from the command line (the relative include resolves from each source file, so no `/I` is needed):

```
cl /W4 code\main.c code\sweep.c
```

`ws2_32` and `advapi32` are linked via `#pragma comment(lib, ...)` in `osprey.h`.

---

## Run (v0.1)

```
Osprey.exe 10.0.0.0/24           # sweep a /24 - default 64 workers, 1000 ms timeout
Osprey.exe 10.0.0.0/22 128 800   # wider range, more workers, tighter timeout
```

Output is the hosts with a reachable endpoint mapper, then a one-line summary.

> A reachable TCP/135 means the host exposes an **RPC** surface, not necessarily live **DCOM** interfaces. That distinction arrives with `epm.c`, which reads *which* interfaces are registered.

---

## License

Sibling to [Kestrel](https://github.com/ssteelfactor-oss/Kestrel), same author, same spirit - native, precise, low-noise. Licensing follows Kestrel; see `LICENSE`.
