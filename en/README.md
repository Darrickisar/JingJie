# JingJie (净界)

JingJie is a low-power hosts filtering module for KernelSU, KernelSU Next and APatch, with
hosts filtering, optional DoH, rule-source management and version rollback.

![version](https://img.shields.io/badge/version-V1.0-informational)
![versionCode](https://img.shields.io/badge/versionCode-670-lightgrey)
![managers](https://img.shields.io/badge/KernelSU%20%C2%B7%20KernelSU%20Next%20%C2%B7%20APatch-supported-brightgreen)

> **Download only from the official links, to avoid tampered scripts.**
> This tool is intended solely for filtering illegal harassment, malicious code and similar
> abusive content. Please use it lawfully and do not add legitimate commercial advertising to
> the block scope.

[中文说明](../README.md)

## What it is

JingJie keeps hosts filtering as the **only thing enabled by default**. Encrypted DNS, app
network policy, blocking history and verbose logging all start switched off. When protection,
auto-refresh, blocking history and DoH are all off, the module does **no extra work**: it
downloads no rule sources and starts no optional background workers.

The interface is a redesigned app-style console with five tabs (Home / Rules / Apps / Logs /
Settings). It runs inside the manager's built-in WebUI — there is no separate Android app.

## Features

| | |
| --- | --- |
| **Rule sources** | Two removable, restorable built-in sources (AWAvenue Ads Rule, 10007) plus up to 16 custom HTTPS sources; collapsible groups, per-source refresh, source health |
| **Lists** | Manual allow/block lists (allowlist wins), exact domain overrides, optional allowlist subscription |
| **hosts** | `Block all ads` / `Keep reward ads` modes, pause and resume protection, cache fallback on a failed refresh, rollback by generation |
| **Auto update** | Off by default; 6 / 12 / 24 hour intervals |
| **Encrypted DNS** | Off by default. Bring your own DoH URL, applied device-wide or to selected apps; never writes Android Private DNS |
| **App policy** | Off by default. Block selected apps from the network, or allow only the addresses resolved by the latest rule generation; starts no VPN, proxy or resident network process |
| **Blocking history** | Off by default. Records only rejected TCP connection attempts; filter by app / domain / port / time |
| **Diagnostics** | Manually loaded rule log, three log levels, one-shot environment check — no background polling |
| **Appearance** | Classic / Liquid surfaces × light / dark / follow system × three glass levels, freely combined |

## Install

1. Download [`JingJie-V1.0.zip`](https://github.com/Darrickisar/JingJie/releases/download/v1.0/JingJie-V1.0.zip)
   from [Releases](https://github.com/Darrickisar/JingJie/releases).
2. In KernelSU, KernelSU Next or APatch, use **“Install from storage”** and pick that ZIP.
3. Reboot when the manager asks you to.
4. Open the console from the module card's **“Open”** action. On first entry it shows the usage
   notice; only after you confirm does the module refresh the enabled sources.

Installation performs no network access. The first network request happens after you confirm
the notice.

> **Do not flash this in a third-party Recovery.** The package is designed only for the local
> ZIP install entry of the supported managers; Recovery flashing is unverified.

In-app updates use the `updateJson` field of `module.prop`
([`update.json`](https://github.com/Darrickisar/JingJie/blob/main/update.json)), which points at
the `main` branch of the repository.

## What is not verified yet

No rooted Android device was attached in the release environment, so the following **still need
real-device verification** and are not marked as passing:

- Real install, reboot, open entry and uninstall flows on all three managers
- Persistence across reboot, and IPv4 / IPv6 dual-stack behaviour
- Coexistence with a VPN, and the real scope of the selected UIDs

What has been executed is the local static, WebUI and BusyBox ash test suites; they do not
substitute for real-device verification.

This project makes no promise about unverified compatibility, block rates, power draw or
performance gains. “Low power” describes the design stance of keeping optional background
capabilities off by default.

## License

GPL-3.0-only. See [LICENSE](../LICENSE) and [NOTICES](../NOTICES).

The `jingjie-doh-proxy` companion statically links Go modules including AdGuard `dnsproxy`
(Apache-2.0) and `miekg/dns` (BSD-3-Clause), pinned by `go.mod` / `go.sum`. That executable is
**not bundled in the module ZIP**: it is fetched from the v1.0 release the first time you enable
or test DoH, and checked against the size, SHA-256 and ELF machine pinned in
`assets/doh-companions.tsv`. Devices that never enable DoH never download it.

## Credits

- [AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)
- [10007](https://github.com/lingeringsound/10007)
- KernelSU, KernelSU Next, APatch and their module WebUI capability

---

Author: 相貌平平韩老魔 · Repository: <https://github.com/Darrickisar/JingJie>
