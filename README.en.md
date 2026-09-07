# dlink-dir825-macfilter

Block and unblock devices on a **D-Link DIR-825ACG1** home router from PowerShell — one command, or a checkbox in a window — without opening the web interface. A second, independent mode keeps a Wi-Fi whitelist: only the listed devices may join the wireless network.

The scripts talk to the undocumented JSON-RPC API of the "anweb" firmware. Two MAC filters are involved: the firewall one leaves a device connected but cuts its internet, on Wi-Fi and cable alike; the Wi-Fi one decides who may associate with the access point at all.

> **This page describes release v1.0.0.** It is rewritten per release, not per commit, so between releases it lags behind the Russian documentation on purpose.

## Language

Not everything is in English, and it is better to know that before downloading:

| Part | Language |
|---|---|
| `dlink-macfilter.ps1` — command line | English |
| `pick-devices.ps1` — the device window | Russian |
| `wifi-whitelist.ps1` — messages | Russian |
| Code comments | Russian |
| [PROTOCOL.en.md](PROTOCOL.en.md) — the firmware API write-up | English, complete |
| [README.md](README.md) — the full manual | Russian |

The command line is enough to use every feature. The window is the convenient way, and it is not translated.

## Requirements

- D-Link DIR-825ACG1, firmware 3.0.7 (build of 8 December 2021), hardware revision G1 — that is what everything was tested on. Other "anweb" firmware with an `/admin/` interface may work; that was not tested.
- Windows with PowerShell 5.1 (ships with the system)
- The router's admin password

## Install

Download the archive from the [Releases page](../../releases) — that gets you the state this page describes, while the green Code button always gives the newest commit.

Unpack it, open the folder and run, once:

```powershell
Unblock-File -Path .\*.ps1
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\dlink-macfilter.ps1 setup
```

`Unblock-File` clears the "downloaded from the internet" mark that Windows puts on a ZIP; `Set-ExecutionPolicy` allows local scripts to run for your account and needs no administrator rights. `setup` asks for the router password, stores it in `cred.xml` encrypted with Windows DPAPI — readable only by the same account on the same machine — and puts a `Devices` shortcut on the desktop.

## Minimal example

```powershell
.\dlink-macfilter.ps1 status
.\dlink-macfilter.ps1 block   -Mac AA:BB:CC:DD:EE:01
.\dlink-macfilter.ps1 unblock -Mac AA:BB:CC:DD:EE:01
```

`status` prints the default policy and every rule, saying what each device gets rather than what the rule says: `BLOCKED`, or `allowed (rule kept, switched off)`. `unblock` switches a rule off instead of deleting it, so blocking again costs a single request; `remove` deletes it for good.

A name can be used instead of an address once the device is in `devices.json`:

```powershell
.\dlink-macfilter.ps1 block -Name tv
```

The desktop shortcut opens the device window, which lists everything the router sees now or saw in the last 24 hours and lets you tick who to block and who to keep on the Wi-Fi whitelist. It is in Russian, but the table is largely self-explanatory: name, MAC address, connection, state, IP, and the two checkbox columns.

## Documentation

- **[PROTOCOL.en.md](PROTOCOL.en.md)** — the full English write-up of the firmware API: authentication, JSON-RPC, both MAC filters, the `/devinfo` areas, and the traps found on the way. This is the part worth reading even if you own a different router.
- **[README.md](README.md)** — the complete manual, in Russian.

## Limits

**Five password attempts.** After that the router bans authentication for a while. If the stored password is wrong, delete `cred.xml` and run `setup` again.

**Flash wear.** Changes are written to the router's flash, one write per operation. Fine for manual switching, not for an automatic loop. Reading state writes nothing.

**Compatibility.** The API is undocumented and the vendor promised nothing about it. A firmware update may break the scripts.

## Licence

[MIT](LICENSE). Not affiliated with D-Link. Use at your own risk, on your own hardware.
