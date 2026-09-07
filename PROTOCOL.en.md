# D-Link DIR-825ACG1 control protocol

A reverse-engineering write-up of the undocumented API of the "anweb" firmware. Everything here was recovered by reading the JavaScript of the web interface and then verified with requests against a live device.

**Firmware 3.0.7**, build of 8 December 2021, hardware revision G1. On other versions the protocol may differ.

There is no official documentation for this interface. D-Link never promised anything about it and is free to change it in any update.

*This is a full translation of [PROTOCOL.md](PROTOCOL.md). The Russian file is the original and is updated first.*

---

## How it was worked out

The web interface is an AngularJS application and its sources are served without authentication. That is the main source:

```
http://192.168.0.1/autoconf.js                     build parameters, including the model
http://192.168.0.1/apps/admin/config.js            list of pages and their controllers
http://192.168.0.1/concat?type=js&path=admin/js_list        application code
http://192.168.0.1/concat?type=js&path=admin/lib_js_list    libraries and data converters
http://192.168.0.1/apps/admin/pages/<page>/ctrl.lazy.js     controller of a particular page
```

The files are minified but not obfuscated: function and field names survive. Useful entry points to grep for are `somovd` (the JSON-RPC client), `authDigest` (authentication), `rpcs` (configuration numbers) and the page names from `config.js`.

---

## Authentication

The scheme is HTTP Digest MD5 with `qop=auth`, but with a non-standard asymmetry that is easy to trip over.

**The challenge arrives in the `anweb-authenticate` header:**

```
HTTP/1.1 401 Unauthorized
Anweb-Authenticate: Digest qop="auth", realm="domain", nonce="6245488"
Anweb-Auth-Try-Count: 5
Anweb-Auth-Try-Count-Remain: 5
Set-Cookie: device-session-id=...
```

**The response goes into the ordinary `Authorization` header**, plus a repeat marker:

```
Authorization: Digest username="admin", realm="domain", nonce="...", uri="/jsonrpc",
               response="...", qop=auth, nc=00000001, cnonce="..."
anweb-repeat-request: true
```

Answering in the same header the challenge came from is useless — the router silently returns 401 again.

**The maths is the standard RFC 2617:**

```
HA1      = md5(username : realm : password)
HA2      = md5(METHOD : uri)
response = md5(HA1 : nonce : nc : cnonce : qop : HA2)
```

The `uri` inside `HA2` is the bare path, without the query string. For `POST /jsonrpc` that is `md5("POST:/jsonrpc")`, for `GET /devinfo?area=...` it is `md5("GET:/devinfo")`.

⚠️ **Five failed attempts mean a temporary ban.** The password cannot be brute-forced; the remaining count comes back in the `Anweb-Auth-Try-Count-Remain` header.

---

## JSON-RPC

A single endpoint: `POST /jsonrpc`. The body is one JSON-RPC 2.0 object or an array of them.

| Method | Parameters | Purpose |
|---|---|---|
| `read` | `id` | read a configuration |
| `write` | `id`, `data`, `pos`, `save` | write |
| `remove` | `id`, `data`, `pos`, `save` | delete a list entry |
| `cmd` | `id` | send a command to the device |

The `cmd` commands: **20** — save the configuration to flash, **6** — reboot, **8** — save and reboot, **10** — factory reset.

A read looks like this:

```json
{ "jsonrpc": "2.0", "method": "read", "params": { "id": 74 }, "id": 1 }
```

A successful reply carries `result.status = 20` and `result.data`. Any other `status` means a refusal, and the `error` field may well be absent — check both.

### Deleting a list entry

`remove` mirrors `write`: `data` carries the same container as on write, and `pos` names the entry to delete.

```json
{ "jsonrpc": "2.0", "method": "remove",
  "params": { "id": 42, "pos": 3, "save": true,
              "data": { "5G_MacFilterList": { "mac": "AA:BB:CC:DD:EE:03",
                                              "hostname": "phone", "active": true } } },
  "id": 1 }
```

The shape was recovered from the client code and then verified on the device: the interface itself marks an entry with a suffix in its internal model and sends a batch of changes on save, so a single stand-alone call never appears in its code.

### Saving and the "configuration changed" flag

A `write` without `save: true` applies the value but does not commit it to flash. The router then considers the running configuration to be out of step with the saved one and shows a "save manually" prompt in the interface.

The sensible compromise: intermediate writes with `save: false` and one `cmd id:20` at the end of the operation. That reduces flash wear and leaves no dangling flag.

---

## Configuration numbers

| ID | Contents |
|---|---|
| 35 | Wi-Fi settings: networks, passwords, radio, the `mbssid` list |
| 39 | cursor: which network is selected for Wi-Fi filter operations |
| 42 | Wi-Fi MAC filter: policy and address lists |
| 74 | firewall MAC filter |
| 112 | device parameters |
| 258 | per-client rate limiting |

---

## Firewall MAC filter (74)

Applies to the whole bridge: Wi-Fi and wired alike. It blocks traffic routing but does not stop the device from staying on the network and talking to its LAN neighbours.

`data.macfilter` is an array. **Element zero holds the default policy, not a rule:**

```json
{ "id": 0, "state": false, "mac": null, "enable": "DROP" }
```

`state: false` — allow everything (blacklist mode), `state: true` — deny everything (whitelist mode). The distinguishing mark of this element is `mac: null`.

The remaining elements are rules:

```json
{ "id": 3, "state": true, "enable": "DROP", "mac": "AA:BB:CC:DD:EE:01", "hostname": "" }
```

`state` says whether the rule is switched on, `enable` is the action (`ACCEPT` or `DROP`).

### Pitfalls

**A new rule is written with `pos: -1`** — that means "append", and the firmware picks the position. An existing rule is overwritten at its own position in the array.

**On a factory-reset device the array is completely empty**, the policy element included. Append the first rule there and it takes position zero and becomes the default policy — which, with `state: true`, means "deny everything". Every device drops off the network at once, including the one the setup was run from, and the only way back is the Reset button.

The correct order: write the policy element into position 0 explicitly first, then add rules.

---

## Wi-Fi MAC filter (42 and 39)

Applies to wireless clients only and blocks the association with the access point itself — the device cannot join the network at all. Wired connections are untouched.

The fields are per band, the prefix being empty for 2.4 GHz and `5G_` for 5 GHz:

```json
{
  "AccessPolicy": "0",      "MacFilterList":    { "max_instance": 0 },
  "5G_AccessPolicy": "0",   "5G_MacFilterList": { "max_instance": 0 },
  "MaxNumMacFilter": 0,     "SupportHotApply": true
}
```

`AccessPolicy`: **0** — filter off, **1** — let in only the listed devices (whitelist), **2** — deny the listed devices (blacklist).

`MacFilterList` is not an array but an object whose property names are entry numbers:

```json
{
  "max_instance": 5,
  "1": { "mac": "AA:BB:CC:DD:EE:01", "hostname": "laptop", "active": true },
  "4": { "mac": "AA:BB:CC:DD:EE:02", "hostname": "phone", "active": true },
  "5": { "mac": "AA:BB:CC:DD:EE:03", "hostname": "desktop", "active": true }
}
```

The entry number is its `pos`. New ones are added with `pos: -1`, just as in configuration 74; an existing one is deleted with `remove` at its own number.

⚠️ **The numbers are stable identifiers, not array indices.** Verified on the device: after an entry is deleted the others keep their numbers, the freed number is never handed out again, and a new entry gets the next one from the counter. The `1, 4, 5` run in the example above is the normal state of a list that has been edited a few times.

Two things follow. A position must never be computed from the order of entries — it has to be taken from the property name. And the order in which several entries are deleted does not matter: there is no shifting here that would force you to work from the end.

`max_instance` is the value of that very counter, that is, the highest number ever issued — not the number of entries. In the example there are three entries and the counter says five.

The `MaxNumMacFilter` field is zero on the firmware tested — the router does not report any limit on the list length.

### The network-select cursor

Configuration 42 addresses not a whole band but **one network inside it**: the router can hold several networks per band, guest networks included, and each has its own filter. Which one is selected is set by a cursor in configuration 39:

```json
{ "jsonrpc": "2.0", "method": "write",
  "params": { "id": 39, "data": { "mbssidCur": 1 }, "save": false }, "id": 1 }
```

For 5 GHz the field is called `5G_mbssidCur`. The network numbers and their count come from configuration 35: `mbssidNum` and `mbssid[]` with the `SSID` and `BSSID` fields. With no guest networks the number is always `1`.

Reading configuration 39 is pointless — it behaves as a command sink, not as storage.

⚠️ **With a single network in a band the cursor is not needed at all — neither for reading nor for writing.** The stock interface sets it before every operation and it is tempting to copy that, but testing on the device showed:

- the reply to a `read` of configuration 42 is byte-for-byte identical before and after the cursor is set, and it carries the fields of **both** bands at once — `AccessPolicy` together with `5G_AccessPolicy`, both address lists;
- `write` and `remove` without a cursor land exactly in the band named by the field prefix: a write to `MacFilterList` went into 2.4 GHz, one to `5G_MacFilterList` into 5 GHz, with no cross effects.

So the band is chosen by the field prefix, while the cursor distinguishes networks inside it. As long as there is one network the cursor always points at it, and every setting of it is a wasted request — and on a read path it also leaves the "configuration changed" flag behind an operation that changed nothing.

This was tested on a device with one network per band. Add a guest network and the cursor is needed again: without it the operation silently lands on the wrong network.

### Order of operations

The stock interface sets the policy first and adds the addresses afterwards. For a whitelist that is dangerous: between the two commands the policy already says "only those on the list" while the list is still empty — the network is closed to everyone.

The safe order is the opposite: fill the lists on both bands first, switch the policy on with the last commands. A failure at any step then leaves the filter switched off.

**The Wi-Fi settings (configuration 35) need not be touched for this** — that is where the network passwords live, and nothing has to be written there for the filter's sake.

### The list file and the list on the router

The whitelist lives in `whitelist.json`, and `sync` brings the router in line with it: it adds the missing addresses and removes the extra ones. The file is the source of truth — which holds exactly as long as the file exists.

On a new computer it does not: it is not in the repository and the initial setup does not create it. Reading a missing file as an empty list means showing an empty table, and the first sync then wipes everything the router held. The failure is a quiet one: until the whitelist is switched on it breaks nothing, and it surfaces later, when the list goes on and half the devices cannot connect.

So, finding no file, the device picker reads the marks straight from configuration 42: it walks `MacFilterList` and `5G_MacFilterList` and counts in how many lists an address appears. In both — `both`, in one — that band. The band is written into the file the very same way, so a list collected from the router matches a previously saved file — verified by comparing four entries covering all three combinations.

It costs no extra request: configuration 42 has already been read for the status line. Reading creates no file — it appears on the first save, or when the list is switched on and `wifi-whitelist.ps1` demands it.

---

## State information: `/devinfo`

`GET /devinfo?area=<areas separated by |>&need_auth=1`, same authentication, `HA2 = md5("GET:/devinfo")`.

| Area | Contents |
|---|---|
| `client` | facts about the caller itself: MAC, IP, interface, SSID, band |
| `version` | model, firmware version, build date, revision, serial number, uptime |
| `187` | LAN clients: MAC, IP, `name` (`WLAN` or a LAN port), hostname, flags |
| `34` | DHCP leases: MAC, IP, hostname, `vendorid`, lease time left |
| `42` | current contents of the Wi-Fi MAC filters |
| `64` | wireless clients: band, SSID, mode, signal level, time online |

Several areas can be requested at once, separated by a vertical bar: `area=187|34|64`. The reply carries one property per area.

The numeric areas match the configuration numbers. A client flag of `reachable` means the device is active, `stale` means it has not answered for a while.

Without the `area` parameter the router returns `Can't find 'area' parameter`.

### How the areas differ in practice

⚠️ **Area 187 returns a row per IP address, not per device.** Thanks to IPv6 a single phone easily accounts for eight rows with the same MAC and different addresses. The list has to be collapsed by MAC, otherwise it looks several times longer than reality.

The three areas complement each other and none of them replaces the others:

- **187** — who is active right now and what they are connected through. A sleeping phone disappears from here.
- **34** — everyone who connected within the lease time (24 hours). The only way to see a device that is switched off. The `vendorid` field hints at the system: `android-dhcp-15`, `MSFT 5.0`.
- **64** — wireless only. The only reliable sign that a device really is on Wi-Fi, and the only source of the band. Addresses here are upper case; in the other areas they are lower case.

Wi-Fi can be told from a cable like this: presence in area 64 means Wi-Fi; in area 187 the `name` field holds `WLAN` for wireless clients and the port name for wired ones. For a device known only from a DHCP lease the connection type is unknown.

### The reachable flag, and why there are three states rather than two

⚠️ **`stale` does not mean "the device is gone".** Area 187 is a neighbour cache, and the flag only says whether the link was confirmed recently. Verified: a computer that has been switched off hangs there as `stale` for a while — and so does a quiet but connected one. Treating `stale` as presence is wrong (you get "online" for a machine just switched off), and so is treating it as absence (you get "offline" for one that is merely silent).

Hence three levels of confidence instead of the two that suggest themselves:

| Evidence | What it means |
|---|---|
| present in area 64, or in 187 with `reachable` | the link is confirmed |
| present in 187 with `stale` only | the router remembers the device, the link is not confirmed |
| only a DHCP lease in area 34 | it is not in the client list at all |

The firmware offers nothing sharper for wired devices: there is no separate area with LAN port state. Six candidates were checked — `net` returns the router's own interfaces, `180` the connection table, `206` IGMP, `267` Wi-Fi channels, and `interface` and `device` are empty.

### Randomised MAC addresses

Nothing to do with the router's protocol, but everyone who writes rules by address needs it. A randomised address is marked by the **second-least-significant bit of the first byte**, called "locally administered" in the IEEE standard: zero means an address issued by the maker of the network card, one means an address the device made up for itself. Written in hex, the first byte of such an address ends in 2, 6, A or E.

The bit describes a property of the address, not a setting of the device, and therefore does not separate two cases:

- **persistent randomisation** — the address is invented once for a particular network and reused; in practice it is stable until the network is forgotten and the device is reset. This is how Android has behaved by default since version 10;
- **non-persistent** — the address changes regularly.

So the bit lets you say "this address may change", but not "this address does change". Telling one from the other takes watching how long the address holds.

---

## Configuration backup

The download goes through `GET /config_load`, but that request alone is not enough: the interface first makes a preparatory call that builds the file. Without it a placeholder page comes back instead of the configuration. That call was not reverse-engineered — a backup is easier to take from the web interface, under **System → Configuration**.

---

## Other observations

The web interface serves the factory credentials in plain text right inside `autoconf.js` — these are firmware build constants, identical for every device of the model, not the current password. The first-run wizard demands that it be changed.

The web interface session expires after 5 minutes of inactivity (`logoutTime`), which is noticeable when debugging through a browser.

Every write operation spends flash memory. For manual switching that is immaterial; for automated loops it is not.
