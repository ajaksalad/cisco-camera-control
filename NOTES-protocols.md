# CPPMF and DORIC protocol notes

Last update: Nov 13, 2026. All facts here come from reverse engineering
(this repo's MITM captures and static analysis of the firmware). There are
no public specifications for either protocol. Cisco treats both as
internal: no IETF/IEEE document and no Cisco document exists. Web searches
for "CPPMF" or "DORIC" specs return only this repo and its forks.

## Quick reference

| Port | Protocol | Security | Role |
|------|----------|----------|------|
| TCP/13491 | CPPMF | cleartext ASCII | discovery, pairing, device info, keepalive |
| TCP/13496 | DORIC | TLS 1.0, non-PFS CBC, no cert validation | provisioning (firmware push) and camera control |

The names "DORIC" and "CPPMF" are the protocols' own on-wire magic strings:
`data/doric_session.bin` offset 0 is ASCII `DORIC\n`, and every CPPMF frame
starts with `CPPMF;`. They are Cisco/Tandberg internal codenames. No public
expansion of either name exists. Cisco port-reference docs do not document
13491 or 13496.

## CPPMF — TCP/13491

### Frame format

```
CPPMF;<len:4digit>;<chan:2digit>;<msg:3digit>;<payload>
```

### Observed messages

All traffic in `data/cppmf_session.bin` flows codec → camera.

| Msg ID | Meaning | Detail |
|--------|---------|--------|
| 001, 003, 028 | session open sequence | |
| 008 | keepalive | repeats every few seconds |
| 011 | key query | keys seen: `link:hwSerialNo`, `link:hwver`, `link:swver`, `link:ipv4:address`, `link:ipv6:address:local`, `link:ipv6:address:global` |
| 012 | endpoint announce | key=value pairs; keys seen: `1:endp:iscrypto=F`, `1:endp:ipv4:address`, `1:endp:ipv6:address:local`, `1:endp:ipv6:address:global`, `1:endp:swver=ce9.15.0.11.aec227943ed` |

### Purpose

Discovery, pairing, and device info. No control commands travel on this
port. The key tree (`link:` / `endp:`) is generic; other keys may exist,
but none are publicly captured.

## DORIC — TCP/13496

### Transport and security

- TLS 1.0 only. Non-PFS CBC cipher suites. No certificate validation.
- The camera accepts exactly ONE TLS client. A second handshake is cut
  with EOF.
- The session opens with a 143-byte banner: `DORIC` + four 32-byte
  identity BLOBs. The BLOBs carry the codec's captured identity. The
  camera admits a client that presents the provisioned identity.
  **Treat `data/*.bin` like a private key.**

### Session flow

1. Banner (above).
2. Handshake: `04 00 01 01 01 04 ...`, then a `0x65` frame with the
   product string (`Precision 60 Camera"HC9.15.0.11 aec227943ed
   2021-01-28`), then `targets!102110,102110-1,-2,-3` (102110 is the
   board codename "Halley"), then `03 01 01 16`.
3. Provisioning: the codec installs a full package (`halley.pkg`,
   about 42 MB). See "What DORIC can re-flash" below.
4. Control: RPC calls (see "Command model" below).
5. Version reports near session end: frames `27 00 01 09 01 <len> <str>`
   and `26 00 01 06 <len> <str>` carry the HC9.15.0.11 strings and the
   target list.

### What DORIC can re-flash

Manifest names found in `data/doric_session.bin`:

| Component | Manifest entry |
|-----------|----------------|
| Target path | `/mnt/base/active/peripherals/halley.pkg` |
| Main controller firmware | `s01654-main.hex` |
| FPGA bitstreams | `fpga/s01778_qsys_define`, `fpga/s01778fpgaconfig.rbf` (an s01810 variant is also present) |
| PTZ motor MCU firmware | `motor/application.hex` |
| Device signing certificate | `pki/signcert.pem` |
| Image tuning/calibration tables | `cfg/ca_corr_table.csv`, `cfg/no_ca_corr_table.csv`, `cfg/psnr_table.csv`, `cfg/nr.cfg` |
| Filesystem layout | `partitions.conf.d/{main,rwfs,extra,secure}`, `/rwfs.conf`, `rwfsfunctions`, `/postinstall.d/rwfs.hook.exec`, SELinux file contexts |

So DORIC can re-flash: SoC firmware, FPGA, motor MCU, certificates,
calibration tables, and filesystem layout. This makes casual fuzzing
dangerous: a malformed session could re-provision the camera.

### Command model

- RPC payload = `varint(svc, obj, methodID)` followed by args.
- Varints are 7-bit groups with `0x80` = "more", in BIG-ENDIAN group
  order. Verified two ways: the banner frame length `81 06` decodes to
  134, and a live `get_position` probe returned `a054` = 4180 and
  `a104` = 4228. (An earlier note claimed "low byte last" — that was
  wrong.)
- Example: `set_ptzf` (wire ID 19, the command earlier captures called
  "PositionSet") = `01 01 13` + four float args.
- The full method table is known. `main.bin` (the DORIC listener binary
  in the apps squashfs) is not stripped: `readelf -sW | c++filt` lists
  all 44 `HalleyControllerStub::` methods, and wire method ID N maps to
  controller vtable slot N+1 (jump table verified). Evidence:
  `../firmware-extract/analysis/doric_13496.md` in the parent repo.
- The full catalog with wire IDs and arg specs is in **DORIC.md** (this
  repo). `doric.py` implements it as the `CMDS` dict.

### Commands verified live (server.py against a real P60, Nov 13, 2026)

`ramp_pt_*`, `zoom_near`/`zoom_far`, `set_ptzf`, `get_status`,
`get_position`, `get_capabilities`, `set_call_led`, `configure`
(includes flip/mirror), `osd_show_text`, `osd_draw_square`, `osd_clear`,
`convert_preset_motor_positions_to_angles_and_zoom`,
`start_facedetection`, `power_on`, `reboot`.

Device limits reported by `get_capabilities` (native units):

| Axis | Range |
|------|-------|
| pan | −3600 … +3600 |
| tilt | −650 … +650 |
| zoom | 4128 … 14864 |
| focus | 4096 … 4890 |

### Observer events

- The camera NEVER acks an RPC. Only two frame kinds exist: our calls
  out, and observer pushes in. Setters are fire-and-forget: "no reply"
  means success.
- Event frames start with the prologue `00 01 <eventID varint>`.
- The client must send `subscribe(connID)` after connect to receive
  events.
- Queries are answered by events: `get_status` → EVT 9, `get_position`
  → EVT 10, `get_capabilities` → EVT 11. `configure` (wire 18) acks
  with EVT 8, and that ack can take more than 3 seconds.

Decoded payload formats (full details in DORIC.md):

| Event | Meaning | Payload |
|-------|---------|---------|
| EVT 1 | position | 4 floats |
| EVT 2 | converted preset positions | 4 floats |
| EVT 4 | `on_faces` | count + per-face 5 uvarints; score is 16.16 fixed point |
| EVT 5 | heartbeat | about 1 per second |
| EVT 13 | video_format | sent at connect |

### Behavior notes

- `start_facedetection` is ON-only. The 44-method catalog has no stop
  RPC. To stop detection, reboot or power-cycle the camera.
- Auto-frame "hunter" and speaker-tracking are codec-side features. The
  P60 has no microphone (datasheet c78-669051), and the codec's system
  LED state is codec-side too. Do not expose these camera-side.

## Still not known

- `osd_draw_square`: whether the trailing bool is a draw/erase flag.
  Unproven against live video.
- Field order inside EVT 4 `FaceDetection`: `x, y, w, h, score` is a
  best guess. In EVT 2, the float NAMES are a guess (order mirrors
  EVT 1); the values themselves are exact.
- Why the EVT 9 flip/mirror state sometimes reads inverted after a
  configure ack. Cause is either NOT-semantics in `configure` or a
  codec-side rewrite. Confirm against live video.

## Corrections made during this work

- Varint group order: "low byte last" was wrong; big-endian is correct
  (see verification above).
- "Only PositionSet is known" is obsolete: the full 44-method catalog
  came from static RE of the unstripped binary, not from live fuzzing.
  Fuzzing stays unnecessary and risky (re-provisioning, see above).
