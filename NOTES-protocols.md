# CPPMF and DORIC: what is known (Nov 2026 analysis)

There are NO public specifications for either protocol. Cisco treats both as
internal. No IETF/IEEE document, no Cisco doc. Every public fact comes from
reverse engineering (this repo's MITM captures). Searches for "CPPMF" and
"DORIC" protocol specs return only unrelated results.

## CPPMF - TCP/13491, cleartext ASCII

Frame: `CPPMF;<len:4digit>;<chan:2digit>;<msg:3digit>;<payload>`

Observed message IDs in data/cppmf_session.bin (codec to camera):

- 001 / 003 / 028 : session open sequence
- 008 : keepalive (repeats ~every few seconds)
- 011 : key query. Keys seen: link:hwSerialNo, link:hwver, link:swver,
  link:ipv4:address, link:ipv6:address:local, link:ipv6:address:global
- 012 : endpoint announce (key=value). Keys seen: 1:endp:iscrypto=F,
  1:endp:ipv4:address, 1:endp:ipv6:address:local,
  1:endp:ipv6:address:global, 1:endp:swver=ce9.15.0.11.aec227943ed

Purpose: discovery/pairing, device info, keepalive. No control commands
travel on this port. The key tree (link:/endp:) is generic; other keys may
exist but none are publicly captured.

## DORIC - TCP/13496, TLS 1.0 (non-PFS CBC, no cert validation)

Observed session structure:

1. 143-byte banner `DORIC` + four 32-byte identity BLOBs. The BLOBs are the
   codec's captured identity; the camera accepts a client that presents the
   provisioned identity. Treat data/*.bin like a private key.
2. Handshake: `04 00 01 01 01 04 ...`, then a 0x65 frame advertising product
   string (`Precision 60 Camera"HC9.15.0.11 aec227943ed 2021-01-28`), then
   `targets!102110,102110-1,-2,-3` (102110 = board codename "Halley"), then
   `03 01 01 16`.
3. Provisioning: full package install (halley.pkg, ~42 MB). Manifest names
   found in data/doric_session.bin:
   - /mnt/base/active/peripherals/halley.pkg (target path)
   - s01654-main.hex (main controller firmware)
   - fpga/s01778_qsys_define, fpga/s01778fpgaconfig.rbf (FPGA bitstreams;
     s01810 variant also present)
   - motor/application.hex (PTZ motor controller MCU firmware)
   - pki/signcert.pem (device signing certificate)
   - cfg/ca_corr_table.csv, cfg/no_ca_corr_table.csv, cfg/psnr_table.csv,
     cfg/nr.cfg (camera image tuning/calibration tables)
   - partitions.conf.d/{main,rwfs,extra,secure}, /rwfs.conf, rwfsfunctions,
     /postinstall.d/rwfs.hook.exec, SELinux file contexts
   So DORIC can re-flash: SoC firmware, FPGA, motor MCU, certs, calibration
   tables, filesystem layout.
4. Control: RPC payload = varint(svc, obj, methodID) + args. The full method
   table is NO LONGER unknown: `main.bin` (the DORIC listener binary in the
   apps squashfs) is not stripped — `readelf -sW | c++filt` lists all 44
   `HalleyControllerStub::` methods, and wire method ID N maps to controller
   vtable slot N+1 (jump table verified; see ../firmware-extract/analysis/
   doric_13496.md in the parent repo). Full catalog with wire IDs and
   arg specs: ../doric_protocol/README.md; implemented as doric.CMDS in this
   repo. Example — set_ptzf (wire 19, "PositionSet"): `01 01 13` + 4 float
   args. Varints are 7-bit groups, 0x80 = more, BIG-ENDIAN group order
   (verified: banner frame length `81 06` = 134; live probe get_position
   `a054` = 4180, `a104` = 4228). (Earlier "low byte last" claim was wrong.)
   Live-verified from server.py against a real P60 (Nov 13 2026): ramp_pt_*,
   zoom_near/far, set_ptzf, get_status/position/capabilities, set_call_led,
   configure (flip/mirror included), osd_show_text/osd_draw_square/osd_clear,
   convert_preset_motor_positions_to_angles_and_zoom, start_facedetection,
   power_on/reboot. get_capabilities limits (native units): pan ±3600,
   tilt ±650, zoom 4128-14864, focus 4096-4890.
5. Version reports near end of session: frames `27 00 01 09 01 <len> <str>`
   and `26 00 01 06 <len> <str>` carrying HC9.15.0.11 strings and target
   list.

## Session semantics (live-verified Nov 13 2026)

- The camera NEVER acks an RPC. Only two frame types exist: our calls out,
  observer pushes in (prologue `00 01 <eventID varint>`). Setters are
  fire-and-forget; "no reply" means success.
- Queries get_status/get_position/get_capabilities are answered by events
  9/10/11. configure (18) acks with event 8 — latency can exceed 3 s.
  Client must send `subscribe(connID)` after connect to receive events.
- Decoded event payload formats: EVT 1 (position, 4 floats), EVT 2 (converted
  preset positions, 4 floats), EVT 4 (on_faces: count + per-face 5 uvarints,
  score 16.16 fixed point), EVT 5 (heartbeat ~1/s), EVT 13 (video_format at
  connect). Details in doric_protocol/README.md.
- The camera accepts exactly ONE TLS client on 13496; a second handshake is
  cut with EOF.
- start_facedetection is ON-only: no stop RPC exists in the 44-method catalog;
  stopping needs a reboot or power cycle.
- hunter/speakertrack and system LEDs are codec-side; the P60 has no
  microphone (datasheet c78-669051). Don't expose them camera-side.

## What is still NOT known

- osd_draw_square: whether the trailing bool is a draw/erase flag (unproven).
- Exact field ORDER inside EVT 4 FaceDetection (x,y,w,h,score is a
  best-guess) and field NAMES in EVT 2 (order mirrors EVT 1; values exact).
- Why EVT 9 flip/mirror state sometimes reads inverted after a configure ack
  (NOT-semantics or codec-side rewrite — confirm against live video).
- Discovery method note (superseded): the catalog came from static RE of the
  unstripped binary, not from live fuzzing. Fuzzing remains unnecessary and
  risky (DORIC can re-provision — see item 3).

## Naming

"DORIC" and "CPPMF" are the protocols' own on-wire magic strings (doric_session.bin offset 0 = ASCII "DORIC\n"; every CPPMF frame starts "CPPMF;"). They are Cisco/Tandberg internal codenames; no public expansion or alternate public name exists. Cisco port-reference docs do not document 13491/13496. Web searches for the names return only this repo and its forks.
