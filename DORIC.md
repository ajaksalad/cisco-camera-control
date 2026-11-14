# DORIC protocol RE (main.bin, tcp/13496)

> Copy of `doric_protocol/README.md` from the parent repo
> (`/mnt/git/cisco-camera`). Keep the two files in sync; the parent repo
> copy is the authoritative one for protocol-RE updates.

Goal: decode the DORIC RPC commands accepted by the camera's DORIC
server (`HalleyDoricServer` in `firmware-extract/output/apps_root/main.bin`)
and their argument formats.

## Confirmed so far

- Binary: ELF32 ARM PIE, not stripped, 3,637,388 bytes, sha256
  211d24834c197e4b3fd5485945a994a014521be8619955b0f3d63b4c7b569bd0
- Server listens on tcp/13496 (LE32 0x34b8 at 0x185b2c, see
  `analysis/doric_13496.md`).
- Objects arrive as `doric::internal::serialize(...)`/`deserialize(...)`
  buffers inside `doric::internal::Packet` frames over TLS/TCP.
- WARNING: `cisco-camera-control/data/doric_session.bin` is a firmware
  UPDATE stream (magic `DORIC\n`), and `cppmf_session.bin` is the
  CPPMF discovery TLV protocol. Neither is a DORIC RPC session. The
  DORIC RPC channel starts with the 7-byte salutation below.
- Wire IDs are numeric. The method dispatch switch is in
  `doric::internal::HalleyControllerSkeleton::dispatch(Packet&)`
  @0x1af088 (3272 bytes); event dispatch is
  `HalleyObserverSkeleton::dispatch` @0x1b1db4.

## Wire framing and session state machine (Ghidra decompile of doric::Bus)

Decompiles in `out/doric_decompile4.txt` / `out/doric_decompile5.txt`
(readelf VAs; Ghidra VAs are +0x10000).

- Frame format: `varint(payload_length) + payload`.
  `Bus::sendPacket` (0x1975f8) builds a header packet containing only
  `serialize_unsigned(payload.size())`, appends header then payload to
  the transport. `Bus::receivePacket` (0x199a94) reads the stream
  buffer, `deserialize_unsigned()` at the cursor gives L,
  `expected = L + header_bytes`; a short read returns and waits.
  `transportReceived` (0x199bec) loops `eraseHead()` per complete frame.
- `Packet` itself is a byte buffer with a cursor; no header parsing
  inside it (`out/doric_decompile3.txt`).
- Session state at Bus+0x38: 1=salutation, 2=negotiation, 3=invoke.
  After TCP/TLS setup the client sends exactly the 7 bytes
  `44 4f 52 49 43 0a 1b` ("DORIC\n" + 0x1b, constant @file 0x277928).
  `processSalutation` (0x198938) byte-compares 7 bytes against a
  GOT-resolved table. Mismatch closes the session with error
  "Invalid salutation" (strings @file 0x277ad4/0x277ae8).
  NOTE: the earlier "1EEEE\0" claim was WRONG — that byte run is the
  tail of debug string "...placeholderILi1EEEE\0" @file 0x2778bc.
  Corrected by live probe (`tools/probe.py`, `out/probe_run1.txt`).
- Negotiation (state 2): immediately after the salutation both sides
  exchange one frame: `varint(len) + payload`, payload = two string
  sets (varint count + N x [varint len + bytes]). The camera's reply
  is `DORIC\n` banner + `81 06` (=varint 134) + 2 sets x 2 x 32-byte
  identity strings (the BLOB1..BLOB4 constants compiled in .rodata,
  e.g. @0x279368). Big-endian varint groups (0x80 = more):
  `81 06` = 1x128+6 = 134 confirms big-endian, not low-byte-last.
- Invocation (state 3): `Bus::processInvocation` (0x198a80) reads
  varint svcID, varint objID, varint methodID, then calls
  `Session::getSkeleton(svcID, objID)` and
  `Skeleton::dispatch(packet, svcID, objID, methodID, ...)`.
  `HalleyControllerSkeleton::dispatch` reads args after the 3-varint
  prologue. So an RPC payload is:
  `varint(svc) varint(obj) varint(method) args...`
  (the `01 01 13` = svc 1, obj 1, method 19 seen in earlier notes).
- Subscribe: controller dispatch case 1 builds
  `HalleyObserverStub(session, objID, int, int, int)` — subscribe
  frame = varint objID + 3 more ints.
- Unknown method -> `serialize_method_not_found`; unknown object ->
  `serialize_object_not_found` reply frames.

## Commands accepted by the server (HalleyControllerImpl vtable @0x2ad4bc)

Verified: wire ID N maps to vtable offset 4*(N+1) = slot label N+1
(jump table @0x1af0c8..0x1af178 in dispatch, linear). Full ID list in
`out/id_map.txt`. Serializer arg types per command also in that file.

| slot | command | args |
|---|---|---|
| 3 | pan_tilt_optical_digital | float x4 |
| 4 | pan_tilt_optical_digital_step | (bool,int) x4 |
| 5 | set_focus_distance | float |
| 6 | hunter_crop | int x4 |
| 7/8 | enable/disable_hunter_mode | - |
| 9 | osd_show_text | string, int x4 |
| 10 | osd_draw_square | int x4, bool |
| 11 | osd_clear | - |
| 12 | set_system_led | int |
| 13 | set_call_led | CameraCallLedState |
| 14 | convert_preset_motor_positions_to_angles_and_zoom | int x3 |
| 15/16 | enable/disable_speakertrack_mode | - |
| 17 | start_facedetection | - |
| 18 | reboot | - |
| 19 | configure | CameraConfig |
| 20 | set_ptzf | CameraPositionSet |
| 21 | get_status | - |
| 22 | get_position | - |
| 23 | get_capabilities | - |
| 24-31 | ramp_left/right/up/down/up_left/up_right/down_left/down_right | int(s) |
| 32 | ramp_pt_stop | - |
| 33 | pan_tilt_reset | - |
| 34/35/36 | ramp_zoom_in/out/stop | int, int, - |
| 37 | zoom_reset | - |
| 38/39/40/41 | focus_near/far/stop/reset | int, int, -, - |
| 42 | focus_trigger_auto | - |
| 43 | focus_logging | int |
| 44/45 | power_on / power_off | - |

### Camera-side vs codec-side (verified 2026-11-13)

- **No-op on this camera (do not expose in UI):** `hunter_crop`, `enable/disable_hunter_mode` — the camera-side handler (main.bin 0xe9368) is an empty stub (stack-guard check + return). These features need the codec's microphone array. The CTS-CAM-P60 has NO microphone and no audio interfaces at all (datasheet c78-669051: HDMI 1.4 + 3G-SDI video, Ethernet only), so all audio-tracking features are codec-driven. `enable/disable_speakertrack_mode` follow the same audio-driven pattern.
- **`set_system_led` (wire 11):** drives the *codec* call LED (`camled`, handler 0x18b9a4) — no visible effect on the camera. Not useful against the camera alone.
- **`set_call_led` (wire 12):** the camera's own LED. Camera-side, works. Verified values: **0 = lit, 1 = off, 2 = blink** (inverse of intuition; confirmed live).
- **`start_facedetection` (wire 17):** camera-side — real algorithm code exists in main.bin (`facedetect_start` 0x22e7f0, `facedetect_one_iteration` 0x22e238, `com_facedetect_*`). ON-only: the controller stub catalog has no stop/toggle method, and the detection task is gated by an internal flag no RPC writes — stop requires reboot or power cycle.
- **`configure` (wire 19), osd_*, PTZ, reboot, power:** camera-side, all verified live.

## Events sent by the camera (HalleyObserverStub vtable)

on_camera_ptod(f,f,f,f),
on_converted_preset_motor_positions_to_angles_and_zoom(f,f,f,f),
on_camera_malfunction(string,int,bool), on_faces(vector FaceDetection),
on_invalid_gain(), on_motion_report(vector bool),
on_source_physical_address(SourcePhysicalAddress), on_config_complete(),
on_status(CameraStatus), on_position(int x4),
on_capabilities(CameraCapabilities), on_power_on_complete(),
on_video_format(int), on_ir(uchar)

Event frame prologue: `00 01 <eventID varint>` then the payload.
Observed payload formats (live captures, 2026-11-13):

- EVT 2 (converted preset positions): four IEEE-754 floats, same field order
  as EVT 1 (pan, tilt, zoom, focus — naming best-guess, values exact).
- EVT 4 (on_faces): `<count U>` then per face five uvarints
  (FaceDetection: x, y, w, h, score — order best-guess from "5 ints").
  score is 16.16 fixed point (16384 = 0.25). Captures with h = 3..6 px and
  score 0.25 are weak/false-positive detections, not locked faces.

## Serializable payload types (verified via Ghidra decompile of Packet primitives)

Wire encoding (from serialize_int @0x19c1ac Ghidra VA, deserialize_unsigned
@0x19b3f4 — pseudocode in out/doric_decompile2.txt):
- int (signed): magnitude split into 7-bit groups, BIG-ENDIAN on the wire
  (bytes built LSB-first, then reverse-inserted). Every byte except the
  last has continuation bit 0x80. Last byte carries sign: 0x40 set =
  negative. Value = concat(groups), negated if sign bit set.
- unsigned / int32: same varint, no sign bit.
- float: serialize_int32_t of the IEEE-754 bit pattern (varint).
- uint8_t / char / bool: 1 raw byte.
- string: varint length + raw bytes.
- vector<T>: varint count, then elements. vector<bool> = count + 1 byte
  each. vector<FaceDetection> elements are 20 bytes = 5 ints.
- Field order = serialize call order.

CameraPositionSet (set_ptzf, matches pan_tilt_zoom_focus(bool,int)x4):
```
@0x00 int pan        @0x04 bool pan enable
@0x08 int tilt       @0x0c bool tilt enable
@0x10 int zoom       @0x14 bool zoom enable
@0x18 int focus      @0x1c bool focus enable
```

CameraConfig (names confirmed via HalleyConfig::configure + dump_config,
@0x18f8a0/0x18f740):
```
@0x00 bool  brightnessauto      @0x24 bool  gammaauto
@0x04 int   brightnesslevel     @0x28 int   gammalevel
@0x08 bool  whitebalanceauto    @0x2c bool  irmodeon
@0x0c int   whitebalancelevel   @0x30 int   powerfrequency
@0x10 uchar focus mode          @0x34 int   videoformat
@0x14 bool  backlighton
@0x18 int   exposurecomplevel   serialize order: 0x00..0x34 ascending
@0x1c int   mirror
@0x20 int   flip
```

CameraStatus (built by get_status @0x18bc70, sp staging = struct):
```
@0x00 bool   camera_is_flipped()
@0x01 bool   camera_is_mirrored()
@0x04 uint   focusGetMode()
@0x08 bool   HalleyDoricServer member flag [this+0x4c]
@0x09 bool   camera_is_upside_down()
```

CameraCapabilities (get_capabilities):
```
@0x00 int        (protocol/version?)
@0x04 string
@0x1c string
@0x34 int @0x38 int @0x3c int @0x40 int
@0x44 int @0x48 int @0x4c int @0x50 int
```

FaceDetection: 5 ints (@0x00..0x10) — x,y,w,h + score?
SourcePhysicalAddress: 4 ints (@0x00..0x0c)
SoftwareInfo: string @0x00, string @0x18 (name, version)

Event 3 on_camera_malfunction(string,int,bool) confirmed from stub
signature; event args list in out/id_map.txt.

## Tools

- `tools/vtable_dump.py <elf> [substrings...]` — ELF32 ARM vtable dump
  (relocation aware).
- `tools/DecompileSubs.java` — Ghidra postScript, decompiles functions
  matching name substrings.
- `tools/probe.py` — live read-only probe (handshake + get_status/
  position/capabilities + announce/subscribe round-trip).
- `out/doric_decompile.txt` — pseudocode (generated by headless run).

## Live probe findings (out/probe_run1.txt, camera 192.168.78.117)

- Handshake accepted as-is from `cisco-camera-control/server.py`
  banner; TLSv1.2 negotiated; server echoes a 143-byte reply
  (salutation + varint(134) + same 2x2 identity-string structure).
- Request frames observed (len + svc,obj,method):
  `04 00 01 01 01` bus.m1(1) -> reply `01 01 01` + string
  "PrecisionHD 1080p 10X".
  `03 01 01 14` get_status, `03 01 01 15` get_position,
  `03 01 01 16` get_capabilities, `03 01 01 13` subscribe ack path.
- Controller method replies arrive as observer-style frames with
  prologue `00 01 <eventID>`: get_status -> event 9, get_position ->
  event 10, get_capabilities -> event 11, set_led -> event 7,
  announce ack -> event 5, subscribe ack -> event 13 (0x0d).
  The controller answers by dispatching to the client-registered
  observer (svc 0 obj 1 = client stub).
- Decoded values: cameraId int 85; serial "FDO2407J6B0";
  software "HC9.15.0.11.aec227943ed, 2021-01-28"; position
  pan=0 tilt=0 zoom=4180 focus=4228 (big-endian varints a054, a104);
  capabilities carries 8 varint limit pairs (pan/tilt/zoom/focus).


