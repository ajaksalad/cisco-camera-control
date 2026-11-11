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
4. Control: PositionSet = `len` + `01 01 13` + varint(pan) `01` varint(tilt)
   `01` varint(zoom) + `01 00 00`. Varints are signed 0x40-bit,
   7-bit groups, low byte last.
5. Version reports near end of session: frames `27 00 01 09 01 <len> <str>`
   and `26 00 01 06 <len> <str>` carrying HC9.15.0.11 strings and target
   list.

## What is NOT known

- The full DORIC opcode table. Only PositionSet is publicly reverse
  engineered. Codec-driven features (autofocus, presets, home, menu, power)
  must map to other opcodes, but no public capture shows them.
- How to discover them: record 13496 while driving the camera from a real
  codec (SX/C/Room system) and diff frames per button press. Live fuzzing
  risks re-provisioning the camera; not recommended.
