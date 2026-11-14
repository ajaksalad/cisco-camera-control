#!/usr/bin/env python3
"""DORIC wire codec + command catalog (reverse-engineered, live-probe verified).

Frame      = uvarint(payload_len) + payload.
uvarint    = 7-bit groups, 0x80 = continuation, BIG-ENDIAN group order.
signed int = sign bit is 0x40 of the most significant group (that group
             then carries 6 data bits).
float      = IEEE-754 bit pattern serialized as signed int32.
bool/uchar = one raw byte.  string = uvarint length + bytes.
RPC call   = frame( uvarint(svc) uvarint(obj) uvarint(method) args... ).
Camera controller: svc=1 obj=1. Replies arrive as observer events:
frame( 00 01 <eventID> args... ).
"""
import struct

def enc_uint(n):
    if n < 0:
        raise ValueError('enc_uint: negative')
    groups = [n & 0x7F]
    n >>= 7
    while n:
        groups.append(0x80 | (n & 0x7F))
        n >>= 7
    return bytes(reversed(groups))

def dec_uint(buf, pos=0):
    v = 0
    while True:
        g = buf[pos]                      # IndexError if truncated
        pos += 1
        if g & 0x80:
            v = (v << 7) | (g & 0x7F)
        else:
            return (v << 7) | g, pos

def enc_int(v):
    b = bytearray(enc_uint(abs(v)))
    if b[0] & 0x40:                 # would collide with sign bit: add a
        b = bytearray(b'\x80') + b  # leading zero continuation group
    if v < 0:
        b[0] |= 0x40
    return bytes(b)

def dec_int(buf, pos=0):
    groups = []
    while True:
        g = buf[pos]
        pos += 1
        groups.append(g)
        if not g & 0x80:
            break
    sign = (groups[0] >> 6) & 1
    v = groups[0] & 0x3F
    for g in groups[1:]:
        v = (v << 7) | (g & 0x7F)
    return (-v if sign else v), pos

def enc_float(f):
    return enc_int(struct.unpack('<i', struct.pack('<f', f))[0])

def dec_float(buf, pos=0):
    v, pos = dec_int(buf, pos)
    return struct.unpack('<f', struct.pack('<i', v))[0], pos

def enc_str(s):
    b = s.encode()
    return enc_uint(len(b)) + b

class Reader:
    def __init__(self, buf, pos=0):
        self.buf, self.pos = buf, pos
    def uint(self):
        v, self.pos = dec_uint(self.buf, self.pos); return v
    def int(self):
        v, self.pos = dec_int(self.buf, self.pos); return v
    def float(self):
        v, self.pos = dec_float(self.buf, self.pos); return v
    def byte(self):
        v = self.buf[self.pos]; self.pos += 1; return v
    def string(self):
        n = self.uint()
        s = self.buf[self.pos:self.pos+n].decode('utf-8','replace')
        self.pos += n; return s

def frame(payload):
    return enc_uint(len(payload)) + payload

def call(mid, args=b''):
    return frame(enc_uint(1) + enc_uint(1) + enc_uint(mid) + args)

def split_frames(buf):
    """Complete frames -> (payloads, leftover)."""
    out, pos = [], 0
    while pos < len(buf):
        try:
            n, p2 = dec_uint(buf, pos)
        except IndexError:
            break
        if len(buf) - p2 < n:
            break
        out.append(buf[p2:p2+n])
        pos = p2 + n
    return out, buf[pos:]

# spec chars: i signed int, u unsigned/uchar, f float, b bool, s string
CMDS = {
    'subscribe':          (1,  'i'),
    'pan_tilt_optical_digital': (2, 'ffff'),
    'pan_tilt_optical_digital_step': (3, 'bifibifibifibi'),
    'set_focus_distance': (4,  'f'),
    'hunter_crop':        (5,  'iiii'),
    'enable_hunter_mode': (6,  ''),
    'disable_hunter_mode':(7,  ''),
    'osd_show_text':      (8,  'siiii'),
    'osd_draw_square':    (9,  'iiiib'),
    'osd_clear':          (10, ''),
    'set_system_led':     (11, 'i'),   # serialize_int (status mode 0..15)
    'set_call_led':       (12, 'u'),   # serialize_unsigned (0 off,1 on,2 blink)
    'convert_preset_motor_positions_to_angles_and_zoom': (13, 'iii'),
    'enable_speakertrack_mode':  (14, ''),
    'disable_speakertrack_mode': (15, ''),
    'start_facedetection':(16, ''),
    'reboot':             (17, ''),
    'configure':          (18, 'C'),   # CameraConfig; ack = event 8 on_config_complete
    'set_ptzf':           (19, 'I'),   # pan,tilt,zoom,focus + enables
    'get_status':         (20, ''),
    'get_position':       (21, ''),
    'get_capabilities':   (22, ''),
    'ramp_left':          (23, 'i'),
    'ramp_right':         (24, 'i'),
    'ramp_up':            (25, 'i'),
    'ramp_down':          (26, 'i'),
    'ramp_up_left':       (27, 'ii'),
    'ramp_up_right':      (28, 'ii'),
    'ramp_down_left':     (29, 'ii'),
    'ramp_down_right':    (30, 'ii'),
    'ramp_pt_stop':       (31, ''),
    'pan_tilt_reset':     (32, ''),
    'ramp_zoom_in':       (33, 'i'),
    'ramp_zoom_out':      (34, 'i'),
    'ramp_zoom_stop':     (35, ''),
    'zoom_reset':         (36, ''),
    'focus_near':         (37, 'i'),
    'focus_far':          (38, 'i'),
    'focus_stop':         (39, ''),
    'focus_reset':        (40, ''),
    'focus_trigger_auto': (41, ''),
    'focus_logging':      (42, 'i'),
    'power_on':           (43, ''),
    'power_off':          (44, ''),
}

# methods answered by an observer event (id): caller waits for that event
QUERY_EVENT = {'get_status': 9, 'get_position': 10, 'get_capabilities': 11,
               'configure': 8}

# CameraConfig field order (struct @0x2a5144, serialize order ascending)
CONFIG_FIELDS = [('brightness_auto','b'),('brightness_level','i'),
                 ('whitebalance_auto','b'),('whitebalance_level','i'),
                 ('focus_mode','u'),('backlight_on','b'),
                 ('exposure_comp_level','i'),('mirror','i'),('flip','i'),
                 ('gamma_auto','b'),('gamma_level','i'),
                 ('ir_mode_on','b'),('power_frequency','i'),
                 ('video_format','i'),
                 ('reserved','b')]     # struct +56: serialized, unused by firmware

def encode_args(spec, args):
    out = bytearray()
    if spec == 'I':          # CameraPositionSet dict
        for k in ('pan','tilt','zoom','focus'):
            if k in args:
                out += enc_int(int(args[k])) + b'\x01'
        return bytes(out)
    if spec == 'C':          # CameraConfig dict
        for name, t in CONFIG_FIELDS:
            out += _one(t, args.get(name))
        return bytes(out)
    for i, t in enumerate(spec):
        out += _one(t, args[i])
    return bytes(out)

def _one(t, v):
    if t == 'i': return enc_int(int(v))
    if t == 'u': return enc_uint(int(v))
    if t == 'f': return enc_float(float(v))
    if t == 'b': return b'\x01' if v else b'\x00'
    if t == 's': return enc_str(str(v))
    raise ValueError('bad spec char %r' % t)

def encode_cmd(name, args):
    mid, spec = CMDS[name]
    return call(mid, encode_args(spec, args))

def decode_event(payload):
    """Observer frame -> (eventID, decoded-or-None, raw hex)."""
    r = Reader(payload)
    r.uint(); r.uint()          # svc, obj (0,1)
    evt = r.uint()
    try:
        if evt == 1:
            data = dict(pan=r.float(), tilt=r.float(),
                        zoom=r.float(), focus=r.float())
        elif evt == 9:
            # field naming matches the configure() request fields (verified
            # live: configure mirror=1 -> byte0=1, flip=1 -> byte1=1)
            data = dict(mirror=r.byte(), flip=r.byte(),
                        focus_mode=r.uint(), flag=r.byte(),
                        upside_down=r.byte())
        elif evt == 10:
            data = dict(pan=r.int(), tilt=r.int(),
                        zoom=r.int(), focus=r.int())
        elif evt == 11:
            data = dict(camera_id=r.int(), serial=r.string(),
                        software=r.string(),
                        limits=[r.int() for _ in range(8)])
        elif evt == 13:
            data = dict(video_format=r.int())
        elif evt == 14:
            data = dict(ir_mode=r.byte())
        else:
            data = None
    except (IndexError, ValueError):
        data = None
    return evt, data, payload.hex()