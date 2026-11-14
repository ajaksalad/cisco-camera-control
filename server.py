#!/usr/bin/env python3
"""
Minimal control server for Cisco TTC8-07 / Precision HD cameras.

Usage:
    ./server.py --camera 192.168.1.150 192.168.1.151 [--names "Stage Left" "Stage Right"] [--port 8080]

Opens a DORIC session to each camera and exposes a tiny HTTP API:

    GET  /          → control web UI (camera selector + PTZ controls)
    POST /position  → JSON {cam, pan, tilt, zoom}  (cam = 0-based index, default 0)
    GET  /status    → JSON array of connection states, one entry per camera

Each camera must already be provisioned by a compatible codec (or by provision.py).
"""
import argparse, http.server, json, os, queue, select, socket, ssl, sys, threading, time
import doric

# CameraConfig power-on defaults (field 15 is serialized but unused by fw).
DEFAULT_CFG = {
    'brightness_auto': 1, 'brightness_level': 0,
    'whitebalance_auto': 1, 'whitebalance_level': 0,
    'focus_mode': 0, 'backlight_on': 0, 'exposure_comp_level': 0,
    'mirror': 0, 'flip': 0, 'gamma_auto': 1, 'gamma_level': 0,
    'ir_mode_on': 0, 'power_frequency': 0, 'video_format': 1,
    'reserved': 0,
}

# ── DORIC protocol constants (captured from a real codec session) ─────────────

BLOB1 = bytes.fromhex('4d5a6de53873433a3088fb770e5651f0b5a5eca3cf7f0845f8d8061fc0382905')
BLOB2 = bytes.fromhex('9bab1c04b4bb64fd14210e47561c87ca88d251ede373fe956452e729e314092c')
BLOB3 = bytes.fromhex('142176358c1ef069ced27be3c1d796929737dbb56b479a29fcea1be6200bccfb')
BLOB4 = bytes.fromhex('2b2f251870aabde90fb7bd0427fe762feba01c4f41dbb48aa6c3e2af32592110')
BANNER = (b'DORIC\n' + bytes([0x1b,0x81,0x06]) +
          bytes([0x02,0x20]) + BLOB3 + bytes([0x20]) + BLOB4 +
          bytes([0x02,0x20]) + BLOB1 + bytes([0x20]) + BLOB2)

DORIC_PORT = 13496

# ── PositionSet encoding (derived from MITM analysis) ────────────────────────

def _encode_pos_field(raw, negative=False):
    sign = 0x40 if negative else 0x00
    low, high = raw & 0x7F, raw >> 7
    if high == 0:   return bytes([low | sign])
    if high < 64:   return bytes([0x80 | sign | high, low])
    return bytes([0x80 | sign | (high >> 7), 0x80 | (high & 0x7F), low])

def _xapi_to_pos_raw(xapi):     return (abs(xapi) * 2549) // 7000
def _xapi_to_zoom_raw(zoom):    return max(0, (29417000 - max(1000, min(20000, zoom)) * 2129) // 3000)

def build_positionset(pan_xapi, tilt_xapi, zoom_xapi):
    pan_enc  = _encode_pos_field(_xapi_to_pos_raw(pan_xapi),  pan_xapi  < 0)
    tilt_enc = _encode_pos_field(_xapi_to_pos_raw(tilt_xapi), tilt_xapi < 0)
    zoom_enc = _encode_pos_field(_xapi_to_zoom_raw(zoom_xapi))
    payload  = bytes([0x01,0x01,0x13]) + pan_enc + b'\x01' + tilt_enc + b'\x01' + zoom_enc + bytes([0x01,0x00,0x00])
    return bytes([len(payload)]) + payload

# ── Camera connection ─────────────────────────────────────────────────────────

class Camera:
    def __init__(self, ip, name=None):
        self.ip       = ip
        self.name     = name or ip
        self.conn     = None
        self.alive    = True
        self.send_q   = queue.Queue()
        self.last_pos = {'pan': None, 'tilt': None, 'zoom': None, 'ts': 0.0}
        self.rxb      = b''            # partial-frame carry across recv()
        self.telemetry = {}            # event id -> last decoded payload
        self.pending  = {}             # event id -> threading.Event (ask())
        self.tlock    = threading.Lock()
        # No config getter in the protocol: keep a local mirror of the last
        # configure() sent. Defaults match the firmware's power-on defaults.
        self.cfg = dict(DEFAULT_CFG)

    def _tls_connect(self):
        # Camera (TTC8-07) only speaks TLS 1.0 with non-PFS CBC ciphers.
        # create_default_context() floors the version at TLS 1.2 on Python >=3.12,
        # which produces "unsupported protocol". Build the context explicitly and
        # drop the floor to TLS 1.0 + SECLEVEL=0.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers('ALL:@SECLEVEL=0')
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(5)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,  10)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,   3)
        except AttributeError:
            pass  # not available on all platforms (Windows)
        raw.connect((self.ip, DORIC_PORT))
        c = ctx.wrap_socket(raw, server_hostname=self.ip)
        c.setblocking(False)
        return c

    def _rd(self, c, timeout=2.0):
        buf = b''; deadline = time.time() + timeout
        while time.time() < deadline:
            r, _, _ = select.select([c], [], [], min(deadline - time.time(), 0.2))
            if r:
                try:
                    d = c.recv(4096)
                    if not d: break
                    buf += d
                except (ssl.SSLWantReadError, BlockingIOError):
                    continue
                except Exception:
                    break
            elif buf:
                break
        return buf

    def _rd_exact(self, c, n, timeout=5):
        buf = b''; deadline = time.time() + timeout
        while len(buf) < n and time.time() < deadline:
            r, _, _ = select.select([c], [], [], 0.5)
            if r:
                d = c.recv(n - len(buf))
                if not d: raise EOFError
                buf += d
        if len(buf) < n: raise TimeoutError
        return buf

    def _handshake(self, c):
        c.send(BANNER)
        assert self._rd_exact(c, 143)[:5] == b'DORIC'
        c.send(bytes.fromhex('040001010104010101010401010b01')); self._rd(c, 3)
        c.send(bytes([0x65,0x00,0x01,0x02,0x02,0x13]) +
               b'Precision 60 Camera\x22HC9.15.0.11 aec227943ed 2021-01-28'
               b'\x07targets!102110,102110-1,102110-2,102110-3'); self._rd(c, 2)
        c.send(bytes([0x03,0x01,0x01,0x16])); self._rd(c, 2)
        c.send(bytes([0x03,0x01,0x01,0x14])); self._rd(c, 2)
        c.send(bytes.fromhex('0d010113000100' '01a020' '01a068' '011201'
                             '0112010001000100' '000202010001020300040101' '0b01'))
        self._rd(c, 2)
        c.send(bytes([0x03,0x01,0x01,0x14])); self._rd(c, 3)

    def run(self):
        while self.alive:
            try:
                c = self._tls_connect()
                self._handshake(c)
                c.send(doric.encode_cmd('subscribe', [1]))  # observer events
                self._rd(c, 3)
                self.conn = c
                self.rxb = b''
                print(f'[camera] ready ({self.name} / {self.ip})', flush=True)
                while self.alive:
                    try:
                        while True:
                            data = self.send_q.get_nowait()
                            try:
                                c.send(data)
                            except (ssl.SSLWantWriteError, BlockingIOError):
                                self.send_q.put(data)
                                break
                    except queue.Empty:
                        pass
                    r, _, _ = select.select([c], [], [], 0.2)
                    if r:
                        try:
                            d = c.recv(4096)
                            if not d:
                                print(f'[camera] disconnect: FIN ({self.name})', flush=True)
                                break
                            self.rxb += d
                            frames, self.rxb = doric.split_frames(self.rxb)
                            for f in frames:
                                self._ingest(f)
                        except (ssl.SSLWantReadError, BlockingIOError):
                            pass
                        except Exception as e:
                            print(f'[camera] recv error ({self.name}): {e}', flush=True)
                            break
            except Exception as e:
                print(f'[camera] connect failed ({self.name}): {e}', flush=True)
            self.conn = None
            pends, self.pending = list(self.pending.values()), {}
            for ev in pends:          # wake ask() callers at once
                ev.set()
            time.sleep(2)
            print(f'[camera] reconnecting... ({self.name})', flush=True)

    def goto(self, pan, tilt, zoom):
        if self.conn is None:
            raise RuntimeError(f'camera not connected ({self.name})')
        frame = build_positionset(int(pan), int(tilt), int(zoom))
        self.send_q.put(frame)
        self.last_pos = {'pan': pan, 'tilt': tilt, 'zoom': zoom, 'ts': time.time()}

    def _ingest(self, payload):
        evt, data, raw = doric.decode_event(payload)
        if os.environ.get('DORIC_RX'):
            print(f'[rx] evt={evt} data={data} raw={raw}', flush=True)
        if data is not None:
            with self.tlock:
                self.telemetry[evt] = data
        ev = self.pending.pop(evt, None)
        if ev is not None:
            # ack frames with no args (e.g. on_config_complete) still count
            ev.result = data if data is not None else 'acked'
            ev.set()

    def command(self, name, args=None):
        if self.conn is None:
            raise RuntimeError(f'camera not connected ({self.name})')
        self.send_q.put(doric.encode_cmd(name, args or []))

    def ask(self, name, args=None, timeout=3.0):
        """Query method whose reply arrives as an observer event."""
        evt_id = doric.QUERY_EVENT[name]
        if self.conn is None:
            raise RuntimeError(f'camera not connected ({self.name})')
        ev = threading.Event()
        ev.result = None
        self.pending[evt_id] = ev
        self.send_q.put(doric.encode_cmd(name, args if args is not None else []))
        if not ev.wait(timeout):
            self.pending.pop(evt_id, None)
            raise TimeoutError(f'no reply to {name} within {timeout}s')
        return ev.result

# ── Web UI ────────────────────────────────────────────────────────────────────

PANEL_HTML = '''
<div class="sec">Move (hold to ramp)</div>
<div class="pad">
<button class="pbtn" data-hold="ramp_up">&#9650;</button>
<div class="padrow">
<button class="pbtn" data-hold="ramp_left">&#9664;</button>
<button class="pbtn" data-cmd="ramp_pt_stop">&#9632;</button>
<button class="pbtn" data-hold="ramp_right">&#9654;</button>
</div>
<button class="pbtn" data-hold="ramp_down">&#9660;</button>
</div>
<div class="row"><label>Speed</label>
<input type="number" id="speed" value="50" min="1" max="100" step="1"></div>
<div class="btnrow">
<button class="abtn" data-hold="ramp_zoom_in" data-stop="ramp_zoom_stop">Zoom+
 (hold)</button>
<button class="abtn" data-hold="ramp_zoom_out" data-stop="ramp_zoom_stop">Zoom-
 (hold)</button>
</div>
<div class="sec">Home / Focus</div>
<div class="btnrow">
<button class="abtn" data-cmd="pan_tilt_reset">PT home</button>
<button class="abtn" data-cmd="zoom_reset">Zoom home</button>
<button class="abtn" data-cmd="focus_reset">Focus home</button>
<button class="abtn" data-cmd="focus_trigger_auto">Auto focus</button>
<button class="abtn" data-hold="focus_near" data-stop="focus_stop">Near</button>
<button class="abtn" data-hold="focus_far" data-stop="focus_stop">Far</button>
</div>
<div class="sec">Query (live reply from camera)</div>
<div class="btnrow">
<button class="abtn" data-ask="get_status">Status</button>
<button class="abtn" data-ask="get_position">Position</button>
<button class="abtn" data-ask="get_capabilities">Capabilities</button>
</div>
<div class="sec">Modes / System (use with care)</div>
<div class="btnrow">

<button class="abtn" data-cmd="start_facedetection">Face detect</button>
<button class="abtn" data-cmd="osd_clear">OSD clear</button>
</div>
<div class="sec">Image (configure: server merges with last-known config)</div>
<div class="btnrow">
<button class="abtn" data-cmd="configure" data-args='{"flip":1}'>Flip on</button>
<button class="abtn" data-cmd="configure" data-args='{"flip":0}'>Flip off</button>
<button class="abtn" data-cmd="configure" data-args='{"mirror":1}'>Mirror on</button>
<button class="abtn" data-cmd="configure" data-args='{"mirror":0}'>Mirror off</button>
</div>
<div class="btnrow">
<button class="abtn" data-cmd="set_call_led" data-args="[0]">Call LED on</button>
<button class="abtn" data-cmd="set_call_led" data-args="[2]">Call LED blink</button>
<button class="abtn" data-cmd="set_call_led" data-args="[1]">Call LED off</button>
<button class="abtn" data-cmd="osd_show_text" data-args="[\"HELLO\",100,100,120,40]">OSD text</button>
</div>
<div class="btnrow">
<button class="abtn danger" data-cmd="power_on">Power on</button>
<button class="abtn danger" data-cmd="power_off">Power off</button>
<button class="abtn danger" data-cmd="reboot">Reboot</button>
</div>
<pre id="telem">telemetry: waiting for events…</pre>
'''

PANEL_JS = '''
const EV_NAMES = {2:'preset_angles',3:'malfunction',4:'faces',6:'motion',
  7:'source_address',8:'config_complete',9:'status',10:'position',
  11:'capabilities',12:'power_on_complete',13:'ack/config',14:'video_format'};
const speed = () => Math.max(1, +$('speed').value || 50);

async function sendCmd(cmd, args, ask) {
  if (selectedCam === null) { $('status').textContent = 'Select a camera first'; return; }
  const body = JSON.stringify({cam: selectedCam, cmd, args: args || []});
  try {
    const r = await fetch('/command', {method:'POST',
      headers:{'Content-Type':'application/json'}, body});
    const t = await r.text();
    if (ask && r.ok) { const j = JSON.parse(t);
      $('telem').textContent = cmd + ' -> ' + JSON.stringify(j.reply, null, 1); }
    else $('status').textContent = r.ok ? 'sent: ' + cmd : 'error ' + r.status + ': ' + t;
  } catch (e) { $('status').textContent = 'network error: ' + e.message; }
}

document.querySelectorAll('[data-hold]').forEach(b => {
  b.addEventListener('pointerdown', () => sendCmd(b.dataset.hold, [speed()]));
  b.addEventListener('pointerup',   () => sendCmd(b.dataset.stop || 'ramp_pt_stop'));
  b.addEventListener('pointercancel', () => sendCmd(b.dataset.stop || 'ramp_pt_stop'));
});
document.querySelectorAll('[data-cmd]').forEach(b => {
  b.addEventListener('click', () => {
    if (b.classList.contains('danger') &&
        !confirm('Send ' + b.dataset.cmd + ' to the camera?')) return;
    sendCmd(b.dataset.cmd, b.dataset.args ? JSON.parse(b.dataset.args) : []);
  });
});
document.querySelectorAll('[data-ask]').forEach(b => {
  b.addEventListener('click', () => sendCmd(b.dataset.ask, [], true));
});

async function pollTelemetry() {
  if (selectedCam === null) return;
  try {
    const r = await fetch('/status');
    const cams = await r.json();
    const t = cams[selectedCam].telemetry || {};
    const lines = Object.entries(t).map(([k, v]) =>
      (EV_NAMES[k] || ('event' + k)) + ': ' + JSON.stringify(v));
    if (lines.length) $('telem').textContent = lines.join(String.fromCharCode(10));
  } catch (e) {}
}
setInterval(pollTelemetry, 2000);
'''

def build_index(cameras):
    cam_buttons = ''.join(
        f'<button class="cam-btn" data-idx="{i}" onclick="selectCam({i})">'
        f'{cam.name}</button>'
        for i, cam in enumerate(cameras)
    )
    html = f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>PTZ</title>
<style>
  body {{ background:#1e1e2e; color:#cdd6f4; font-family:sans-serif;
          max-width:520px; margin:40px auto; padding:0 20px; }}
  h1 {{ color:#89b4fa; font-size:1.1rem; letter-spacing:.05em; margin-bottom:4px; }}
  .cam-row {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:18px; }}
  .cam-btn {{ padding:8px 14px; border:2px solid #45475a; border-radius:6px;
              background:#313244; color:#cdd6f4; font-size:.9rem; cursor:pointer; }}
  .cam-btn.active {{ border-color:#89b4fa; background:#1e1e2e; color:#89b4fa;
                     font-weight:700; }}
  .row {{ display:flex; gap:10px; align-items:center; margin:14px 0; }}
  .row label {{ width:60px; color:#6c7086; font-size:.85rem; }}
  input[type=number] {{ flex:1; background:#313244; color:#cdd6f4;
                        border:1px solid #45475a; border-radius:4px;
                        padding:6px 8px; font-size:1rem; text-align:right; }}
  button.go {{ width:100%; padding:11px; border:none; border-radius:8px;
               background:#89b4fa; color:#1e1e2e; font-weight:700;
               font-size:1rem; cursor:pointer; margin-top:8px; }}
  button.go:active {{ background:#74c7ec; }}
  button.go.ok {{ background:#a6e3a1; }}
  #status {{ font-size:.8rem; color:#6c7086; margin-top:12px;
             min-height:1em; font-family:monospace; }}
  #selected-label {{ font-size:.85rem; color:#a6adc8; margin-bottom:6px; }}
.sec {{ color:#7fb3ff; font-weight:bold; margin:16px 0 6px; font-size:13px;
        text-transform:uppercase; letter-spacing:1px; }}
.pad {{ display:flex; flex-direction:column; align-items:center; gap:4px;
        margin:6px 0; }}
.padrow {{ display:flex; gap:4px; }}
.pbtn {{ width:52px; height:44px; font-size:18px; background:#1b2430;
         border:1px solid #345; color:#eee; border-radius:8px; cursor:pointer;
         touch-action:none; }}
.pbtn:active {{ background:#2c3e52; }}
.btnrow {{ display:flex; flex-wrap:wrap; gap:6px; margin:6px 0; }}
.abtn {{ background:#1b2430; border:1px solid #345; color:#eee;
         padding:8px 12px; border-radius:8px; cursor:pointer;
         touch-action:none; }}
.abtn:active {{ background:#2c3e52; }}
.abtn.danger {{ border-color:#a33; color:#f88; }}
#telem {{ background:#10161d; border:1px solid #234; padding:10px;
          border-radius:8px; font-size:12px; margin-top:12px;
          white-space:pre-wrap; }}
</style></head><body>
<h1>PTZ CONTROL</h1>
<div class="cam-row" id="cam-row">{cam_buttons}</div>
<div id="selected-label">No camera selected</div>
<div class="row"><label>Pan</label>
  <input type="number" id="pan" value="0" min="-10000" max="10000" step="1"></div>
<div class="row"><label>Tilt</label>
  <input type="number" id="tilt" value="0" min="-2500" max="2500" step="1"></div>
<div class="row"><label>Zoom</label>
  <input type="number" id="zoom" value="5000" min="1000" max="20000" step="100"></div>
<button class="go" id="go">Go</button>
{PANEL_HTML}
<div id="status">Select a camera above</div>
<script>
const $ = id => document.getElementById(id);
let selectedCam = {0 if cameras else 'null'};

function selectCam(idx) {{
  selectedCam = idx;
  document.querySelectorAll('.cam-btn').forEach((b,i) =>
    b.classList.toggle('active', i === idx));
  const names = {json.dumps([c.name for c in cameras])};
  $('selected-label').textContent = 'Controlling: ' + names[idx];
  $('status').textContent = 'ready';
}}

// auto-select first camera on load
selectCam(0);

$('go').onclick = async () => {{
  if (selectedCam === null) {{ $('status').textContent = 'Select a camera first'; return; }}
  const body = JSON.stringify({{
    cam: selectedCam,
    pan: +$('pan').value,
    tilt: +$('tilt').value,
    zoom: +$('zoom').value
  }});
  $('status').textContent = 'sending: ' + body;
  try {{
    const r = await fetch('/position', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body}});
    const t = await r.text();
    $('status').textContent = r.ok ? 'ok: ' + t : 'error ' + r.status + ': ' + t;
    $('go').classList.toggle('ok', r.ok);
    setTimeout(() => $('go').classList.remove('ok'), 500);
  }} catch (e) {{
    $('status').textContent = 'network error: ' + e.message;
  }}
}};
{PANEL_JS}
</script></body></html>
'''.encode('utf-8')
    return html

# ── HTTP handler ──────────────────────────────────────────────────────────────

def make_handler(cameras):
    index_html = build_index(cameras)

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def _send(self, code, body=b'', ctype='text/plain'):
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ('/', '/index.html'):
                self._send(200, index_html, 'text/html; charset=utf-8')
            elif self.path == '/status':
                body = json.dumps([{
                    'name':      cam.name,
                    'ip':        cam.ip,
                    'connected': cam.conn is not None,
                    'last_pos':  cam.last_pos,
                    'telemetry': {str(k): v for k, v in cam.telemetry.items()},
                } for cam in cameras]).encode()
                self._send(200, body, 'application/json')
            elif self.path == '/commands':
                body = json.dumps([
                    {'name': n, 'id': mid, 'args': spec}
                    for n, (mid, spec) in sorted(
                        doric.CMDS.items(), key=lambda kv: kv[1][0])
                    if n != 'subscribe'
                ], indent=1).encode()
                self._send(200, body, 'application/json')
            else:
                self._send(404, b'not found')

        def do_POST(self):
            if self.path not in ('/position', '/command'):
                self._send(404, b'not found'); return
            try:
                n = int(self.headers.get('Content-Length', 0))
                data = json.loads(self.rfile.read(n))
                idx = int(data.get('cam', 0))
                if idx < 0 or idx >= len(cameras):
                    self._send(400, f'cam index {idx} out of range (0–{len(cameras)-1})'.encode())
                    return
                if self.path == '/position':
                    cameras[idx].goto(data['pan'], data['tilt'], data['zoom'])
                    self._send(200, b'ok')
                    return
                cmd = data['cmd']
                if cmd not in doric.CMDS or cmd == 'subscribe':
                    self._send(400, f'unknown command: {cmd}'.encode()); return
                args = data.get('args', [])
                if cmd == 'configure':
                    if not isinstance(args, dict):
                        self._send(400, b'configure args must be a JSON object')
                        return
                    cameras[idx].cfg.update(args)
                    reply = cameras[idx].ask('configure', cameras[idx].cfg,
                                             timeout=8.0)
                    self._send(200, json.dumps(
                        {'cmd': cmd, 'config': cameras[idx].cfg,
                         'ack': reply}).encode(), 'application/json')
                elif cmd in doric.QUERY_EVENT:
                    reply = cameras[idx].ask(cmd)
                    self._send(200, json.dumps({'cmd': cmd, 'reply': reply}).encode(),
                               'application/json')
                else:
                    cameras[idx].command(cmd, args)
                    self._send(200, json.dumps({'cmd': cmd, 'sent': True}).encode(),
                               'application/json')
            except RuntimeError as e:
                self._send(503, str(e).encode())
            except Exception as e:
                self._send(400, f'{type(e).__name__}: {e}'.encode())
    return H

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--camera', required=True, nargs='+',
                    metavar='IP', help='one or more camera IP addresses')
    ap.add_argument('--names', nargs='+', metavar='NAME',
                    help='friendly names for each camera (must match --camera count)')
    ap.add_argument('--port', type=int, default=8080, help='HTTP port (default 8080)')
    args = ap.parse_args()

    names = args.names or []
    if names and len(names) != len(args.camera):
        ap.error(f'--names count ({len(names)}) must match --camera count ({len(args.camera)})')

    cameras = [
        Camera(ip, names[i] if i < len(names) else f'Camera {i+1}')
        for i, ip in enumerate(args.camera)
    ]

    for cam in cameras:
        threading.Thread(target=cam.run, daemon=True, name=f'cam-{cam.name}').start()

    srv = http.server.ThreadingHTTPServer(('', args.port), make_handler(cameras))
    cam_list = ', '.join(f'{c.name}={c.ip}' for c in cameras)
    print(f'[web] listening on :{args.port} ({cam_list})', flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        for cam in cameras:
            cam.alive = False
        print('\n[web] shutting down')

if __name__ == '__main__':
    main()
