#!/usr/bin/env python3
"""
Provision a Cisco TTC8-07 camera by replaying a captured codec session.

Usage:
    ./provision.py <camera_ip>

Reads cppmf_session.bin and doric_session.bin from ./data/ and streams them
to the camera over TLS. Effectively impersonates the codec that was captured,
installing its identity and firmware on the target camera. Camera will reboot
after the install completes (~2 minutes upload + ~1 minute reboot).

After this completes the camera is bound to the captured codec's identity —
i.e. anyone with the same BLOBs (in server.py) can control it.
"""
import os, socket, ssl, sys, threading, time

CPPMF_PORT = 13491
DORIC_PORT = 13496
DATA_DIR   = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')

def log(label, msg):
    print(f'[{time.strftime("%H:%M:%S")}] [{label}] {msg}', flush=True)

def tls_connect(ip, port):
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
    raw.settimeout(10)
    raw.connect((ip, port))
    return ctx.wrap_socket(raw, server_hostname=ip)

def drain(sock, label, stop_evt):
    """Read replies from camera into the void (just to keep TCP flowing)."""
    total = 0
    while not stop_evt.is_set():
        sock.settimeout(0.5)
        try:
            d = sock.recv(8192)
            if not d:
                log(label, f'EOF after {total}B drained')
                return
            total += len(d)
        except socket.timeout:
            continue
        except ssl.SSLWantReadError:
            continue
        except OSError:
            return
    log(label, f'drained {total}B from camera')

def replay(ip, port, fname, label, settle_secs):
    path = os.path.join(DATA_DIR, fname)
    if not os.path.exists(path):
        log(label, f'MISSING DATA FILE: {path}')
        return
    with open(path, 'rb') as f:
        data = f.read()
    log(label, f'connecting {ip}:{port}')
    try:
        c = tls_connect(ip, port)
    except Exception as e:
        log(label, f'TLS connect FAILED: {type(e).__name__}: {e}')
        return
    log(label, f'TLS up {c.version()} — streaming {len(data):,} bytes')

    stop = threading.Event()
    threading.Thread(target=drain, args=(c, label, stop), daemon=True).start()

    sent = 0; chunk = 65536; last_log = 0; t0 = time.time()
    while sent < len(data):
        try:
            sent += c.send(data[sent:sent+chunk])
        except Exception as e:
            log(label, f'send error at {sent}/{len(data)}: {type(e).__name__}: {e}')
            break
        if sent - last_log >= 5_000_000 or sent == len(data):
            mb = sent / 1_048_576
            log(label, f'  {sent:,}/{len(data):,} ({100*sent/len(data):.1f}%) {mb:.1f}MB @ {mb/max(time.time()-t0,0.001):.1f}MB/s')
            last_log = sent

    log(label, f'all bytes sent — settling {settle_secs}s')
    time.sleep(settle_secs)
    stop.set()
    try: c.close()
    except: pass
    log(label, 'session done')

def main():
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(1)
    ip = sys.argv[1]
    log('main', f'==> provisioning {ip}')
    log('main', 'this takes ~2 minutes and the camera will reboot when done')

    cppmf_t = threading.Thread(
        target=replay,
        args=(ip, CPPMF_PORT, 'cppmf_session.bin', 'cppmf', 120),
        daemon=True,
    )
    cppmf_t.start()
    time.sleep(2)  # let CPPMF establish first
    replay(ip, DORIC_PORT, 'doric_session.bin', 'doric', settle_secs=30)
    log('main', 'replay complete. wait ~60s for reboot, then test with server.py')

if __name__ == '__main__':
    main()
