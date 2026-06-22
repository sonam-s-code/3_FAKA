# web_3faka_server.py
# FastAPI UI for the 3FAKA demo (NFC + Fingerprint + Password).
# Non-interactive: no getpass, no terminal prompts.

import time
from typing import Dict, Tuple

import serial
from serial import SerialException
from serial.tools import list_ports

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

# ---- import NON-interactive building blocks from your CLI module ----
from finalthreeFAKA import (
    # core actors & helpers
    CS, DS, U, FuzzyExtractor,
    read_nfc, read_fingerprint, enroll_fingerprint,
    make_nfc_summary, write_nfc_summary,
    short_hash, SER_TIMEOUT, NFC_MAX_LEN,
    # simple password DB helpers
    gen_salt_hex, hash_password, verify_password,
)

# ---------------- Config ----------------
DEFAULT_PORT = "/dev/ttyACM0"
DEFAULT_BAUD = 115200

# Keep per-user state required by the protocol:
# We must reuse the same CS/DS/U objects at login that were created at register.
STATE_MODELS: Dict[str, Tuple[CS, DS, U]] = {}   # username -> (CS1, DS1, U1)
USER_DB: Dict[str, Dict] = {}                    # username -> {salt, pw_hash, nfc_uid}

# ---------------- BIO builder (stable across runs) ----------------
def make_bio16(fid: int, conf: int, mode: str = "fid_only") -> str:
    """
    Build a 16-char BIO string consistently for both register and login.

    mode = "fid_only"     -> use only fingerprint ID (most stable for demos)
         = "bucket_conf"  -> ID + confidence bucketed to 5s (adds a bit of entropy)
         = "raw"          -> ID + raw confidence (fragile; not recommended)
    """
    if mode == "fid_only":
        core = f"{fid:03d}"
    elif mode == "bucket_conf":
        buck = max(0, min(99, (conf // 5) * 5))
        core = f"{fid:03d}{buck:02d}"
    else:
        core = f"{fid:03d}{conf:03d}"
    return core.ljust(16, "0")[:16]

BIO_MODE = "fid_only"  # must match for register and login: "fid_only" | "bucket_conf" | "raw"

# ---------------- Serial helpers ----------------
def pick_port(requested: str) -> str:
    """Return a good port to try. If requested is empty or wrong, try an Arduino-like port."""
    req = (requested or "").strip()
    if req:
        return req
    for p in list_ports.comports():
        desc = (p.description or "").lower()
        if "arduino" in desc or "usb" in desc or "ch340" in desc:
            return p.device
    return DEFAULT_PORT

def open_serial_safe(port: str, baud: int, attempts: int = 2) -> serial.Serial:
    """Open COM port with a small retry. Always exclusive on Windows."""
    err = None
    for _ in range(attempts):
        try:
            ser = serial.Serial(
                port,
                baudrate=baud,
                timeout=SER_TIMEOUT,
                write_timeout=3,
                rtscts=False,
                dsrdtr=False,
            )
            time.sleep(0.35)
            ser.reset_input_buffer()
            return ser
        except (SerialException, PermissionError) as e:
            err = e
            time.sleep(1.2)  # let Windows release the handle
    raise SerialException(f"could not open port '{port}': {err}")

# ---------------- Registration (non-interactive) ----------------
def do_register(username: str, password: str, port: str, baud: int):
    logs = []
    def log(s): logs.append(s)

    # sanity
    username = (username or "").strip()
    password = (password or "")
    if not username or not password:
        return False, ["Username and password are required."]

    port = pick_port(port)
    baud = int(baud or DEFAULT_BAUD)

    # Build servers
    CS1 = CS(95)
    DS1 = DS(32)
    log("========== REGISTER ==========")
    log("[Figure 4.1 – Central Server]")
    log("Compute for DS registration:")
    try:
        Sk, tk, PKdsk = CS1.DS_reg(DS1.ID)
        DS1.reg_authentication(Sk, tk, PKdsk, CS1.ID)
        log("Domain server registration completed.   (Fig. 4.1)")
    except Exception as e:
        log(f"❌ DS registration failed: {e}")
        return False, logs

    # Serial section: open, read NFC, fingerprint (with enroll on first failure)
    ser = None
    try:
        log("Tap your NFC card for user registration ...")
        ser = open_serial_safe(port, baud)
        uid, _ = read_nfc(ser)
        log(f"🆔 NFC UID: {hex(uid)}")

        log("Place your finger for user registration ...")
        fid, conf = read_fingerprint(ser, retries=1)
        if fid is None:
            new_id = (uid % 127) or 1
            log(f"No match; enrolling fingerprint with ID {new_id} ...")
            if not enroll_fingerprint(ser, new_id):
                raise RuntimeError("Fingerprint enrollment failed.")
            log("Scan again to verify ...")
            fid, conf = read_fingerprint(ser, retries=1)
            if fid is None:
                raise RuntimeError("Fingerprint read failed after enrollment.")

        bio16 = make_bio16(fid, conf, mode=BIO_MODE)

        # User side (per paper: ID_i = username, PW_i = password)
        U1 = U(username, password, FuzzyExtractor(16, 8))
        U_ID, U_FV, U_gamma = U1.get_reg_data(bio16)
        U1.create_SC(*CS1.U_reg(U_ID, U_FV, U_gamma))
        log("User registration completed.           (Fig. 4.2)")

        # Store credentials + models for this user
        salt = gen_salt_hex(16)
        USER_DB[username] = {"salt": salt, "pw_hash": hash_password(password, salt), "nfc_uid": uid}
        STATE_MODELS[username] = (CS1, DS1, U1)

        # Clear UI fields instruction & success message (consumed by the client)
        log("")
        log("✅ Successfully registered.")
        log("Please re-enter your Username & Password, then press 'Login'.")
        log("During login, you will be prompted to tap the NFC card and place your finger.")
        return True, logs

    except Exception as e:
        logs.append(f"❌ ERROR: {e}")
        return False, logs
    finally:
        if ser:
            try: ser.close()
            except: pass

# ---------------- Login (non-interactive) ----------------
def do_login(username: str, password: str, port: str, baud: int):
    logs = []
    def log(s): logs.append(s)

    username = (username or "").strip()
    password = (password or "")
    if not username or not password:
        return False, ["Username and password are required."]

    # validate credentials
    rec = USER_DB.get(username)
    if not rec or not verify_password(password, rec["salt"], rec["pw_hash"]):
        return False, ["Invalid username or password."]

    cs_ds_u = STATE_MODELS.get(username)
    if not cs_ds_u:
        return False, ["No server state for this user. (Register again in this session.)"]
    CS1, DS1, U1 = cs_ds_u

    port = pick_port(port)
    baud = int(baud or DEFAULT_BAUD)

    ser = None
    try:
        log("=========== LOGIN ===========")
        ser = open_serial_safe(port, baud)

        log("Tap your NFC card to login ...")
        lu, _ld = read_nfc(ser)
        if rec["nfc_uid"] != lu:
            raise RuntimeError("NFC UID mismatch.")
        log("NFC ✓")

        log("Place your finger to login ...")
        lfid, lconf = read_fingerprint(ser, retries=5)
        if lfid is None:
            raise RuntimeError("Fingerprint not recognized.")
        login_bio16 = make_bio16(lfid, lconf, mode=BIO_MODE)

        # ---- Figure 4.3: steps 1–6 ----
        try:
            L1, Tu1_val = U1.authentication_1(username, password, login_bio16, DS1.PK, CS1.ID, DS1.ID)
            L2, Ts1_val = DS1.authentication_2(L1, Tu1_val)
            a, b, d = CS1.authentication_3(L2, Ts1_val)
            one, two, three = DS1.authentication_4(a, b, d)
            M3 = U1.authentication_5(one, two, three)
            DS1.authentication_6(M3)
        except SystemExit as e:
            logs.append(f"❌ Biometric reproduce failed: {e}")
            logs.append("Hint: Use the same finger as registration. "
                        "For a robust demo, the server uses BIO_MODE='fid_only'.")
            return False, logs

        # Write short summary to NFC
        summary = make_nfc_summary(username, lu, U1.last_session_key, max_len=NFC_MAX_LEN)
        log(f"Saving to NFC (≤{NFC_MAX_LEN}B): {summary}")
        ok = write_nfc_summary(ser, summary, retries=3)

        # Verify by reading back
        log("Verifying write by reading back...")
        back_uid, back_data = read_nfc(ser)
        log(f"Read-back UID={hex(back_uid)} | Data='{back_data}'")
        if ok and (short_hash(U1.last_session_key, 8) in back_data
                   or short_hash(U1.last_session_key, 12) in back_data
                   or short_hash(U1.last_session_key, 16) in back_data):
            log("✅ NFC contains the latest session summary.")
        elif ok:
            log("⚠️ Write reported success but card shows different data.")
        else:
            log("❌ Write failed; card still has previous data.")

        log("")  # spacing
        log("🎉 Login successful.")
        return True, logs

    except Exception as e:
        logs.append(f"❌ ERROR: {e}")
        # add hint for busy COM port
        if isinstance(e, SerialException) and "could not open port" in str(e).lower():
            logs.append("Hint: close Arduino Serial Monitor/Plotter and stop any other programs using this COM port. "
                        "If the server crashed previously, unplug/replug the board and try again.")
        return False, logs
    finally:
        if ser:
            try: ser.close()
            except: pass

# ---------------- FastAPI app & routes ----------------
app = FastAPI()

INDEX_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Three-Factor Auth (NFC + Fingerprint + Password)</title>
  <style>
    body { background:#0f172a; color:#e2e8f0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, 'Noto Sans', Arial; }
    .wrap { max-width: 1080px; margin: 30px auto; display:flex; gap:24px; }
    .card { background:#111827; border:1px solid #1f2937; border-radius:12px; padding:16px; }
    .left { width: 360px; }
    .right { flex:1; min-height: 520px; }
    label { display:block; margin-top:12px; margin-bottom:6px; font-size: 14px; color:#a5b4fc; }
    input, select { width:100%; padding:10px 12px; border-radius:10px; border:1px solid #374151; background:#0b1220; color:#e5e7eb; }
    .btns { display:flex; gap:10px; margin-top:16px; }
    button { padding:10px 14px; border-radius:10px; border:1px solid #374151; background:#1f2937; color:#e5e7eb; cursor:pointer; }
    button:hover { background:#334155; }
    pre { white-space:pre-wrap; word-break:break-word; font-size:13px; line-height:1.25; }
    h1 { margin:0 0 8px 0; font-size:18px; color:#93c5fd; }
    .muted { color:#94a3b8; font-size:12px; margin-top:10px; }
    .top { display:flex; align-items:center; gap:8px; margin-bottom:10px; }
    .tag { font-size:12px; border:1px solid #334155; background:#0b1220; color:#93c5fd; padding:2px 6px; border-radius:6px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card left">
      <div class="top">
        <span class="tag">Web UI</span>
        <h1>Three-Factor Auth (NFC + Fingerprint + Password)</h1>
      </div>

      <label>Arduino Port</label>
      <div style="display:flex; gap:8px;">
        <input id="port" value="/dev/ttyACM0"/>
        <button onclick="listPorts()">List</button>
      </div>

      <label>Baud</label>
      <input id="baud" value="115200"/>

      <hr style="border:none; border-top:1px solid #1f2937; margin:16px 0;">

      <label>Username</label>
      <input id="user" placeholder="e.g., alice"/>

      <label>Password</label>
      <input id="pass" type="password" placeholder="••••••••"/>

      <div class="btns">
        <button id="btn-register" onclick="go('register')">Register</button>
        <button id="btn-login" onclick="go('login')">Login</button>
      </div>

      <div class="muted">
        Tip: Keep the Arduino powered and your PN532 + sensor ready. <br>
        The UI will prompt you (tap card / place finger) via the log.
      </div>
    </div>

    <div class="card right">
      <pre id="log">Waiting…</pre>
    </div>
  </div>

<script>
let mustReenter = false;

function appendLog(lines) {
  const el = document.getElementById('log');
  el.textContent = Array.isArray(lines) ? lines.join('\\n') : String(lines);
}

function getCreds() {
  return {
    username: document.getElementById('user').value,
    password: document.getElementById('pass').value,
    port:     document.getElementById('port').value,
    baud:     document.getElementById('baud').value
  };
}

async function go(which) {
  const url = which === 'register' ? '/api/register' : '/api/login';
  const payload = getCreds();
  appendLog(`${which.toUpperCase()}…`);

  if (which === 'login' && mustReenter && (!payload.username || !payload.password)) {
    appendLog([
      'Please re-enter your Username & Password, then click "Login".',
      'Tip: The fields were cleared after registration for security.'
    ]);
    return;
  }

  try {
    const r = await fetch(url, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const j = await r.json();

    // After successful registration: clear fields and require re-entry
    if (which === 'register' && j.ok) {
      document.getElementById('user').value = '';
      document.getElementById('pass').value = '';
      mustReenter = true;
      appendLog([
        ...j.logs,
        '',
        '📝 Please re-enter a valid Username & Password, then click "Login".',
        'You will be prompted to tap the NFC card and place your finger.'
      ]);
      return;
    }

    // On successful login, we can reset the re-entry requirement
    if (which === 'login' && j.ok) {
      mustReenter = false;
    }

    appendLog(j.logs || ['(no logs)']);
  } catch (e) {
    console.error(e);
    appendLog(['Request failed:', String(e)]);
  }
}

async function listPorts() {
  try {
    const r = await fetch('/api/ports');
    const j = await r.json();
    appendLog(['Detected serial ports:', ...j.ports]);
  } catch (e) {
    console.error(e);
    appendLog(['Failed to list ports:', String(e)]);
  }
}
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML

@app.get("/api/ports")
def api_ports():
    ports = [f"{p.device} — {p.description}" for p in list_ports.comports()]
    return {"ports": ports}

@app.post("/api/register")
async def api_register(payload: dict):
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    port     = str(payload.get("port", DEFAULT_PORT))
    baud     = int(payload.get("baud", DEFAULT_BAUD))

    ok, logs = do_register(username, password, port, baud)
    return JSONResponse({"ok": ok, "logs": logs})

@app.post("/api/login")
async def api_login(payload: dict):
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    port     = str(payload.get("port", DEFAULT_PORT))
    baud     = int(payload.get("baud", DEFAULT_BAUD))

    ok, logs = do_login(username, password, port, baud)
    return JSONResponse({"ok": ok, "logs": logs})
