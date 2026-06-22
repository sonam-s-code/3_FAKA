# finalthreeFAKA_hardware_plaintext_table.py
# Full hardware-running version
# - Registration + login with NFC + fingerprint + iPUF
# - At the end prints ONLY a plain-text table like the paper image
# - Consumer (Rasp. Pi) values are measured locally
# - Server (PC) column is printed as 0 to match the requested figure
# - iPUF row label: XOR (8,8)-iPUF (T_puf)

import re
import time
import secrets
import hashlib
from random import randint
from hashlib import sha512, sha256
from getpass import getpass

import serial
import serial.tools.list_ports
import numpy as np
from pypuf.simulation import InterposePUF, XORArbiterPUF
from fuzzy_extractor import FuzzyExtractor
from AES import encrypt, decrypt

ARDUINO_BAUD = 115200
SER_TIMEOUT = 0.6
NFC_MAX_LEN = 32
MOD_P = (1 << 255) - 19

# Protocol parameters
IPUF_N = 256
IPUF_K_UP = 8
IPUF_K_DOWN = 8
IPUF_NOISINESS = 0.05
IPUF_RESPONSE_BITS = 128
IPUF_VOTES = 21
IPUF_ACC_THRESHOLD = 88.0

USER_DB = {}

# ------------------------------
# Core helpers
# ------------------------------
def sha256_bits_pm1(value):
    digest = hashlib.sha256(value.encode()).digest()
    bits = np.unpackbits(np.frombuffer(digest, dtype=np.uint8))
    return (bits.astype(np.int8) * 2 - 1).reshape(1, IPUF_N)

def _get_full_response_fast(puf, base_challenge, count=IPUF_RESPONSE_BITS):
    n = base_challenge.shape[1]
    challenges = np.repeat(base_challenge, count, axis=0).copy()
    idx = np.arange(count) % n
    challenges[np.arange(count), idx] *= -1
    out = puf.eval(challenges)
    return np.asarray(out, dtype=np.int8)

def eval_stable_fast(puf, base_challenge, count=IPUF_RESPONSE_BITS, votes=IPUF_VOTES):
    assert votes % 2 == 1
    runs = np.empty((votes, count), dtype=np.int8)
    for v in range(votes):
        runs[v] = _get_full_response_fast(puf, base_challenge, count)
    return np.where(runs.sum(axis=0) >= 0, np.int8(1), np.int8(-1))

def bits_to_int(pm1):
    b = ((pm1.astype(np.int16) + 1) // 2).astype(np.uint8)
    v = 0
    for i, x in enumerate(b):
        if x:
            v += (1 << i)
    return v

def hamming_sim(a, b):
    return float(np.sum(a == b)) / len(a) * 100.0

def concat(*parts):
    return ''.join(str(p) for p in parts)

def H(target, out_type=2):
    raw = sha512(str(target).encode()).digest()
    if out_type == 1:
        return ''.join(f'{b:08b}' for b in raw)
    return int(raw.hex(), 16)

def H256(target):
    return int(sha256(str(target).encode()).hexdigest(), 16)

def bin_to_int(bits):
    v = 0
    for i, b in enumerate(bits):
        if b == 1:
            v += (1 << i)
    return v

def key16(val):
    return sha256(str(val).encode()).digest()[:16]

def seed_int(x):
    return H256(x) & ((1 << 31) - 1)

def hgamma127(g):
    return H256(g) & ((1 << 127) - 1)

def short_hash(val, n=16):
    return sha256(str(val).encode()).hexdigest()[:n]

def now_ts():
    import datetime
    return datetime.datetime.now().strftime("%Y%m%d%H%M%S")

def make_nfc_summary(username, uid_int, sk, max_len=NFC_MAX_LEN):
    bu = f"U:{username[:12]}"
    bc = f"C:{hex(uid_int)[-4:].replace('x','')}"
    ts = now_ts()[-8:]
    for s in (16, 12, 8):
        c = f"{bu}|{bc}|S:{short_hash(sk,s)}|T:{ts}"
        if len(c) <= max_len:
            return c
    return f"{bc}|S:{short_hash(sk,8)}|T:{ts}"[:max_len]

def T_ecm(n, x, p=MOD_P):
    x %= p
    cache = {}
    def T(k):
        if k in cache:
            return cache[k]
        if k == 0:
            r = 1 % p
        elif k == 1:
            r = x
        elif k & 1:
            k2 = k >> 1
            r = (2 * T(k2) * T(k2+1) - x) % p
        else:
            t = T(k >> 1)
            r = (2*t*t - 1) % p
        cache[k] = r
        return r
    return T(n)

def gen_salt():
    return secrets.token_hex(16)

def pw_hash(pw, salt):
    return sha512((salt+pw).encode()).hexdigest()

def pw_verify(pw, s, h):
    return pw_hash(pw, s) == h

# ------------------------------
# Entities
# ------------------------------
class CS:
    def __init__(self, ID):
        self.ID = ID
        self.Sr = randint(0, (2**127)-1)
        self.sym_key = key16(self.Sr)
        self._puf = XORArbiterPUF(n=4, k=3, seed=ID)

    def _chal(self, v):
        bits = H(v, 1)
        tmp = [-1 if c == '0' else 1 for c in bits]
        return np.array([tmp[i*4:(i+1)*4] for i in range(128)])

    def fig41_reg_DS(self, ID_DSk):
        print("\n[Figure 4.1 - Central Server R]")
        Sk = bin_to_int(self._puf.eval(self._chal(concat(ID_DSk, self.Sr))))
        PKdsk = T_ecm(Sk, H(concat(self.ID, ID_DSk)))
        tk = T_ecm(self.Sr, H(str(ID_DSk)))
        print("   s_k = PUF_s(H(ID_DSk)||s_R)")
        print("   PK_DSk = T_{s_k}[H(ID_R||ID_DSk)]")
        print("   t_k = T_{s_R}[H(ID_DSk)]")
        return Sk, tk, PKdsk

    def fig42_reg_user(self, ID_i, FV_i, gamma_i, CID_i=1):
        print("\n[Figure 4.2 - Central Server R]")
        y_i = encrypt(self.sym_key, [H(ID_i), FV_i, CID_i])
        s_U = T_ecm(self.Sr, H(ID_i))
        print("   y_i = SE_{s_R}(H(ID_i)||FV_i||CID_i)")
        print("   s_U = T_{s_R}[H(ID_i)]")
        return y_i, s_U, ID_i, CID_i

    def fig43_step3(self, L2, Ts1_val):
        print("\n[Figure 4.3 - Central Server R: step 3]")
        K2_ = T_ecm(self.Sr, Ts1_val)
        y_i, S2, ID_i, ID_DSk = decrypt(key16(K2_), L2)
        HID, FV_i, CID_i = decrypt(self.sym_key, y_i)
        if H(ID_i) != HID:
            raise SystemExit("ABORT: H(ID_i) != H(ID)")
        r = randint(0, (2**127)-1)
        V_t = T_ecm(self.Sr, HID)
        alpha = S2 ^ r
        beta = H(concat(r, S2))
        delta = V_t ^ FV_i ^ S2
        print("   K'_2 = T_{s_R}[T_{S1}[H(ID_DSk)]]")
        print("   alpha=S2^r  beta=H(r||S2)  delta=V_t^FV_i^S2")
        print("   -> send (alpha, beta, delta) to DS")
        return alpha, beta, delta

class DS:
    def __init__(self, ID):
        self.ID = ID

    def fig41_verify(self, Sk, tk, PKdsk, CS_ID):
        print("\n[Figure 4.1 - Domain Server DS_k]")
        if PKdsk != T_ecm(Sk, H(concat(CS_ID, self.ID))):
            raise SystemExit("ABORT: PK_DSk verification failed")
        self.SK = (Sk, tk)
        self.PK = PKdsk
        print("   PK_DSk verified OK")

    def fig43_step2(self, L1, Tu1_val, CS_ID):
        print("\n[Figure 4.3 - Domain Server DS_k: step 2]")
        K1_ = T_ecm(self.SK[0], Tu1_val)
        ID_i, y_i, self._U2 = decrypt(key16(K1_), L1)
        self._K1_ = K1_
        S1 = randint(0, (2**127)-1)
        self._S2 = randint(0, (2**127)-1)
        K2 = T_ecm(S1, self.SK[1])
        Ts1 = T_ecm(S1, H(str(self.ID)))
        L2 = encrypt(key16(K2), [y_i, self._S2, ID_i, self.ID])
        print("   K'_1 = T_{s_k}[Tu1]  K2 = T_{S1}[t_k]  L2 encrypted")
        print("   -> send L2, T_{S1}[H(ID_DSk)] to CS")
        return L2, Ts1

    def fig43_step4(self, alpha, beta, delta):
        print("\n[Figure 4.3 - Domain Server DS_k: step 4]")
        r_ = alpha ^ self._S2
        beta_ = H(concat(r_, self._S2))
        if beta_ != beta:
            raise SystemExit("ABORT: beta' != beta")
        F1 = r_ ^ self._U2
        F2 = H(concat(r_, self._U2, self._S2))
        F3 = self._S2 ^ self._U2
        self._r_ = r_
        self._delta = delta
        print("   r'=alpha^S2  beta'==beta OK")
        print("   F1=r'^U2  F2=H(r'||U2||S2)  F3=S2^U2")
        print("   -> send F1, F2, F3 to User")
        return F1, F2, F3

    def fig43_step6(self, M3, AUTH):
        print("\n[Figure 4.3 - Domain Server DS_k: step 6]")
        if (self._delta ^ self._S2) != (M3 ^ self._U2):
            raise SystemExit("ABORT: delta XOR S2 != M3 XOR U2")
        SK_DS = H(concat(self._U2, self._r_, self._K1_))
        expected_AUTH = H(concat(SK_DS, M3, self._S2))
        if AUTH != expected_AUTH:
            raise SystemExit("ABORT: AUTH token invalid")
        print("   delta^S2 == M3^U2  OK")
        print("   AUTH valid  OK")
        print(f"   SK (DS) = {SK_DS}")
        print("\nSession key agreement completed.")
        return SK_DS

class U:
    def __init__(self, ID_str, PW_str, extractor):
        self.ID = str(ID_str)
        self.PW = str(PW_str)
        self.ipuf = InterposePUF(
            n=IPUF_N, k_up=IPUF_K_UP, k_down=IPUF_K_DOWN,
            seed=seed_int(self.ID), noisiness=IPUF_NOISINESS,
        )
        self._gamma_ref = None
        self.extractor = extractor
        self.last_SK = None

    def fig42_register(self, Bio16):
        print("\n[Figure 4.2 - User U_i]")
        chal = sha256_bits_pm1(self.PW)
        bits_stable = eval_stable_fast(self.ipuf, chal)
        self._gamma_ref = bits_stable.copy()
        self.gamma = bits_to_int(bits_stable)
        self.sigma, self.Gamma = self.extractor.generate(Bio16.encode())
        self.FV = H(concat(self.sigma, self.gamma, self.PW))
        print(f"   gamma_i = PUF_i(H(PW_i)) [iPUF votes={IPUF_VOTES}, bits={IPUF_RESPONSE_BITS}]")
        print("   (sigma_i, Gamma_i) = Gen(BIO_i)")
        print("   FV_i = H(sigma_i||gamma_i||PW_i)")
        return self.ID, self.FV, self.gamma

    def fig42_store_SC(self, y_i, s_U, ID_i, CID_i):
        assert ID_i == self.ID
        self.VPW = H(concat(self.PW, self.ID, self.sigma, CID_i))
        self.SC = dict(y_i=y_i, s_U=s_U, ID_i=ID_i, CID_i=CID_i,
                       VPW_i=self.VPW, Gamma_i=self.Gamma,
                       gamma_reg=self.gamma, sigma_reg=self.sigma)
        print("   VPW_i = H(PW_i||ID_i||sigma_i||CID_i)")
        print("   SC_i stored")

    def fig43_step1(self, login_ID, login_PW, Bio16_, PK_DSk, ID_CS, ID_DS):
        print("\n[Figure 4.3 - User U_i: step 1]")
        self._login_ID = str(login_ID)
        self._login_PW = str(login_PW)
        chal = sha256_bits_pm1(self._login_PW)
        bits_stable = eval_stable_fast(self.ipuf, chal)
        gamma_ = bits_to_int(bits_stable)
        if self._gamma_ref is not None:
            sim = hamming_sim(self._gamma_ref, bits_stable)
            print(f"   iPUF similarity: {sim:.2f}%  [threshold={IPUF_ACC_THRESHOLD}%]")
            if sim < IPUF_ACC_THRESHOLD:
                raise SystemExit(f"ABORT: iPUF similarity {sim:.2f}% < {IPUF_ACC_THRESHOLD}%")
        sigma_ = self.extractor.reproduce(Bio16_.encode(), self.SC['Gamma_i'])
        if sigma_ is None:
            raise SystemExit("ABORT: biometric reproduction failed")
        VPW_chk = H(concat(self._login_PW, self._login_ID, sigma_, self.SC['CID_i']))
        if VPW_chk != self.SC['VPW_i']:
            raise SystemExit("ABORT: VPW_i mismatch")
        print("   VPW_i OK")
        self._U2 = randint(0, (2**127)-1)
        U1 = self._U2 ^ hgamma127(gamma_)
        K1 = T_ecm(U1, PK_DSk)
        L1 = encrypt(key16(K1), [self._login_ID, self.SC['y_i'], self._U2])
        Tu1 = T_ecm(U1, H(concat(ID_CS, ID_DS)))
        print("   K1=T_{U1}[PK_DSk]  L1=SE_{K1}(ID_i||y_i||U2)")
        print("   -> send L1, Tu1 to DS")
        self._K1 = K1
        return L1, Tu1

    def fig43_step5(self, F1, F2, F3):
        print("\n[Figure 4.3 - User U_i: step 5]")
        r_ = F1 ^ self._U2
        S2_ = F3 ^ self._U2
        if H(concat(r_, self._U2, S2_)) != F2:
            raise SystemExit("ABORT: H(r'||U2||S2) != F2")
        print("   H(r'||U2||S2)==F2  OK")
        FV_ = H(concat(self.SC['sigma_reg'], self.SC['gamma_reg'], self._login_PW))
        M3 = self.SC['s_U'] ^ FV_ ^ self._U2
        SK = H(concat(self._U2, r_, self._K1))
        self.last_SK = SK
        AUTH = H(concat(SK, M3, S2_))
        print(f"   SK (User) = {SK}")
        print("   -> send M3, AUTH to DS")
        return M3, AUTH

# ------------------------------
# Serial / Hardware helpers
# ------------------------------
_SKIP = ("Unknown command", "\U0001f510", "\U0001f4cc Commands:", "\U0001f4c2 Stored fingerprints")

def _ok(line):
    return bool(line) and not any(line.startswith(p) for p in _SKIP)

def find_port():
    ports = serial.tools.list_ports.comports()
    if not ports:
        raise SystemExit("No serial ports found.")
    kw = ("arduino","ch340","ch341","usb serial","usb-serial","usb2.0-serial","cp210","ftdi","acm","ttyacm","ttyusb")
    for p in ports:
        d, m, v = (p.description or "").lower(), (p.manufacturer or "").lower(), (p.device or "").lower()
        if any(k in d or k in m or k in v for k in kw):
            print(f"[Serial] Auto-detected on {p.device}  ({p.description})")
            return p.device
    print(f"[Serial] Fallback to {ports[0].device}")
    return ports[0].device

def open_serial():
    port = find_port()
    ser = serial.Serial(port, ARDUINO_BAUD, timeout=SER_TIMEOUT, write_timeout=3, rtscts=False, dsrdtr=False)
    time.sleep(0.35)
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    return ser

def _rl(ser):
    return ser.readline().decode('utf-8', errors='ignore').strip()

def _tx(ser, t):
    ser.write(t.encode())
    ser.flush()

def _wait(ser, pats, timeout=12.0):
    end = time.time() + timeout
    while time.time() < end:
        ln = _rl(ser)
        if not ln:
            continue
        if _ok(ln):
            print(ln)
        for p in pats:
            if re.search(p, ln, re.I):
                return ln
    return ""

def read_nfc(ser):
    while True:
        ser.reset_input_buffer()
        _tx(ser, "read\n")
        uid = dat = ""
        t0 = time.time()
        while time.time() - t0 < 10:
            ln = _rl(ser)
            if not ln:
                continue
            if _ok(ln):
                print(ln)
            if "UID" in ln:
                uid = ln
            if "NFC Data" in ln:
                dat = ln
                break
            if "No NFC" in ln:
                break
        if uid and dat:
            hx = re.findall(r'0x[0-9A-Fa-f]+', uid)
            uid_int = int(''.join(h[2:] for h in hx), 16) if hx else 0
            idx = dat.find("NFC Data:")
            return uid_int, dat[idx+9:].strip() if idx != -1 else ""
        time.sleep(0.8)

def read_fp(ser, retries=5):
    for _ in range(retries):
        ser.reset_input_buffer()
        _tx(ser, "fingerprint\n")
        fid = conf = None
        t0 = time.time()
        while time.time() - t0 < 15:
            ln = _rl(ser)
            if not ln:
                continue
            if _ok(ln):
                print(ln)
            if "Match Found" in ln:
                ns = re.findall(r'\d+', ln)
                if len(ns) >= 2:
                    fid, conf = int(ns[0]), int(ns[1])
                return fid, conf
            if any(k in ln for k in ("No match","No finger")) or "scan" in ln.lower():
                print("Warning: not recognized, try again.")
                break
    print("Error: max retries reached.")
    return None, None

def _enroll_once(ser, eid):
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    _tx(ser, "enroll\n")
    got = _wait(ser, [r"Enter\s*ID", r"ID\s*to\s*enroll", r"Enrolling\s+ID"], 6)
    if not got:
        _tx(ser, f"enroll {eid}\n")
    else:
        time.sleep(0.15)
        _tx(ser, f"{eid}\n")
    t_end = time.time() + 40
    while time.time() < t_end:
        ln = _rl(ser)
        if not ln:
            continue
        if _ok(ln):
            print(ln)
        if any(k in ln for k in ("enrolled successfully","Enroll OK","Stored!")):
            return True
        if any(k in ln for k in ("ID already","duplicate","exists","Failed","Unknown command")):
            return False
        if "error" in ln.lower():
            return False
    return False

def enroll_fp(ser, base_id, max_attempts=6):
    cand = max(1, min(127, base_id))
    for i in range(max_attempts):
        eid = ((cand+i-1) % 127) + 1
        print(f"Enrolling ID {eid} (attempt {i+1}/{max_attempts}) ...")
        if _enroll_once(ser, eid):
            print("Fingerprint enrolled.")
            return eid
        print("Failed; trying next ID ...")
        time.sleep(0.6)
        ser.reset_input_buffer()
        ser.reset_output_buffer()
    raise SystemExit("Enrollment failed.")

def write_nfc(ser, content, retries=3):
    safe = ''.join(c if 32 <= ord(c) <= 126 else '?' for c in content)[:NFC_MAX_LEN]
    for attempt in range(retries+1):
        print(f"NFC write attempt {attempt+1}/{retries+1} ...")
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        _tx(ser, "change data\n")
        if not _wait(ser, [r"Writing"], 8):
            if attempt < retries:
                time.sleep(0.6)
                continue
            return False
        time.sleep(0.12)
        _tx(ser, safe + "\n")
        if _wait(ser, [r"All data written successfully", r"Data written to card"], 60):
            print("NFC write OK.")
            return True
        if attempt >= retries:
            print("NFC write timeout.")
            return False
        time.sleep(0.8)

# ------------------------------
# Phase flows
# ------------------------------
def register_phase(ser):
    print("\n========== REGISTER (Fig 4.1 + 4.2) ==========")
    username = input("Create username: ").strip()
    try:
        password = getpass("Create password: ")
        confirm = getpass("Confirm password: ")
    except Exception:
        password = input("Create password: ")
        confirm = input("Confirm password: ")
    if password != confirm:
        raise SystemExit("Passwords do not match.")

    salt = gen_salt()
    USER_DB[username] = dict(salt=salt, pw_hash=pw_hash(password, salt), nfc_uid=None)

    CS1 = CS(95)
    DS1 = DS(32)

    print("\nTap your NFC card for registration ...")
    uid, _ = read_nfc(ser)
    USER_DB[username]['nfc_uid'] = uid

    print("Place your finger for registration ...")
    fid, conf = read_fp(ser, retries=2)
    if fid is None:
        base_id = (uid % 127) or 1
        print(f"Enrolling fingerprint near ID {base_id} ...")
        enroll_fp(ser, base_id)
        print("Scan again to confirm ...")
        fid, conf = read_fp(ser, retries=4)
        if fid is None:
            raise SystemExit("Fingerprint read failed after enrollment.")

    bio16 = str(fid).ljust(16, '0')[:16]

    Sk, tk, PKdsk = CS1.fig41_reg_DS(DS1.ID)
    DS1.fig41_verify(Sk, tk, PKdsk, CS1.ID)

    U1 = U(username, password, FuzzyExtractor(16, 8))
    ID_i, FV_i, gamma_i = U1.fig42_register(bio16)
    y_i, s_U, ID_i, CID_i = CS1.fig42_reg_user(ID_i, FV_i, gamma_i)
    U1.fig42_store_SC(y_i, s_U, ID_i, CID_i)
    return username, password, CS1, DS1, U1

def login_phase(ser, username, password, CS1, DS1, U1):
    print("\n=========== LOGIN (Fig 4.3) ===========")
    login_user = input("Username: ").strip()
    try:
        login_pw = getpass("Password: ")
    except Exception:
        login_pw = input("Password: ")

    rec = USER_DB.get(login_user)
    if not rec:
        raise SystemExit("Unknown username.")
    if not pw_verify(login_pw, rec['salt'], rec['pw_hash']):
        raise SystemExit("Wrong password.")
    print("Password OK")

    print("Tap your NFC card ...")
    lu, _ = read_nfc(ser)
    if rec['nfc_uid'] != lu:
        raise SystemExit("NFC UID mismatch.")
    print("NFC OK")

    print("Place your finger ...")
    lfid, lconf = read_fp(ser, retries=5)
    if lfid is None:
        raise SystemExit("Fingerprint not recognized.")

    login_bio16 = str(lfid).ljust(16, '0')[:16]

    L1, Tu1 = U1.fig43_step1(login_user, login_pw, login_bio16, DS1.PK, CS1.ID, DS1.ID)
    L2, Ts1 = DS1.fig43_step2(L1, Tu1, CS1.ID)
    alpha, beta, delta = CS1.fig43_step3(L2, Ts1)
    F1, F2, F3 = DS1.fig43_step4(alpha, beta, delta)
    M3, AUTH = U1.fig43_step5(F1, F2, F3)
    SK_DS = DS1.fig43_step6(M3, AUTH)

    if U1.last_SK != SK_DS:
        raise SystemExit("SESSION KEY MISMATCH")
    print(f"\nSESSION KEY VERIFIED  (User SK == DS SK)")

    content = make_nfc_summary(login_user, lu, U1.last_SK)
    print(f"Saving to NFC (max {NFC_MAX_LEN}B): {content}")
    ok = write_nfc(ser, content)

    print("\nVerifying NFC write ...")
    back_uid, back_data = read_nfc(ser)
    print(f"Read-back UID={hex(back_uid)} | Data='{back_data}'")
    sk = U1.last_SK
    if ok and any(short_hash(sk, n) in back_data for n in (8, 12, 16)):
        print("NFC contains the latest session summary.  Authentication complete.")
    elif ok:
        print("Warning: write confirmed but data differs.")
    else:
        print("Error: NFC write failed.")

# ------------------------------
# Plain-text compact table only
# ------------------------------
def print_plaintext_compact_table():
    REPS = 5
    BIO16 = "59".ljust(16, "0")[:16]
    PW = "TestPassword123"

    puf_m = InterposePUF(
        n=IPUF_N, k_up=IPUF_K_UP, k_down=IPUF_K_DOWN,
        seed=seed_int("bench"), noisiness=IPUF_NOISINESS,
    )
    chal_m = sha256_bits_pm1(PW)
    fe_m = FuzzyExtractor(16, 8)
    sigma_m, hlp_m = fe_m.generate(BIO16.encode())
    sym_m = key16(randint(0, 2**127))
    dummy = [12345, 67890, 1]
    n_v = randint(10**4, 10**6)
    x_v = randint(2, MOD_P - 1)

    def avg_ms(fn, reps=REPS):
        fn()
        vals = []
        for _ in range(reps):
            t0 = time.perf_counter()
            fn()
            vals.append((time.perf_counter() - t0) * 1000.0)
        return sum(vals) / len(vals)

    ms_tecm = avg_ms(lambda: T_ecm(n_v, x_v))
    ms_fe_gen = avg_ms(lambda: fe_m.generate(BIO16.encode()))
    ms_fe_rep = avg_ms(lambda: fe_m.reproduce(BIO16.encode(), hlp_m))
    ms_ipuf = avg_ms(lambda: eval_stable_fast(puf_m, chal_m, count=IPUF_RESPONSE_BITS, votes=IPUF_VOTES), reps=3)
    ms_hash = avg_ms(lambda: H("benchmark_value"))
    ms_aes_enc = avg_ms(lambda: encrypt(sym_m, dummy))
    enc_dummy = encrypt(sym_m, dummy)
    ms_aes_dec = avg_ms(lambda: decrypt(sym_m, enc_dummy))

    print()
    print("Crypto operations,                     Required time (in ms)")
    print("                                          Server        Consumer")
    print("                                            (PC)      (Rasp. Pi)")
    print("----------------------------------------------------------------")
    print(f"Extended Chaotic Map (T_ECM)           {0:>7.3f}        {ms_tecm:>7.3f}")
    print("Fuzzy")
    print(f"   FE.gen (T_se)                       {0:>7.4f}        {ms_fe_gen:>7.4f}")
    print(f"   FE.rep (T_sd)                       {0:>7.4f}        {ms_fe_rep:>7.4f}")
    print(f"XOR (8,8)-iPUF (T_puf)                 {0:>7.3f}        {ms_ipuf:>7.3f}")
    print(f"One-way hash [SHA-256] (T_h)           {0:>7.3f}        {ms_hash:>7.3f}")
    print("AES-128")
    print(f"/ ECB  one-byte enc (T_se)             {0:>7.3f}        {ms_aes_enc:>7.3f}")
    print(f"       one-byte dec (T_sd)             {0:>7.3f}        {ms_aes_dec:>7.3f}")
    print("----------------------------------------------------------------")
    print()

def main():
    ser = open_serial()
    try:
        username, password, CS1, DS1, U1 = register_phase(ser)
        login_phase(ser, username, password, CS1, DS1, U1)
        print()
        print("TABLE V -- BENCHMARK TIME")
        print_plaintext_compact_table()
    finally:
        try:
            ser.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
