[README.md](https://github.com/user-attachments/files/29204839/README.md)
# 3FAKA
It's lightweight 3factor authentication protocol using extended chaotic maps and physical unclonable functions(PUFs) for portable devices. It ensures robust security, including mutual authentication and anonymity, while resisting cloning and other attacks. Designed for efficiency, it's ideal for resource-constrained IoT and healthcare applications.

3FAKA (NFC + Fingerprint + Password)

A practical demo of the **Three‑Factor Authentication & Key Agreement (3FAKA)** protocol using:
- **NFC card** (PN532 over I2C) as the smart‑card factor,
- **Fingerprint sensor** as the biometric factor, and
- **Password** as the knowledge factor.
---

## Repository Layout

```
3FAKA/
├─ App/
│  ├─ AES.py
│  ├─ finalthreeFAKA.py
│  └─ web.py
├─ Arduino/
│  └─V2.ino                # Arduino sketch for PN532 + Fingerprint
├─ Documents/
│  └─ Robust Three-Factor Lightweight Authentication Based on Extended.pdf   #2023 paper
├─ Module Error- Solution Code/
│  └─ ModuleNotFoundError.doc
├─ README.md
├─ Library requirements.txt
```

---

## Hardware

- **Arduino** (e.g., Uno/Nano/MEGA; 5V boards tested).
- **PN532 NFC** module (I2C mode). Default I2C pins (Uno: A4 SDA, A5 SCL).
- **Fingerprint sensor** (e.g., “Adafruit” UART‑based sensor).
- NFC Mifare Classic/Ultralight card or tag.

### Arduino libraries (install from Library Manager)
- *Adafruit PN532*
- *Adafruit BusIO*
- *Adafruit Unified Sensor*
- *Adafruit Fingerprint Sensor Library*

Wire PN532 for **I2C**, and the fingerprint sensor for **UART** (pins depend on your board).

---

## Software Prereqs

- **Windows 10/11**
- **Python 3.11** (critical for package compatibility)
- **Git** (optional but recommended)

> ⚠️ Python 3.13 currently causes build/import issues for `fuzzy-extractor` / `fastpbkdf2`. Use 3.11.

---
## Setup (Windows, PowerShell)

```powershell
# 1) Clone or create this folder
# git clone https://github.com/sonam-s-code/3FAKA.git
cd 3FAKA

# 2) Create and activate a Python 3.11 virtual environment
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3) Install requirements
pip install --upgrade pip
pip install -r requirements.txt
```

> If installation errors mention compilers or `fastpbkdf2`, install **Visual Studio Build Tools (C++)** or refer the **ModulenNotFoundError.docx** or try:
>
> ```powershell
> pip install --only-binary=:all: fastpbkdf2 pycryptodome
> ```

---
## Flash the Arduino

Open `arduino/V2/V2.ino` in the **Arduino IDE**:
1. Select your board and COM port.
2. Click **Upload**.
3. Keep the board connected (the web app will open/close the port when needed).

The sketch should respond on serial to:
- `read` → prints NFC UID and current tag data
- `write <len> <ascii>` → writes ASCII to the tag (max length depends on your tag)
- `fingerprint` → tries to match an enrolled fingerprint
- `enroll` → prompts for a new fingerprint ID enrollment

---

## Run the Web UI

```powershell
# From the repo root (with venv activated):
uvicorn web:app --reload --port 8000
```

Now open **http://127.0.0.1:8000**

**Steps**
1. **Register**
   - Enter **Username** and **Password**.
   - Click **Register**.
   - The log will prompt you to **tap your NFC card** and **place your finger**.
   - On first use, it will **enroll** your fingerprint automatically if no match is found.
2. **Login**
   - Enter the Username with Password then Tap the **same NFC card** and place your finger again.
   - On success, the server writes a short **session summary** back to the NFC tag (so you can verify it).

---

## Configuration

- Default serial port in the web UI is `COM11`. You can change it in the sidebar or edit `DEFAULT_PORT` in `app/web.py`.
- NFC summary length is limited by your tag. You can change `NFC_MAX_LEN` in `app/finalthreeFAKA.py` if your card supports more bytes (e.g. 32 → 48).

---

## Troubleshooting

- **“could not open port ‘COM…’”**  
  Close Arduino Serial Monitor/Plotter and any app using the same COM port. Unplug/re‑plug the board and try again.

- **Fingerprint not recognized during Register**  
  The web flow attempts an **auto‑enroll** (picks an ID and retries). After enrollment, it re‑scans to verify.

- **NFC write reported OK but read‑back is different**  
  Tap again and ensure the tag allows the requested write length. Reduce `NFC_MAX_LEN` or move the tag slower.

- **Using Python 3.13**  
  Switch to **Python 3.11** for best compatibility.

---
