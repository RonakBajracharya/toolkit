# CTF Crypto Toolkit — Installation Guide

> **CryptoHack-Ready Cryptography Toolkit** | Python 3.10+ | Linux · macOS · Windows (WSL)

---

## Table of Contents

1. [Requirements](#1-requirements)
2. [Quick Install](#2-quick-install)
3. [Step-by-Step Install](#3-step-by-step-install)
   - 3.1 [Linux / macOS](#31-linux--macos)
   - 3.2 [Windows (WSL)](#32-windows-wsl)
   - 3.3 [Docker](#33-docker)
4. [Optional Dependencies](#4-optional-dependencies)
5. [Verify Installation](#5-verify-installation)
6. [Running the CLI](#6-running-the-cli)
7. [Running the Web Server](#7-running-the-web-server)
8. [Troubleshooting](#8-troubleshooting)
9. [Updating](#9-updating)

---

## 1. Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.10 | 3.12 |
| pip | 22+ | latest |
| RAM | 512 MB | 2 GB (for lattice attacks) |
| OS | Linux / macOS / WSL2 | Ubuntu 22.04+ |

**Core Python packages:**

| Package | Version | Purpose |
|---------|---------|---------|
| `pycryptodome` | 3.20+ | AES, DES, RC4, ChaCha20, RSA primitives |
| `gmpy2` | 2.2+ | Fast big-integer arithmetic (factoring, roots) |
| `sympy` | 1.12+ | Number theory, modular inverse, factoring |
| `flask` | 3.0+ | Web UI server |

---

## 2. Quick Install

If you just want to get started immediately:

```bash
git clone https://github.com/yourname/toolkit.git
cd toolkit
pip install -r requirements.txt
python ctf_crypto.py          # interactive terminal UI
python server.py              # web interface at http://localhost:5000
```

---

## 3. Step-by-Step Install

### 3.1 Linux / macOS

#### Step 1 — Clone the repository

```bash
git clone https://github.com/yourname/toolkit.git
cd toolkit
```

Or, if you received the toolkit as a zip:

```bash
unzip toolkit.zip
cd toolkit
```

#### Step 2 — Install system dependencies

**Ubuntu / Debian:**

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv \
    libgmp-dev libmpfr-dev libmpc-dev gcc g++ make
```

`libgmp-dev` is required by `gmpy2` for fast big-integer math. Without it, gmpy2 will fail to compile.

**macOS (Homebrew):**

```bash
brew install python gmp mpfr libmpc
```

**Arch Linux:**

```bash
sudo pacman -S python python-pip gmp mpfr libmpc gcc
```

#### Step 3 — Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate          # Linux / macOS
# venv\Scripts\activate           # Windows
```

Using a virtualenv keeps the toolkit's dependencies isolated from your system Python.

#### Step 4 — Install Python packages

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

If you don't have a `requirements.txt`, install directly:

```bash
pip install pycryptodome gmpy2 sympy flask cryptography requests
```

#### Step 5 — Make the CLI executable (optional)

```bash
chmod +x ctf_crypto.py
# Now you can run: ./ctf_crypto.py instead of python ctf_crypto.py
```

---

### 3.2 Windows (WSL)

The toolkit is designed for Unix-like systems. On Windows, use WSL2 (Windows Subsystem for Linux).

#### Step 1 — Install WSL2

Open PowerShell as Administrator:

```powershell
wsl --install
```

Then restart your machine and open Ubuntu from the Start menu.

#### Step 2 — Install inside WSL

Follow the [Linux instructions](#31-linux--macos) exactly inside your WSL terminal.

#### Step 3 — Access the web UI from Windows

Once `server.py` is running inside WSL, open your Windows browser and navigate to:

```
http://localhost:5000
```

WSL2 automatically forwards ports from the Linux environment to Windows.

**Note for native Windows (without WSL):** Install Python 3.12 from [python.org](https://python.org), then run `pip install pycryptodome sympy flask`. The `gmpy2` package requires a pre-built wheel on Windows:

```
pip install gmpy2 --only-binary=:all:
```

If no wheel is available, download it from [https://github.com/aleaxit/gmpy/releases](https://github.com/aleaxit/gmpy/releases).

---

### 3.3 Docker

No setup required — everything runs inside a container.

#### Option A — Build from Dockerfile

Create `Dockerfile` in the toolkit root:

```dockerfile
FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    libgmp-dev libmpfr-dev libmpc-dev gcc g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir pycryptodome gmpy2 sympy flask cryptography requests

EXPOSE 5000
CMD ["python", "server.py", "--host", "0.0.0.0", "--port", "5000"]
```

Build and run:

```bash
docker build -t ctf-crypto .
docker run -p 5000:5000 ctf-crypto
```

Then open `http://localhost:5000` in your browser.

#### Option B — Interactive CLI in Docker

```bash
docker run -it --rm -v $(pwd):/work ctf-crypto python ctf_crypto.py
```

---

## 4. Optional Dependencies

These are not required for core functionality but unlock additional attack methods.

### fpylll — Lattice Reduction (LLL)

Required for ECDSA nonce bias attacks and advanced lattice challenges on CryptoHack.

```bash
# Ubuntu / Debian
sudo apt install -y libfplll-dev
pip install fpylll

# macOS
brew install fplll
pip install fpylll
```

Without `fpylll`, the `lll_reduce()` function falls back to a pure Python implementation, which is much slower and only practical for small lattices (dimension < 20).

### hashpumpy — Length Extension Attacks

Required for the `length_extension_attack()` function against SHA-1/SHA-256/MD5.

```bash
pip install hashpumpy
```

### SageMath — Advanced Number Theory

SageMath provides the most powerful environment for lattice attacks, elliptic curve discrete logs, and algebraic attacks. It is optional but highly recommended for hard CryptoHack challenges.

```bash
# Ubuntu
sudo apt install sagemath

# macOS
brew install --cask sage

# Or use the online notebook:
# https://sagecell.sagemath.org
```

### pwntools — CTF Interaction

Required if you want to use the toolkit against live CTF servers (padding oracles, interactive challenges).

```bash
pip install pwntools
```

---

## 5. Verify Installation

Run the built-in verification script:

```bash
python3 -c "
import sys
print(f'Python {sys.version}')

checks = [
    ('pycryptodome', 'Crypto.Cipher.AES'),
    ('gmpy2',        'gmpy2'),
    ('sympy',        'sympy'),
    ('flask',        'flask'),
]

for name, mod in checks:
    try:
        __import__(mod)
        print(f'  [OK]  {name}')
    except ImportError:
        print(f'  [!!]  {name}  <-- MISSING, run: pip install {name}')

# Test core modules
try:
    import sys, os
    sys.path.insert(0, '.')
    from modules.classical import caesar_decrypt
    from modules.rsa_attacks import wiener_attack
    from modules.aes_attacks import aes_ecb_encrypt
    from modules.encoding import to_base64, auto_crack_xor
    print()
    print('  [OK]  classical ciphers')
    print('  [OK]  RSA attacks')
    print('  [OK]  AES attacks')
    print('  [OK]  encoding utilities')
    print()
    print('All checks passed. Toolkit is ready.')
except Exception as e:
    print(f'  [!!]  Module error: {e}')
"
```

Expected output:

```
Python 3.12.x ...
  [OK]  pycryptodome
  [OK]  gmpy2
  [OK]  sympy
  [OK]  flask

  [OK]  classical ciphers
  [OK]  RSA attacks
  [OK]  AES attacks
  [OK]  encoding utilities

All checks passed. Toolkit is ready.
```

---

## 6. Running the CLI

### Interactive mode (recommended for beginners)

```bash
python ctf_crypto.py
```

Launches a full menu-driven interface. No arguments needed — just pick a number.

### Command mode

```bash
# Encode / Decode
python ctf_crypto.py encode -d "Hello, World!" --format base64
python ctf_crypto.py decode -d "SGVsbG8sIFdvcmxkIQ==" --format base64
python ctf_crypto.py decode -d "some_weird_string" --format auto    # try everything

# Classical ciphers
python ctf_crypto.py caesar -d "URYYB JBEYQ" --bruteforce
python ctf_crypto.py caesar -d "HELLO" --shift 13 --encrypt
python ctf_crypto.py vigenere -d "CIPHERTEXT" --crack --maxkey 20
python ctf_crypto.py classical -d "XUBBM YMZBT"                     # auto-detect

# XOR
python ctf_crypto.py xor -d "0x1a2b3c4d..." --crack                 # auto crack
python ctf_crypto.py xor -d "0xdeadbeef" --key "0xab"               # known key

# Hash
python ctf_crypto.py hash -d "password" --algorithm sha256
python ctf_crypto.py hash --crack 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5
python ctf_crypto.py hash --crack <hash> --wordlist /usr/share/wordlists/rockyou.txt

# RSA
python ctf_crypto.py rsa --n <N> --e 3 --c <C> --decrypt            # auto-solve
python ctf_crypto.py rsa --n <N> --e <E> --wiener                   # Wiener's attack
python ctf_crypto.py rsa --n <N> --e <E> --c <C> --factor           # factor then decrypt
python ctf_crypto.py rsa --keygen 2048                               # generate keypair

# AES
python ctf_crypto.py aes --key deadbeef0011223344556677889900aabb \
    --mode CBC --iv 00000000000000000000000000000000 \
    -d "0x..." --decrypt
```

### Reading from a file

```bash
python ctf_crypto.py decode -f ciphertext.txt --format auto
python ctf_crypto.py xor -f data.bin --hex --crack
```

### Piping

```bash
echo "URYYB" | python ctf_crypto.py caesar
cat ciphertext.b64 | python ctf_crypto.py decode --format base64
```

---

## 7. Running the Web Server

```bash
python server.py
```

Default: `http://0.0.0.0:5000`

### Options

```bash
python server.py --port 8080          # change port
python server.py --host 127.0.0.1     # localhost only (more secure)
python server.py --debug              # enable Flask debug mode (dev only)
```

### API Endpoints

The server exposes a REST API consumed by the web UI, but you can call it directly too:

```
POST /api/encode          Encode data in various formats
POST /api/decode          Decode data, with auto-detection
POST /api/hash            Hash data, crack hashes, identify hash type
POST /api/xor             XOR encrypt/decrypt and crack
POST /api/classical       All classical cipher operations
POST /api/rsa             RSA keygen, encrypt, decrypt, all attacks
POST /api/aes             AES ECB/CBC/CTR/GCM encrypt & decrypt
POST /api/ctr_attack      CTR nonce-reuse and known-plaintext recovery
POST /api/ec              EC point operations, ECDSA k-reuse, DLP
POST /api/number_theory   modinv, CRT, Tonelli-Shanks, BSGS, factor
```

**Example — crack RSA with Wiener's attack via curl:**

```bash
curl -s -X POST http://localhost:5000/api/rsa \
  -H "Content-Type: application/json" \
  -d '{"action":"wiener","n":"<N>","e":"<E>","c":"<C>"}' | python3 -m json.tool
```

**Example — auto-decode a mystery string:**

```bash
curl -s -X POST http://localhost:5000/api/decode \
  -H "Content-Type: application/json" \
  -d '{"format":"auto","data":"SGVsbG8gQ1RG"}' | python3 -m json.tool
```

---

## 8. Troubleshooting

### `gmpy2` fails to install

```
ERROR: Failed building wheel for gmpy2
```

**Fix:** Install GMP development libraries first.

```bash
# Ubuntu / Debian
sudo apt install libgmp-dev libmpfr-dev libmpc-dev

# macOS
brew install gmp

# Then retry
pip install gmpy2
```

On Windows without WSL, download the pre-built wheel from the [gmpy2 releases page](https://github.com/aleaxit/gmpy/releases) and install with `pip install gmpy2‑<version>‑cpXX‑win_amd64.whl`.

---

### `ModuleNotFoundError: No module named 'Crypto'`

You have `crypto` installed instead of `pycryptodome`. They conflict.

```bash
pip uninstall crypto pycrypto pycryptodome
pip install pycryptodome
```

---

### `ImportError: cannot import name 'mod_inverse' from 'sympy'`

Your sympy version is too old.

```bash
pip install --upgrade sympy
```

---

### Flask server returns 404 for the UI

The server reads `static/index.html` at startup. Make sure the `static/` directory exists and contains `index.html`:

```bash
ls toolkit/static/
# Should show: index.html
```

If missing, the HTML file may not have been included in your download.

---

### `PermissionError` on Linux when running `./ctf_crypto.py`

```bash
chmod +x ctf_crypto.py
```

---

### Slow factoring / attacks timing out

Large RSA keys (2048-bit+) cannot be factored with trial division or Pollard's rho in reasonable time — this is intentional. For CryptoHack challenges, the keys are always designed to be breakable with one of the implemented methods (Fermat, Wiener, small `e`, etc.). If the auto-solver fails, examine the specific challenge hint.

For Wiener's attack to work, `d` must satisfy `d < n^(1/4) / 3`. If `e` is small (e.g. `e = 3`) and the message is small, try `small_e_attack` first.

---

### Port already in use

```bash
# Find what's using port 5000
lsof -i :5000
# Kill it, or use a different port
python server.py --port 5001
```

On macOS, AirPlay receiver uses port 5000 by default. Either disable it in System Preferences → Sharing, or run the server on a different port.

---

## 9. Updating

If you cloned via git:

```bash
git pull origin main
pip install -r requirements.txt --upgrade
```

If you're using a virtual environment, activate it first:

```bash
source venv/bin/activate
git pull
pip install -r requirements.txt --upgrade
```

---

## File Structure Reference

```
toolkit/
│
├── ctf_crypto.py          CLI entry point (interactive + command mode)
├── server.py              Flask web server & REST API
├── requirements.txt       Python dependencies
│
├── modules/
│   ├── __init__.py
│   ├── classical.py       Caesar, Vigenere, Substitution, Rail Fence, Playfair, ...
│   ├── encoding.py        Base64/32/58/85, hex, XOR, morse, hashing, auto-decode
│   ├── rsa_attacks.py     Wiener, Hastad, Fermat, Pollard, small-e, CRT, keygen
│   ├── aes_attacks.py     ECB/CBC/CTR/GCM, padding oracle, bit-flip, nonce reuse
│   └── pqc_ec.py          ECDLP, ECDSA k-reuse, Pohlig-Hellman, LLL, DH attacks
│
└── static/
    └── index.html         Single-page web UI
```

---

*Happy hacking. Stay legal, stay ethical, and go solve some CryptoHack challenges.*
