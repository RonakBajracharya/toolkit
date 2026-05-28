#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║          CTF CRYPTO TOOLKIT - Terminal Interface          ║
║                  CryptoHack Ready v1.0                   ║
╚═══════════════════════════════════════════════════════════╝

Usage:
  python ctf_crypto.py <command> [options]

Run with --help for full usage, or just: python ctf_crypto.py
"""

import argparse
import sys
import os
import json
import binascii
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# ─── Colors ───────────────────────────────────────────────────────────────────

class C:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    PURPLE = '\033[95m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RESET  = '\033[0m'

def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║      ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗          ║
║     ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗         ║
║     ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║         ║
║     ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║         ║
║     ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝         ║
║      ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝          ║
║                                                                  ║
║              CTF Cryptography Toolkit v1.0                       ║
║          CryptoHack Ready · By CTF Players, For CTF Players      ║
╚══════════════════════════════════════════════════════════════════╝{C.RESET}
""")

def ok(msg): print(f"{C.GREEN}[+]{C.RESET} {msg}")
def info(msg): print(f"{C.BLUE}[*]{C.RESET} {msg}")
def warn(msg): print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def err(msg): print(f"{C.RED}[-]{C.RESET} {msg}")
def section(msg): print(f"\n{C.PURPLE}{C.BOLD}{'═'*60}{C.RESET}\n{C.PURPLE}{C.BOLD}  {msg}{C.RESET}\n{'═'*60}")

# ─── Helpers ──────────────────────────────────────────────────────────────────

def read_input(data: str | None, file: str | None, hex_input: bool = False) -> bytes | str:
    if file:
        with open(file, 'rb') as f:
            raw = f.read()
        return raw
    if data:
        if hex_input:
            return bytes.fromhex(data.replace(' ', '').replace('0x', ''))
        return data.encode() if not data.startswith('\\x') else bytes.fromhex(data.replace('\\x', ''))
    return sys.stdin.buffer.read()

def print_result(result, label: str = "Result"):
    if isinstance(result, bytes):
        print(f"\n{C.GREEN}{C.BOLD}{label}:{C.RESET}")
        try:
            printable = result.decode('utf-8')
            print(f"  {C.WHITE}Text:{C.RESET} {printable}")
        except Exception:
            pass
        print(f"  {C.WHITE}Hex: {C.RESET} {result.hex()}")
        print(f"  {C.WHITE}B64: {C.RESET} {__import__('base64').b64encode(result).decode()}")
    elif isinstance(result, list):
        for i, item in enumerate(result[:5]):
            print(f"\n{C.CYAN}[Result {i+1}]{C.RESET}")
            for k, v in item.items() if isinstance(item, dict) else enumerate(item):
                if k == 'text' and isinstance(v, bytes):
                    try:
                        v = v.decode('utf-8', 'replace')
                    except Exception:
                        v = v.hex()
                elif k == 'text' and isinstance(v, (bytes, bytearray)):
                    v = bytes(v).decode('utf-8', 'replace')
                print(f"  {C.YELLOW}{k}:{C.RESET} {v}")
    elif isinstance(result, dict):
        for k, v in result.items():
            if isinstance(v, bytes):
                try:
                    v_str = v.decode('utf-8', 'replace')
                except Exception:
                    v_str = v.hex()
                print(f"  {C.YELLOW}{k}:{C.RESET} {v_str} (hex: {v.hex() if isinstance(v, bytes) else ''})")
            else:
                print(f"  {C.YELLOW}{k}:{C.RESET} {v}")
    else:
        print(f"\n{C.GREEN}{C.BOLD}{label}:{C.RESET} {result}")

# ─── Commands ─────────────────────────────────────────────────────────────────

def cmd_encode(args):
    section("ENCODING")
    from modules.encoding import (to_base64, to_base32, to_hex, to_binary,
                                   to_decimal, to_morse, to_octal, to_base58, to_base85)
    data = read_input(args.data, args.file)
    if isinstance(data, str):
        data = data.encode()
    
    funcs = {
        'base64': to_base64, 'base32': to_base32, 'hex': to_hex,
        'binary': to_binary, 'decimal': to_decimal, 'octal': to_octal,
        'base58': to_base58, 'base85': to_base85,
    }
    if args.format in funcs:
        result = funcs[args.format](data)
        ok(f"{args.format.upper()}: {result}")
    elif args.format == 'morse':
        result = to_morse(data.decode())
        ok(f"Morse: {result}")
    elif args.format == 'all':
        for name, fn in funcs.items():
            try:
                print(f"  {C.CYAN}{name:10}{C.RESET}: {fn(data)}")
            except Exception as e:
                print(f"  {C.RED}{name:10}{C.RESET}: error - {e}")

def cmd_decode(args):
    section("DECODING")
    from modules.encoding import (from_base64, from_base32, from_hex, from_binary,
                                   from_decimal, from_morse, from_octal, from_base58,
                                   from_base85, auto_decode)
    data = args.data or sys.stdin.read().strip()
    
    funcs = {
        'base64': lambda x: from_base64(x),
        'base32': from_base32, 'hex': from_hex, 'binary': from_binary,
        'decimal': from_decimal, 'octal': from_octal,
        'base58': from_base58, 'base85': from_base85,
    }
    if args.format == 'morse':
        result = from_morse(data)
        ok(f"Morse decoded: {result}")
    elif args.format == 'auto':
        results = auto_decode(data)
        info(f"Trying all decodings on input...")
        for r in results:
            print(f"  {C.CYAN}{r['method']:15}{C.RESET}: {r['printable'][:80]}")
    elif args.format in funcs:
        try:
            result = funcs[args.format](data)
            print_result(result, f"{args.format.upper()} decoded")
        except Exception as e:
            err(f"Decode failed: {e}")

def cmd_hash(args):
    section("HASH")
    from modules.encoding import hash_data, hash_identifier, crack_hash_wordlist, crack_hash_digits
    
    if args.crack:
        target = args.crack
        algo = args.algorithm or 'md5'
        info(f"Cracking {algo.upper()} hash: {target}")
        
        if args.wordlist:
            with open(args.wordlist) as f:
                words = [line.strip() for line in f]
            result = crack_hash_wordlist(target, words, algo)
        else:
            info("No wordlist provided, trying digits (0-99999999)...")
            result = crack_hash_digits(target, 8, algo)
        
        if result:
            ok(f"CRACKED: {result}")
        else:
            warn("Not found in search space")
    elif args.identify:
        candidates = hash_identifier(args.identify)
        ok(f"Hash type candidates: {', '.join(candidates)}")
    elif args.data or args.file:
        data = read_input(args.data, args.file)
        if isinstance(data, str):
            data = data.encode()
        algo = args.algorithm or 'sha256'
        result = hash_data(data, algo)
        ok(f"{algo.upper()}: {result}")

def cmd_xor(args):
    section("XOR ANALYSIS")
    from modules.encoding import (xor_with_key, auto_crack_xor, xor_bytes,
                                   guess_xor_key_length, single_byte_xor_score)
    
    if args.key:
        data = read_input(args.data, args.file, args.hex)
        if isinstance(data, str):
            data = data.encode()
        key = bytes.fromhex(args.key.replace('0x', '').replace(' ', ''))
        result = xor_with_key(data, key)
        print_result(result, "XOR Result")
    elif args.crack:
        data = read_input(args.data, args.file, args.hex)
        if isinstance(data, str):
            data = data.encode()
        info("Running XOR crack analysis...")
        
        if args.keylen:
            from modules.encoding import multi_byte_xor_crack
            key, dec = multi_byte_xor_crack(data, int(args.keylen))
            ok(f"Key (keylen={args.keylen}): {key.hex()}")
            print_result(dec, "Decrypted")
        else:
            results = auto_crack_xor(data)
            info(f"Top {len(results)} XOR solutions:")
            for r in results[:3]:
                print(f"\n  {C.CYAN}Key:{C.RESET} {r['key']} (len={r['key_len']})")
                try:
                    text = r['text'].decode('utf-8', 'replace')[:100]
                except Exception:
                    text = str(r['text'])[:100]
                print(f"  {C.CYAN}Text:{C.RESET} {text}")

def cmd_caesar(args):
    section("CAESAR CIPHER")
    from modules.classical import caesar_encrypt, caesar_decrypt, caesar_bruteforce, rot13, rot47
    
    text = args.data or sys.stdin.read()
    
    if args.bruteforce:
        results = caesar_bruteforce(text)
        info("All 26 Caesar shifts (ranked by English frequency):")
        for r in results[:5]:
            print(f"  {C.CYAN}Shift {r['shift']:2d}{C.RESET}: {r['text'][:80]}")
    elif args.rot13:
        ok(f"ROT13: {rot13(text)}")
    elif args.rot47:
        ok(f"ROT47: {rot47(text)}")
    elif args.shift is not None:
        if args.encrypt:
            ok(f"Encrypted: {caesar_encrypt(text, args.shift)}")
        else:
            ok(f"Decrypted: {caesar_decrypt(text, args.shift)}")

def cmd_vigenere(args):
    section("VIGENERE CIPHER")
    from modules.classical import vigenere_encrypt, vigenere_decrypt, vigenere_crack
    
    text = args.data or sys.stdin.read()
    
    if args.key:
        if args.encrypt:
            ok(f"Encrypted: {vigenere_encrypt(text, args.key)}")
        else:
            ok(f"Decrypted: {vigenere_decrypt(text, args.key)}")
    else:
        info(f"Cracking Vigenere cipher... (max key length: {args.maxkey or 12})")
        results = vigenere_crack(text, args.maxkey or 12)
        for r in results[:3]:
            print(f"\n  {C.CYAN}Key:{C.RESET} {r['key']} (len={r['key_length']})")
            print(f"  {C.CYAN}Text:{C.RESET} {r['text'][:100]}")

def cmd_rsa(args):
    section("RSA ATTACKS")
    from modules.rsa_attacks import (
        rsa_auto_solve, wiener_attack, hastad_broadcast, small_e_attack,
        rsa_keygen, rsa_decrypt, rsa_encrypt, long_to_bytes, bytes_to_long,
        fermat_factor, smooth_factor, modinv
    )
    
    def parse_int(s):
        if not s:
            return None
        s = s.strip()
        if s.startswith('0x'):
            return int(s, 16)
        return int(s)
    
    n = parse_int(args.n)
    e = parse_int(args.e)
    c = parse_int(args.c)
    p = parse_int(args.p)
    q = parse_int(args.q)
    d = parse_int(args.d)
    
    if args.keygen:
        bits = int(args.keygen)
        key = rsa_keygen(bits, e or 65537)
        print(f"\n{C.GREEN}RSA Key Generated ({bits} bits):{C.RESET}")
        for k, v in key.items():
            print(f"  {C.CYAN}{k}{C.RESET} = {hex(v) if v > 100 else v}")
        return
    
    if args.wiener and n and e:
        info("Running Wiener's attack...")
        result = wiener_attack(e, n)
        if result:
            d_w, p_w, q_w = result
            ok(f"SUCCESS! d={d_w}")
            if c:
                pt = rsa_decrypt(c, d_w, n)
                print_result(pt, "Plaintext")
        else:
            warn("Wiener's attack failed (d may not be small enough)")
    
    elif args.hastad:
        # Parse multiple n,c pairs from args
        info("Hastad broadcast attack requires multiple (n, c) pairs with same e")
        warn("Provide via --hastad-data file with JSON: [[n1,c1],[n2,c2],...]")
    
    elif args.factor and n:
        info(f"Factoring n ({n.bit_length()} bits)...")
        result = smooth_factor(n)
        if result:
            ok(f"FACTORED via {result['method']}!")
            ok(f"p = {result['p']}")
            ok(f"q = {result['q']}")
            if e and c:
                from sympy import mod_inverse
                phi = (result['p'] - 1) * (result['q'] - 1)
                d_calc = modinv(e, phi)
                pt = rsa_decrypt(c, d_calc, n)
                print_result(pt, "Plaintext")
        else:
            warn(f"Could not factor n ({n.bit_length()} bits) with available methods")
    
    elif args.decrypt and n and e and c:
        info("Running RSA auto-solve...")
        result = rsa_auto_solve(n, e, c, p, q, d)
        print_result(result, "RSA Auto-solve")
    
    elif n and e and c:
        info("Auto-solving RSA...")
        result = rsa_auto_solve(n, e, c, p, q, d)
        print_result(result, "RSA Result")

def cmd_aes(args):
    section("AES OPERATIONS")
    from modules.aes_attacks import (
        aes_ecb_encrypt, aes_ecb_decrypt, aes_cbc_encrypt, aes_cbc_decrypt,
        aes_ctr_encrypt, aes_gcm_encrypt, aes_gcm_decrypt, ecb_detect,
        auto_detect_aes_mode, BLOCK
    )
    
    key = bytes.fromhex(args.key.replace('0x', '').replace(' ', '')) if args.key else None
    iv = bytes.fromhex(args.iv.replace('0x', '').replace(' ', '')) if args.iv else bytes(BLOCK)
    nonce = bytes.fromhex(args.nonce.replace('0x', '').replace(' ', '')) if args.nonce else bytes(8)
    
    data = read_input(args.data, args.file, args.hex)
    if isinstance(data, str):
        data = data.encode()
    
    mode = (args.mode or 'ecb').upper()
    
    if args.detect:
        mode_guess = auto_detect_aes_mode(data)
        ok(f"Detected mode: {mode_guess}")
        return
    
    if not key:
        err("Key required (--key <hex>)")
        return
    
    if args.decrypt:
        if mode == 'ECB':
            result = aes_ecb_decrypt(key, data)
        elif mode == 'CBC':
            result = aes_cbc_decrypt(key, iv, data)
        elif mode == 'CTR':
            n = int.from_bytes(nonce, 'big')
            result = aes_ctr_encrypt(key, n, data)
        elif mode == 'GCM':
            tag = bytes.fromhex(args.tag) if args.tag else b'\x00' * 16
            result = aes_gcm_decrypt(key, nonce, data, tag)
        else:
            err(f"Unknown mode: {mode}")
            return
    else:
        if mode == 'ECB':
            result = aes_ecb_encrypt(key, data)
        elif mode == 'CBC':
            result = aes_cbc_encrypt(key, iv, data)
        elif mode == 'CTR':
            n = int.from_bytes(nonce, 'big')
            result = aes_ctr_encrypt(key, n, data)
        elif mode == 'GCM':
            result, tag = aes_gcm_encrypt(key, nonce, data)
            ok(f"Tag: {tag.hex()}")
        else:
            err(f"Unknown mode: {mode}")
            return
    
    print_result(result, f"AES-{mode} Result")

def cmd_classical(args):
    section("CLASSICAL CIPHER AUTO-SOLVER")
    from modules.classical import auto_detect_classical
    text = args.data or sys.stdin.read()
    info(f"Running all classical cipher attacks on {len(text)} chars...")
    results = auto_detect_classical(text)
    for i, r in enumerate(results[:8]):
        print(f"\n{C.CYAN}[{i+1}] {r['method']}{C.RESET}")
        text_preview = r['text'][:100] if isinstance(r['text'], str) else r['text'].decode('utf-8', 'replace')[:100]
        print(f"    {text_preview}")

def cmd_interactive():
    """Interactive menu mode."""
    banner()
    print(f"{C.CYAN}Interactive Mode{C.RESET} - Type command or 'help'\n")
    
    MENU = """
  {y}ENCODINGS{r}          {y}CLASSICAL{r}          {y}ASYMMETRIC{r}
  [1] Encode/Decode    [5] Caesar/ROT       [9]  RSA Auto-Solve
  [2] XOR Analysis     [6] Vigenere         [10] RSA Wiener
  [3] Hash             [7] Substitution     [11] RSA Hastad
  [4] Auto-Decode      [8] Auto-Classical   [12] EC/DLP

  {y}SYMMETRIC{r}          {y}UTILITIES{r}
  [13] AES Encrypt     [16] Number Theory
  [14] AES Decrypt     [17] Lattice Tools
  [15] AES Attack      [q]  Quit
""".format(y=C.YELLOW+C.BOLD, r=C.RESET)
    
    while True:
        print(MENU)
        choice = input(f"{C.BOLD}Select [{C.CYAN}1-17{C.WHITE}/q{C.RESET}{C.BOLD}]: {C.RESET}").strip()
        
        if choice == 'q':
            print(f"\n{C.CYAN}Stay crypto!{C.RESET}")
            break
        elif choice == '1':
            _interactive_encode()
        elif choice == '2':
            _interactive_xor()
        elif choice == '3':
            _interactive_hash()
        elif choice == '4':
            _interactive_auto_decode()
        elif choice == '5':
            _interactive_caesar()
        elif choice == '6':
            _interactive_vigenere()
        elif choice == '7':
            _interactive_substitution()
        elif choice == '8':
            _interactive_auto_classical()
        elif choice == '9':
            _interactive_rsa_auto()
        elif choice == '10':
            _interactive_rsa_wiener()
        elif choice == '11':
            _interactive_rsa_hastad()
        elif choice == '13' or choice == '14' or choice == '15':
            _interactive_aes(choice)
        elif choice == '16':
            _interactive_number_theory()
        else:
            warn(f"Unknown choice: {choice}")

def _get(prompt, default=None):
    val = input(f"  {C.YELLOW}{prompt}{C.RESET}: ").strip()
    return val if val else default

def _interactive_encode():
    section("ENCODE / DECODE")
    from modules.encoding import (to_base64, from_base64, to_hex, from_hex,
                                   to_binary, from_binary, to_base32, from_base32)
    data = _get("Input data (text or hex with 0x prefix)")
    direction = _get("Encode or Decode? [e/d]", 'e').lower()
    fmt = _get("Format [base64/base32/hex/binary/auto]", 'base64').lower()
    
    if direction == 'e':
        if data.startswith('0x'):
            data = bytes.fromhex(data[2:])
        else:
            data = data.encode()
        if fmt == 'base64':
            ok(to_base64(data))
        elif fmt == 'hex':
            ok(to_hex(data))
        elif fmt == 'binary':
            ok(to_binary(data))
        elif fmt == 'base32':
            ok(to_base32(data))
    else:
        try:
            if fmt == 'base64' or fmt == 'auto':
                ok(from_base64(data))
            elif fmt == 'hex':
                ok(from_hex(data).decode('utf-8', 'replace'))
            elif fmt == 'binary':
                ok(from_binary(data).decode('utf-8', 'replace'))
            elif fmt == 'base32':
                ok(from_base32(data).decode('utf-8', 'replace'))
        except Exception as e:
            err(f"Failed: {e}")

def _interactive_xor():
    section("XOR ANALYSIS")
    data = _get("Input (hex with 0x prefix, or text)")
    if data.startswith('0x'):
        data = bytes.fromhex(data[2:])
    else:
        data = data.encode()
    
    key = _get("Key (hex, leave blank to crack)", None)
    if key:
        from modules.encoding import xor_with_key
        key_bytes = bytes.fromhex(key.replace('0x', ''))
        result = xor_with_key(data, key_bytes)
        print_result(result)
    else:
        from modules.encoding import auto_crack_xor
        results = auto_crack_xor(data)
        for r in results[:3]:
            print(f"\n  {C.CYAN}Key:{C.RESET} {r['key']}  |  {C.CYAN}Text:{C.RESET} {bytes(r['text']).decode('utf-8','replace')[:80]}")

def _interactive_hash():
    section("HASH")
    data = _get("Data to hash (or hash to crack with --crack)")
    action = _get("Action [hash/crack/identify]", 'hash')
    algo = _get("Algorithm [md5/sha1/sha256/sha512]", 'sha256')
    
    if action == 'hash':
        from modules.encoding import hash_data
        ok(hash_data(data.encode(), algo))
    elif action == 'crack':
        from modules.encoding import crack_hash_digits, crack_hash_bruteforce
        wl = _get("Wordlist file (blank for digit bruteforce)", None)
        if wl:
            from modules.encoding import crack_hash_wordlist
            with open(wl) as f:
                words = [l.strip() for l in f]
            result = crack_hash_wordlist(data, words, algo)
        else:
            info("Trying digit bruteforce (0-99999999)...")
            result = crack_hash_digits(data, 8, algo)
        ok(f"CRACKED: {result}") if result else warn("Not found")
    elif action == 'identify':
        from modules.encoding import hash_identifier
        ok(f"Likely: {', '.join(hash_identifier(data))}")

def _interactive_auto_decode():
    section("AUTO-DECODE")
    from modules.encoding import auto_decode
    data = _get("Input string")
    results = auto_decode(data)
    info(f"Trying {len(results)} decodings:")
    for r in results:
        print(f"  {C.CYAN}{r['method']:15}{C.RESET}: {r['printable'][:80]}")

def _interactive_caesar():
    section("CAESAR / ROT13 / ROT47")
    text = _get("Ciphertext")
    action = _get("Action [bruteforce/encrypt/decrypt/rot13/rot47]", 'bruteforce')
    from modules.classical import caesar_bruteforce, caesar_encrypt, caesar_decrypt, rot13, rot47
    if action == 'bruteforce':
        for r in caesar_bruteforce(text)[:5]:
            print(f"  Shift {r['shift']:2d}: {r['text'][:80]}")
    elif action == 'rot13':
        ok(rot13(text))
    elif action == 'rot47':
        ok(rot47(text))
    elif action in ('encrypt', 'decrypt'):
        shift = int(_get("Shift [0-25]", '3'))
        fn = caesar_encrypt if action == 'encrypt' else caesar_decrypt
        ok(fn(text, shift))

def _interactive_vigenere():
    section("VIGENERE CIPHER")
    text = _get("Text")
    key = _get("Key (blank to crack)", None)
    from modules.classical import vigenere_encrypt, vigenere_decrypt, vigenere_crack
    if key:
        action = _get("Encrypt or Decrypt [e/d]", 'd')
        fn = vigenere_encrypt if action == 'e' else vigenere_decrypt
        ok(fn(text, key))
    else:
        maxkl = int(_get("Max key length [12]", '12'))
        for r in vigenere_crack(text, maxkl)[:3]:
            print(f"\n  Key: {C.CYAN}{r['key']}{C.RESET}")
            print(f"  {r['text'][:120]}")

def _interactive_substitution():
    section("SUBSTITUTION CIPHER")
    text = _get("Ciphertext")
    from modules.classical import substitution_crack_frequency
    result = substitution_crack_frequency(text)
    ok(f"Suggested key: {result['key']}")
    ok(f"Decrypted: {result['text'][:200]}")
    info("Tune the mapping manually if needed")

def _interactive_auto_classical():
    section("AUTO CLASSICAL SOLVER")
    from modules.classical import auto_detect_classical
    text = _get("Ciphertext")
    results = auto_detect_classical(text)
    for i, r in enumerate(results[:5]):
        t = r['text'] if isinstance(r['text'], str) else r['text'].decode('utf-8','replace')
        print(f"\n{C.CYAN}[{i+1}] {r['method']}{C.RESET}: {t[:100]}")

def _interactive_rsa_auto():
    section("RSA AUTO-SOLVE")
    from modules.rsa_attacks import rsa_auto_solve
    def gi(p): return int(_get(p, '0') or 0) or None
    n = gi("n (or 0 to skip)")
    e = gi("e") or 65537
    c = gi("c (ciphertext int)")
    p = gi("p (if known)")
    q = gi("q (if known)")
    d = gi("d (if known)")
    if n and e and c:
        result = rsa_auto_solve(n, e, c, p, q, d)
        print_result(result)
    else:
        warn("Need at least n, e, c")

def _interactive_rsa_wiener():
    section("RSA WIENER'S ATTACK")
    from modules.rsa_attacks import wiener_attack, rsa_decrypt
    e = int(_get("e (public exponent)"))
    n = int(_get("n (modulus)"))
    c_str = _get("c (ciphertext, optional)", None)
    result = wiener_attack(e, n)
    if result:
        d, p, q = result
        ok(f"d = {d}")
        ok(f"p = {p}")
        ok(f"q = {q}")
        if c_str:
            c = int(c_str)
            pt = rsa_decrypt(c, d, n)
            print_result(pt, "Plaintext")
    else:
        warn("Wiener's attack failed")

def _interactive_rsa_hastad():
    section("HASTAD BROADCAST ATTACK")
    from modules.rsa_attacks import hastad_broadcast
    e = int(_get("e (must be small, e.g. 3)"))
    k = int(_get("How many (n, c) pairs?"))
    ns, cs = [], []
    for i in range(k):
        ns.append(int(_get(f"n[{i+1}]")))
        cs.append(int(_get(f"c[{i+1}]")))
    result = hastad_broadcast(cs, ns, e)
    if result:
        print_result(result, "Plaintext")
    else:
        warn("Attack failed (need at least e pairs)")

def _interactive_aes(choice):
    section("AES")
    from modules.aes_attacks import (aes_ecb_encrypt, aes_ecb_decrypt, aes_cbc_encrypt,
                                      aes_cbc_decrypt, aes_ctr_encrypt, BLOCK)
    key_hex = _get("Key (hex)")
    key = bytes.fromhex(key_hex.replace('0x','').replace(' ',''))
    mode = _get("Mode [ECB/CBC/CTR]", 'ECB').upper()
    iv_hex = _get("IV/Nonce (hex, blank for zeros)", None)
    iv = bytes.fromhex(iv_hex.replace('0x','')) if iv_hex else bytes(BLOCK)
    
    data_str = _get("Data (hex with 0x, or text)")
    if data_str.startswith('0x'):
        data = bytes.fromhex(data_str[2:])
    else:
        data = data_str.encode()
    
    encrypt = choice == '13'
    try:
        if mode == 'ECB':
            result = aes_ecb_encrypt(key, data) if encrypt else aes_ecb_decrypt(key, data)
        elif mode == 'CBC':
            result = aes_cbc_encrypt(key, iv, data) if encrypt else aes_cbc_decrypt(key, iv, data)
        elif mode == 'CTR':
            n = int.from_bytes(iv[:8], 'big')
            result = aes_ctr_encrypt(key, n, data)
        print_result(result)
    except Exception as e:
        err(f"AES operation failed: {e}")

def _interactive_number_theory():
    section("NUMBER THEORY TOOLS")
    from modules.rsa_attacks import modinv, crt, fermat_factor
    from modules.pqc_ec import tonelli_shanks, bsgs_multiplicative
    
    opts = {
        '1': ('Modular inverse', lambda: ok(str(modinv(int(_get("a")), int(_get("m")))))),
        '2': ('Fermat factoring', lambda: ok(str(fermat_factor(int(_get("n")))))),
        '3': ('Tonelli-Shanks sqrt', lambda: ok(str(tonelli_shanks(int(_get("n")), int(_get("p")))))),
        '4': ('Discrete log BSGS', lambda: ok(str(bsgs_multiplicative(int(_get("g")), int(_get("h")), int(_get("order")), int(_get("p")))))),
    }
    for k, (name, _) in opts.items():
        print(f"  [{k}] {name}")
    choice = _get("Select")
    if choice in opts:
        try:
            opts[choice][1]()
        except Exception as e:
            err(str(e))

# ─── Main Parser ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog='ctf_crypto',
        description='CTF Cryptography Toolkit - CryptoHack Ready',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ctf_crypto.py encode -d "Hello World" -f base64
  python ctf_crypto.py decode -d "SGVsbG8=" -f base64
  python ctf_crypto.py decode -d "your_data" -f auto
  python ctf_crypto.py caesar -d "URYYB JBEYQ" --bruteforce
  python ctf_crypto.py vigenere -d "CIPHERTEXT" --crack
  python ctf_crypto.py xor -d "hex_data" --crack
  python ctf_crypto.py rsa --n 1234 --e 65537 --c 5678 --decrypt
  python ctf_crypto.py rsa --n 1234 --e 3 --c 5678 --wiener
  python ctf_crypto.py aes --key deadbeef... --mode CBC --iv 00... -d hex --decrypt
  python ctf_crypto.py hash -d "password" --algorithm sha256
  python ctf_crypto.py hash --crack 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5
  python ctf_crypto.py classical -d "XUBBM YMZBT"
        """
    )
    
    sub = parser.add_subparsers(dest='command')
    
    # Encode
    p_enc = sub.add_parser('encode', help='Encode data')
    p_enc.add_argument('-d', '--data', help='Input string')
    p_enc.add_argument('-f', '--file', help='Input file')
    p_enc.add_argument('--format', default='all',
                       choices=['base64','base32','hex','binary','decimal','octal','base58','base85','morse','all'])
    
    # Decode  
    p_dec = sub.add_parser('decode', help='Decode data')
    p_dec.add_argument('-d', '--data', help='Input string')
    p_dec.add_argument('-f', '--file', help='Input file')
    p_dec.add_argument('--format', default='auto',
                       choices=['base64','base32','hex','binary','decimal','octal','base58','base85','morse','auto'])
    
    # Hash
    p_hash = sub.add_parser('hash', help='Hash and crack hashes')
    p_hash.add_argument('-d', '--data', help='Data to hash')
    p_hash.add_argument('-f', '--file', help='File to hash')
    p_hash.add_argument('--crack', help='Hash to crack')
    p_hash.add_argument('--wordlist', help='Wordlist file')
    p_hash.add_argument('--identify', help='Identify hash type')
    p_hash.add_argument('--algorithm', default='sha256')
    
    # XOR
    p_xor = sub.add_parser('xor', help='XOR analysis')
    p_xor.add_argument('-d', '--data', help='Data (hex or text)')
    p_xor.add_argument('-f', '--file', help='Input file')
    p_xor.add_argument('--hex', action='store_true', help='Input is hex')
    p_xor.add_argument('--key', help='XOR key (hex)')
    p_xor.add_argument('--keylen', help='Force key length')
    p_xor.add_argument('--crack', action='store_true', help='Auto-crack XOR')
    
    # Caesar
    p_c = sub.add_parser('caesar', help='Caesar cipher')
    p_c.add_argument('-d', '--data', help='Text')
    p_c.add_argument('--shift', type=int, help='Shift value')
    p_c.add_argument('--encrypt', action='store_true')
    p_c.add_argument('--bruteforce', action='store_true')
    p_c.add_argument('--rot13', action='store_true')
    p_c.add_argument('--rot47', action='store_true')
    
    # Vigenere
    p_v = sub.add_parser('vigenere', help='Vigenere cipher')
    p_v.add_argument('-d', '--data', help='Text')
    p_v.add_argument('--key')
    p_v.add_argument('--encrypt', action='store_true')
    p_v.add_argument('--crack', action='store_true')
    p_v.add_argument('--maxkey', type=int, default=12)
    
    # Classical auto
    p_cl = sub.add_parser('classical', help='Auto-solve classical ciphers')
    p_cl.add_argument('-d', '--data', help='Ciphertext')
    
    # RSA
    p_rsa = sub.add_parser('rsa', help='RSA attacks')
    p_rsa.add_argument('--n', help='Modulus')
    p_rsa.add_argument('--e', help='Public exponent')
    p_rsa.add_argument('--c', help='Ciphertext integer')
    p_rsa.add_argument('--p', help='Prime p')
    p_rsa.add_argument('--q', help='Prime q')
    p_rsa.add_argument('--d', help='Private exponent')
    p_rsa.add_argument('--wiener', action='store_true', help="Wiener's attack")
    p_rsa.add_argument('--hastad', action='store_true', help="Hastad broadcast")
    p_rsa.add_argument('--factor', action='store_true', help='Factor n')
    p_rsa.add_argument('--decrypt', action='store_true', help='Auto-solve & decrypt')
    p_rsa.add_argument('--keygen', help='Generate key (specify bits)')
    
    # AES
    p_aes = sub.add_parser('aes', help='AES operations')
    p_aes.add_argument('-d', '--data', help='Data (text or hex)')
    p_aes.add_argument('-f', '--file', help='Input file')
    p_aes.add_argument('--hex', action='store_true')
    p_aes.add_argument('--key', help='Key (hex)')
    p_aes.add_argument('--iv', help='IV (hex, for CBC)')
    p_aes.add_argument('--nonce', help='Nonce (hex, for CTR/GCM)')
    p_aes.add_argument('--tag', help='GCM auth tag (hex)')
    p_aes.add_argument('--mode', default='ECB', choices=['ECB','CBC','CTR','GCM'])
    p_aes.add_argument('--encrypt', action='store_true')
    p_aes.add_argument('--decrypt', action='store_true')
    p_aes.add_argument('--detect', action='store_true', help='Detect AES mode')
    
    args = parser.parse_args()
    
    if args.command is None:
        banner()
        cmd_interactive()
        return
    
    banner()
    
    dispatch = {
        'encode': cmd_encode,
        'decode': cmd_decode,
        'hash': cmd_hash,
        'xor': cmd_xor,
        'caesar': cmd_caesar,
        'vigenere': cmd_vigenere,
        'classical': cmd_classical,
        'rsa': cmd_rsa,
        'aes': cmd_aes,
    }
    
    if args.command in dispatch:
        dispatch[args.command](args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
