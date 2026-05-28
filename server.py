#!/usr/bin/env python3
"""
CTF Crypto Toolkit - Web Server
Run: python server.py [--port 5000]
"""

import sys
import os
import json
import traceback
from pathlib import Path
from flask import Flask, request, jsonify, render_template_string

sys.path.insert(0, str(Path(__file__).parent))

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

def safe_run(fn, *args, **kwargs):
    try:
        result = fn(*args, **kwargs)
        return {'success': True, 'result': result}
    except Exception as e:
        return {'success': False, 'error': str(e), 'trace': traceback.format_exc()}

def to_serializable(obj):
    if isinstance(obj, bytes):
        try:
            text = obj.decode('utf-8', 'replace')
        except Exception:
            text = repr(obj)
        return {'hex': obj.hex(), 'text': text, 'base64': __import__('base64').b64encode(obj).decode()}
    if isinstance(obj, (list, tuple)):
        return [to_serializable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, int) and obj > 2**53:
        return str(obj)
    return obj

# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route('/api/encode', methods=['POST'])
def api_encode():
    data = request.json
    fmt = data.get('format', 'base64')
    raw = data.get('data', '')
    
    # Parse input
    if data.get('input_type') == 'hex':
        raw_bytes = bytes.fromhex(raw.replace('0x','').replace(' ',''))
    else:
        raw_bytes = raw.encode() if isinstance(raw, str) else raw
    
    from modules.encoding import (to_base64, to_base32, to_hex, to_binary,
                                   to_decimal, to_octal, to_base58, to_base85, to_morse)
    encoders = {
        'base64': to_base64, 'base32': to_base32, 'hex': to_hex,
        'binary': to_binary, 'decimal': to_decimal, 'octal': to_octal,
        'base58': to_base58, 'base85': to_base85,
    }
    
    if fmt == 'all':
        results = {}
        for name, fn in encoders.items():
            try:
                results[name] = fn(raw_bytes)
            except Exception as e:
                results[name] = f'ERROR: {e}'
        try:
            results['morse'] = to_morse(raw_bytes.decode('utf-8', 'replace'))
        except Exception:
            pass
        return jsonify({'success': True, 'results': results})
    elif fmt == 'morse':
        return jsonify({'success': True, 'result': to_morse(raw_bytes.decode('utf-8', 'replace'))})
    elif fmt in encoders:
        return jsonify({'success': True, 'result': encoders[fmt](raw_bytes)})
    else:
        return jsonify({'success': False, 'error': f'Unknown format: {fmt}'})

@app.route('/api/decode', methods=['POST'])
def api_decode():
    data = request.json
    fmt = data.get('format', 'auto')
    raw = data.get('data', '').strip()
    
    from modules.encoding import (from_base64, from_base32, from_hex, from_binary,
                                   from_decimal, from_octal, from_base58, from_base85,
                                   from_morse, auto_decode)
    decoders = {
        'base64': from_base64, 'base32': from_base32, 'hex': from_hex,
        'binary': from_binary, 'decimal': from_decimal, 'octal': from_octal,
        'base58': from_base58, 'base85': from_base85,
    }
    
    if fmt == 'auto':
        results = auto_decode(raw)
        return jsonify({'success': True, 'results': [
            {'method': r['method'], 'printable': r['printable'], 
             'hex': r['result'].hex() if isinstance(r['result'], bytes) else ''}
            for r in results
        ]})
    elif fmt == 'morse':
        return jsonify({'success': True, 'result': from_morse(raw)})
    elif fmt in decoders:
        try:
            result = decoders[fmt](raw)
            return jsonify({'success': True, 'result': to_serializable(result)})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    return jsonify({'success': False, 'error': f'Unknown format: {fmt}'})

@app.route('/api/hash', methods=['POST'])
def api_hash():
    data = request.json
    action = data.get('action', 'hash')
    
    if action == 'hash':
        from modules.encoding import hash_data
        raw = data.get('data', '').encode()
        algo = data.get('algorithm', 'sha256')
        return jsonify({'success': True, 'result': hash_data(raw, algo), 'algorithm': algo})
    
    elif action == 'crack':
        from modules.encoding import crack_hash_wordlist, crack_hash_digits, crack_hash_bruteforce
        target = data.get('hash', '')
        algo = data.get('algorithm', 'md5')
        wordlist = data.get('wordlist', [])
        
        if wordlist:
            result = crack_hash_wordlist(target, wordlist, algo)
        else:
            max_len = data.get('max_length', 6)
            charset = data.get('charset', '0123456789')
            result = crack_hash_bruteforce(target, charset, max_len, algo)
        
        if result:
            return jsonify({'success': True, 'cracked': result})
        return jsonify({'success': True, 'cracked': None, 'message': 'Not found'})
    
    elif action == 'identify':
        from modules.encoding import hash_identifier
        h = data.get('hash', '')
        return jsonify({'success': True, 'candidates': hash_identifier(h)})

@app.route('/api/xor', methods=['POST'])
def api_xor():
    data = request.json
    
    raw = data.get('data', '')
    if data.get('input_type') == 'hex' or raw.startswith('0x'):
        raw_bytes = bytes.fromhex(raw.replace('0x','').replace(' ',''))
    else:
        raw_bytes = raw.encode()
    
    if 'key' in data and data['key']:
        from modules.encoding import xor_with_key
        key_hex = data['key'].replace('0x','').replace(' ','')
        key = bytes.fromhex(key_hex)
        result = xor_with_key(raw_bytes, key)
        return jsonify({'success': True, 'result': to_serializable(result)})
    else:
        from modules.encoding import auto_crack_xor
        results = auto_crack_xor(raw_bytes)
        serialized = []
        for r in results[:5]:
            try:
                text = bytes(r['text']).decode('utf-8', 'replace')
            except Exception:
                text = repr(r['text'])
            serialized.append({'key': r['key'], 'key_len': r['key_len'], 'text': text, 'score': r['score']})
        return jsonify({'success': True, 'results': serialized})

@app.route('/api/classical', methods=['POST'])
def api_classical():
    data = request.json
    action = data.get('action', 'auto')
    text = data.get('text', '')
    
    if action == 'auto':
        from modules.classical import auto_detect_classical
        results = auto_detect_classical(text)
        serialized = []
        for r in results[:10]:
            t = r['text'] if isinstance(r['text'], str) else r['text'].decode('utf-8', 'replace')
            serialized.append({'method': r['method'], 'text': t, 'score': r['score']})
        return jsonify({'success': True, 'results': serialized})
    
    elif action == 'caesar':
        from modules.classical import caesar_encrypt, caesar_decrypt, caesar_bruteforce
        shift = data.get('shift')
        if shift is None:
            results = caesar_bruteforce(text)
            return jsonify({'success': True, 'results': results[:5]})
        direction = data.get('direction', 'decrypt')
        fn = caesar_encrypt if direction == 'encrypt' else caesar_decrypt
        return jsonify({'success': True, 'result': fn(text, int(shift))})
    
    elif action == 'vigenere':
        key = data.get('key')
        direction = data.get('direction', 'decrypt')
        from modules.classical import vigenere_encrypt, vigenere_decrypt, vigenere_crack
        if key:
            fn = vigenere_encrypt if direction == 'encrypt' else vigenere_decrypt
            return jsonify({'success': True, 'result': fn(text, key)})
        else:
            maxkl = data.get('max_key_length', 12)
            results = vigenere_crack(text, maxkl)
            return jsonify({'success': True, 'results': [
                {'key': r['key'], 'key_length': r['key_length'], 'text': r['text']}
                for r in results[:5]
            ]})
    
    elif action == 'substitution':
        from modules.classical import substitution_crack_frequency
        result = substitution_crack_frequency(text)
        return jsonify({'success': True, 'key': result['key'], 
                       'mapping': {k: v for k, v in result['mapping'].items()},
                       'text': result['text']})
    
    elif action == 'rail_fence':
        from modules.classical import rail_fence_encrypt, rail_fence_decrypt, rail_fence_bruteforce
        rails = data.get('rails')
        direction = data.get('direction', 'decrypt')
        if rails:
            fn = rail_fence_encrypt if direction == 'encrypt' else rail_fence_decrypt
            return jsonify({'success': True, 'result': fn(text, int(rails))})
        else:
            results = rail_fence_bruteforce(text)
            return jsonify({'success': True, 'results': results[:5]})
    
    elif action == 'affine':
        from modules.classical import affine_encrypt, affine_decrypt, affine_bruteforce
        a = data.get('a')
        b = data.get('b')
        direction = data.get('direction', 'decrypt')
        if a is not None and b is not None:
            fn = affine_encrypt if direction == 'encrypt' else affine_decrypt
            return jsonify({'success': True, 'result': fn(text, int(a), int(b))})
        else:
            return jsonify({'success': True, 'results': affine_bruteforce(text)[:5]})
    
    elif action == 'playfair':
        from modules.classical import playfair_encrypt, playfair_decrypt
        key = data.get('key', 'KEY')
        direction = data.get('direction', 'decrypt')
        fn = playfair_encrypt if direction == 'encrypt' else playfair_decrypt
        return jsonify({'success': True, 'result': fn(text, key)})
    
    return jsonify({'success': False, 'error': f'Unknown action: {action}'})

@app.route('/api/rsa', methods=['POST'])
def api_rsa():
    data = request.json
    action = data.get('action', 'auto')
    
    def pi(k):
        v = data.get(k)
        if v is None:
            return None
        v = str(v).strip()
        if v.startswith('0x'):
            return int(v, 16)
        return int(v) if v else None
    
    n, e, c = pi('n'), pi('e'), pi('c')
    p, q, d = pi('p'), pi('q'), pi('d')
    
    if action == 'auto':
        from modules.rsa_attacks import rsa_auto_solve
        result = rsa_auto_solve(n, e, c, p, q, d)
        return jsonify({'success': True, 'result': to_serializable(result)})
    
    elif action == 'wiener':
        from modules.rsa_attacks import wiener_attack, rsa_decrypt
        result = wiener_attack(e, n)
        if result:
            d_w, p_w, q_w = result
            resp = {'found': True, 'd': str(d_w), 'p': str(p_w), 'q': str(q_w)}
            if c:
                pt = rsa_decrypt(c, d_w, n)
                resp['plaintext'] = to_serializable(pt)
            return jsonify({'success': True, 'result': resp})
        return jsonify({'success': True, 'result': {'found': False}})
    
    elif action == 'hastad':
        from modules.rsa_attacks import hastad_broadcast
        ciphertexts = [int(x) for x in data.get('ciphertexts', [])]
        moduli = [int(x) for x in data.get('moduli', [])]
        result = hastad_broadcast(ciphertexts, moduli, e)
        return jsonify({'success': True, 'result': to_serializable(result) if result else None})
    
    elif action == 'factor':
        from modules.rsa_attacks import smooth_factor, modinv, rsa_decrypt
        result = smooth_factor(n)
        if result:
            resp = {'found': True, 'method': result['method'],
                   'p': str(result['p']), 'q': str(result['q'])}
            if e and c:
                phi = (result['p'] - 1) * (result['q'] - 1)
                d_calc = modinv(e, phi)
                pt = rsa_decrypt(c, d_calc, n)
                resp['d'] = str(d_calc)
                resp['plaintext'] = to_serializable(pt)
            return jsonify({'success': True, 'result': resp})
        return jsonify({'success': True, 'result': {'found': False, 'message': 'Could not factor n'}})
    
    elif action == 'keygen':
        from modules.rsa_attacks import rsa_keygen
        bits = int(data.get('bits', 512))
        e_val = int(data.get('e', 65537))
        key = rsa_keygen(bits, e_val)
        return jsonify({'success': True, 'result': {k: str(v) for k, v in key.items()}})
    
    elif action == 'encrypt' or action == 'decrypt':
        from modules.rsa_attacks import rsa_encrypt, rsa_decrypt, long_to_bytes
        if action == 'encrypt':
            pt_str = data.get('plaintext', '')
            pt = pt_str.encode() if isinstance(pt_str, str) else bytes.fromhex(pt_str)
            ct = rsa_encrypt(pt, e, n)
            return jsonify({'success': True, 'result': str(ct)})
        else:
            pt = rsa_decrypt(c, d, n)
            return jsonify({'success': True, 'result': to_serializable(pt)})
    
    return jsonify({'success': False, 'error': f'Unknown action: {action}'})

@app.route('/api/aes', methods=['POST'])
def api_aes():
    data = request.json
    action = data.get('action', 'encrypt')
    mode = data.get('mode', 'ECB').upper()
    
    def parse_hex(s, default_len=None):
        if not s:
            return bytes(default_len) if default_len else None
        s = str(s).replace('0x','').replace(' ','')
        return bytes.fromhex(s)
    
    key = parse_hex(data.get('key'))
    iv = parse_hex(data.get('iv'), 16)
    nonce = parse_hex(data.get('nonce'), 8)
    raw = data.get('data', '')
    
    if data.get('input_type') == 'hex' or (isinstance(raw, str) and raw.startswith('0x')):
        raw_bytes = bytes.fromhex(str(raw).replace('0x','').replace(' ',''))
    elif isinstance(raw, str):
        raw_bytes = raw.encode()
    else:
        raw_bytes = bytes(raw)
    
    from modules.aes_attacks import (
        aes_ecb_encrypt, aes_ecb_decrypt, aes_cbc_encrypt, aes_cbc_decrypt,
        aes_ctr_encrypt, aes_gcm_encrypt, aes_gcm_decrypt, ecb_detect, auto_detect_aes_mode
    )
    
    if action == 'detect':
        mode_guess = auto_detect_aes_mode(raw_bytes)
        dup = ecb_detect(raw_bytes)
        return jsonify({'success': True, 'mode': mode_guess, 'has_duplicate_blocks': dup})
    
    try:
        if action == 'encrypt':
            if mode == 'ECB':
                result = aes_ecb_encrypt(key, raw_bytes)
            elif mode == 'CBC':
                result = aes_cbc_encrypt(key, iv, raw_bytes)
            elif mode == 'CTR':
                n = int.from_bytes(nonce[:8], 'big')
                result = aes_ctr_encrypt(key, n, raw_bytes)
            elif mode == 'GCM':
                ct, tag = aes_gcm_encrypt(key, nonce, raw_bytes)
                return jsonify({'success': True, 'result': to_serializable(ct), 'tag': tag.hex()})
        else:
            if mode == 'ECB':
                result = aes_ecb_decrypt(key, raw_bytes)
            elif mode == 'CBC':
                result = aes_cbc_decrypt(key, iv, raw_bytes)
            elif mode == 'CTR':
                n = int.from_bytes(nonce[:8], 'big')
                result = aes_ctr_encrypt(key, n, raw_bytes)
            elif mode == 'GCM':
                tag = parse_hex(data.get('tag'), 16)
                result = aes_gcm_decrypt(key, nonce, raw_bytes, tag)
        
        return jsonify({'success': True, 'result': to_serializable(result)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ctr_attack', methods=['POST'])
def api_ctr_attack():
    data = request.json
    action = data.get('action', 'nonce_reuse')
    
    if action == 'nonce_reuse':
        from modules.aes_attacks import ctr_nonce_reuse_attack
        ciphertexts = [bytes.fromhex(c) for c in data.get('ciphertexts', [])]
        keystream = ctr_nonce_reuse_attack(ciphertexts)
        return jsonify({'success': True, 'keystream': keystream.hex()})
    
    elif action == 'known_pt':
        from modules.aes_attacks import ctr_keystream_from_known_plaintext
        ct = bytes.fromhex(data.get('ciphertext', ''))
        pt = data.get('plaintext', '').encode()
        ks = ctr_keystream_from_known_plaintext(ct, pt)
        return jsonify({'success': True, 'keystream': ks.hex()})

@app.route('/api/ec', methods=['POST'])
def api_ec():
    data = request.json
    action = data.get('action', 'bsgs')
    
    if action == 'bsgs_mul':
        from modules.pqc_ec import EllipticCurve, baby_step_giant_step
        a, b, p = int(data['a']), int(data['b']), int(data['p'])
        curve = EllipticCurve(a, b, p)
        G = (int(data['Gx']), int(data['Gy']))
        Q = (int(data['Qx']), int(data['Qy']))
        order = int(data['order'])
        result = baby_step_giant_step(G, Q, order, curve)
        return jsonify({'success': True, 'result': result})
    
    elif action == 'ecdsa_k_reuse':
        from modules.pqc_ec import ecdsa_k_reuse_attack
        r = int(data['r'])
        s1, s2 = int(data['s1']), int(data['s2'])
        z1, z2 = int(data['z1']), int(data['z2'])
        n = int(data['n'])
        result = ecdsa_k_reuse_attack(r, s1, s2, z1, z2, n)
        if result:
            k, d = result
            return jsonify({'success': True, 'k': str(k), 'd': str(d)})
        return jsonify({'success': True, 'result': None})
    
    elif action == 'pohlig':
        from modules.pqc_ec import dh_pohlig_hellman
        g = int(data['g'])
        h = int(data['h'])
        p = int(data['p'])
        result = dh_pohlig_hellman(g, h, p)
        return jsonify({'success': True, 'result': str(result) if result is not None else None})
    
    elif action == 'point_add':
        from modules.pqc_ec import EllipticCurve
        a, b, p = int(data['a']), int(data['b']), int(data['p'])
        curve = EllipticCurve(a, b, p)
        P = (int(data['Px']), int(data['Py']))
        Q = (int(data['Qx']), int(data['Qy']))
        result = curve.point_add(P, Q)
        return jsonify({'success': True, 'result': list(result) if result else None})
    
    elif action == 'scalar_mult':
        from modules.pqc_ec import EllipticCurve
        a, b, p = int(data['a']), int(data['b']), int(data['p'])
        curve = EllipticCurve(a, b, p)
        P = (int(data['Px']), int(data['Py']))
        k = int(data['k'])
        result = curve.scalar_mult(k, P)
        return jsonify({'success': True, 'result': list(result) if result else None})

@app.route('/api/number_theory', methods=['POST'])
def api_number_theory():
    data = request.json
    action = data.get('action')
    
    if action == 'modinv':
        from modules.rsa_attacks import modinv
        return jsonify({'success': True, 'result': str(modinv(int(data['a']), int(data['m'])))})
    
    elif action == 'crt':
        from modules.rsa_attacks import crt
        residues = [int(x) for x in data['residues']]
        moduli = [int(x) for x in data['moduli']]
        return jsonify({'success': True, 'result': str(crt(residues, moduli))})
    
    elif action == 'tonelli':
        from modules.pqc_ec import tonelli_shanks
        return jsonify({'success': True, 'result': str(tonelli_shanks(int(data['n']), int(data['p'])))})
    
    elif action == 'bsgs':
        from modules.pqc_ec import bsgs_multiplicative
        g, h, order, p = int(data['g']), int(data['h']), int(data['order']), int(data['p'])
        return jsonify({'success': True, 'result': str(bsgs_multiplicative(g, h, order, p))})
    
    elif action == 'fermat':
        from modules.rsa_attacks import fermat_factor
        result = fermat_factor(int(data['n']))
        if result:
            return jsonify({'success': True, 'p': str(result[0]), 'q': str(result[1])})
        return jsonify({'success': True, 'result': None})
    
    elif action == 'iroot':
        from modules.rsa_attacks import iroot
        root, exact = iroot(int(data['n']), int(data['k']))
        return jsonify({'success': True, 'root': str(root), 'exact': exact})
    
    elif action == 'gcd':
        import math
        return jsonify({'success': True, 'result': str(math.gcd(int(data['a']), int(data['b'])))})
    
    elif action == 'factor':
        from sympy import factorint
        factors = factorint(int(data['n']))
        return jsonify({'success': True, 'result': {str(k): v for k, v in factors.items()}})

# ─── Web UI ───────────────────────────────────────────────────────────────────

HTML = open(Path(__file__).parent / 'static' / 'index.html').read()

@app.route('/')
def index():
    return HTML

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'version': '1.0'})

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()
    
    print(f"""
╔══════════════════════════════════════════════╗
║   CTF Crypto Toolkit - Web Server           ║
║   Listening on http://{args.host}:{args.port}        ║
╚══════════════════════════════════════════════╝
""")
    app.run(host=args.host, port=args.port, debug=args.debug)
