"""
Classical Cipher Attacks & Solvers
Covers: Caesar, ROT13, Vigenere, Substitution, Atbash, Playfair, Rail Fence,
        Columnar Transposition, Affine, Beaufort, Running Key, Autokey
"""

import string
import itertools
from collections import Counter
from typing import Optional

ENGLISH_FREQ = {
    'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
    's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8,
    'u': 2.8, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0,
    'p': 1.9, 'b': 1.5, 'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15,
    'q': 0.10, 'z': 0.07
}

ENGLISH_BIGRAMS = ['th','he','in','er','an','re','on','en','at','ou','ea','hi','is','or','ti']

def index_of_coincidence(text: str) -> float:
    text = ''.join(c.lower() for c in text if c.isalpha())
    n = len(text)
    if n < 2:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

def frequency_score(text: str) -> float:
    text = text.lower()
    freq = Counter(c for c in text if c.isalpha())
    total = sum(freq.values())
    if total == 0:
        return 0.0
    score = sum(abs(freq.get(c, 0) / total * 100 - ENGLISH_FREQ.get(c, 0))
                for c in string.ascii_lowercase)
    return -score  # higher = better

def is_english_word(text: str, threshold: float = 0.4) -> bool:
    """Heuristic English detection."""
    COMMON = set('the and ing ion tio ent ation for that this with have from'.split())
    text = text.lower()
    hits = sum(1 for w in COMMON if w in text)
    return hits >= 3

# ─── Caesar / ROT13 ───────────────────────────────────────────────────────────

def caesar_encrypt(text: str, shift: int) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)

def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)

def caesar_bruteforce(text: str) -> list[dict]:
    results = []
    for shift in range(26):
        decrypted = caesar_decrypt(text, shift)
        results.append({
            'shift': shift,
            'text': decrypted,
            'score': frequency_score(decrypted)
        })
    return sorted(results, key=lambda x: x['score'], reverse=True)

def rot13(text: str) -> str:
    return caesar_encrypt(text, 13)

def rot47(text: str) -> str:
    result = []
    for ch in text:
        if 33 <= ord(ch) <= 126:
            result.append(chr((ord(ch) - 33 + 47) % 94 + 33))
        else:
            result.append(ch)
    return ''.join(result)

# ─── Atbash ───────────────────────────────────────────────────────────────────

def atbash(text: str) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr(base + 25 - (ord(ch) - base)))
        else:
            result.append(ch)
    return ''.join(result)

# ─── Affine ───────────────────────────────────────────────────────────────────

def affine_encrypt(text: str, a: int, b: int) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((a * (ord(ch) - base) + b) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)

def affine_decrypt(text: str, a: int, b: int) -> str:
    from sympy import mod_inverse
    try:
        a_inv = mod_inverse(a, 26)
    except Exception:
        return "Error: 'a' has no inverse mod 26"
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr(a_inv * (ord(ch) - base - b) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)

def affine_bruteforce(text: str) -> list[dict]:
    from sympy import mod_inverse
    results = []
    valid_a = [a for a in range(1, 26) if __import__('math').gcd(a, 26) == 1]
    for a in valid_a:
        for b in range(26):
            dec = affine_decrypt(text, a, b)
            results.append({'a': a, 'b': b, 'text': dec, 'score': frequency_score(dec)})
    return sorted(results, key=lambda x: x['score'], reverse=True)[:10]

# ─── Vigenere ─────────────────────────────────────────────────────────────────

def vigenere_encrypt(text: str, key: str) -> str:
    key = key.upper()
    result, ki = [], 0
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[ki % len(key)]) - ord('A')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)

def vigenere_decrypt(text: str, key: str) -> str:
    key = key.upper()
    result, ki = [], 0
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[ki % len(key)]) - ord('A')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)

def kasiski_test(text: str) -> list[int]:
    """Find likely key lengths via Kasiski examination."""
    text = ''.join(c.upper() for c in text if c.isalpha())
    spacings = []
    for length in range(3, 6):
        for i in range(len(text) - length):
            trigram = text[i:i+length]
            j = text.find(trigram, i + length)
            while j != -1:
                spacings.append(j - i)
                j = text.find(trigram, j + 1)
    if not spacings:
        return []
    import math
    factors = Counter()
    for s in spacings:
        for f in range(2, min(s + 1, 21)):
            if s % f == 0:
                factors[f] += 1
    return [k for k, _ in factors.most_common(5)]

def vigenere_crack(text: str, max_key_len: int = 12) -> list[dict]:
    """Crack Vigenere using IoC + frequency analysis."""
    alpha = ''.join(c.upper() for c in text if c.isalpha())
    results = []
    # Try key lengths 1-max_key_len
    key_lengths = kasiski_test(text) or list(range(1, max_key_len + 1))
    # Always check 1-max_key_len
    key_lengths = sorted(set(key_lengths) | set(range(1, max_key_len + 1)))[:max_key_len]

    for kl in key_lengths:
        # Split into streams
        streams = [alpha[i::kl] for i in range(kl)]
        key = ''
        valid = True
        for stream in streams:
            best_shift = 0
            best_score = float('-inf')
            for shift in range(26):
                dec = caesar_decrypt(stream, shift)
                s = frequency_score(dec)
                if s > best_score:
                    best_score = s
                    best_shift = shift
            key += chr(best_shift + ord('A'))
        decrypted = vigenere_decrypt(text, key)
        results.append({
            'key_length': kl,
            'key': key,
            'text': decrypted,
            'score': frequency_score(decrypted)
        })
    return sorted(results, key=lambda x: x['score'], reverse=True)[:5]

# ─── Beaufort ─────────────────────────────────────────────────────────────────

def beaufort_encrypt(text: str, key: str) -> str:
    """Beaufort cipher (reciprocal - encrypt = decrypt)."""
    key = key.upper()
    result, ki = [], 0
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[ki % len(key)]) - ord('A')
            result.append(chr((shift - (ord(ch) - base)) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)

beaufort_decrypt = beaufort_encrypt  # reciprocal

# ─── Substitution ─────────────────────────────────────────────────────────────

def substitution_encrypt(text: str, key: str) -> str:
    """key is 26-char alphabet mapping A->key[0], B->key[1] etc."""
    key = key.upper()
    result = []
    for ch in text:
        if ch.isalpha():
            idx = ord(ch.upper()) - ord('A')
            mapped = key[idx]
            result.append(mapped if ch.isupper() else mapped.lower())
        else:
            result.append(ch)
    return ''.join(result)

def substitution_decrypt(text: str, key: str) -> str:
    key = key.upper()
    inv = [''] * 26
    for i, c in enumerate(key):
        inv[ord(c) - ord('A')] = chr(i + ord('A'))
    return substitution_encrypt(text, ''.join(inv))

def substitution_crack_frequency(ciphertext: str) -> dict:
    """Map cipher letters to English by frequency."""
    alpha = ''.join(c.upper() for c in ciphertext if c.isalpha())
    freq = Counter(alpha)
    english_by_freq = sorted(ENGLISH_FREQ.keys(), key=lambda c: ENGLISH_FREQ[c], reverse=True)
    cipher_by_freq = [c for c, _ in freq.most_common()]
    mapping = {}
    for c, e in zip(cipher_by_freq, english_by_freq):
        mapping[c] = e.upper()
    # Fill unmapped
    used = set(mapping.values())
    unused = [c.upper() for c in english_by_freq if c.upper() not in used]
    unmapped = [c for c in string.ascii_uppercase if c not in mapping]
    for c, u in zip(unmapped, unused):
        mapping[c] = u
    # Build key
    key = ''.join(mapping.get(chr(i + ord('A')), chr(i + ord('A'))) for i in range(26))
    decrypted = substitution_decrypt(ciphertext, key)
    return {'mapping': mapping, 'key': key, 'text': decrypted, 'score': frequency_score(decrypted)}

# ─── Rail Fence ───────────────────────────────────────────────────────────────

def rail_fence_encrypt(text: str, rails: int) -> str:
    if rails == 1:
        return text
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for ch in text:
        fence[rail].append(ch)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return ''.join(''.join(r) for r in fence)

def rail_fence_decrypt(text: str, rails: int) -> str:
    if rails == 1:
        return text
    n = len(text)
    indices = []
    rail, direction = 0, 1
    for i in range(n):
        indices.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    order = sorted(range(n), key=lambda i: indices[i])
    result = [''] * n
    for pos, ch in zip(order, text):
        result[pos] = ch
    return ''.join(result)

def rail_fence_bruteforce(text: str) -> list[dict]:
    results = []
    for rails in range(2, min(len(text), 15)):
        dec = rail_fence_decrypt(text, rails)
        results.append({'rails': rails, 'text': dec, 'score': frequency_score(dec)})
    return sorted(results, key=lambda x: x['score'], reverse=True)[:5]

# ─── Columnar Transposition ───────────────────────────────────────────────────

def columnar_encrypt(text: str, key: str) -> str:
    cols = len(key)
    # Pad
    pad = (cols - len(text) % cols) % cols
    text += 'X' * pad
    rows = len(text) // cols
    grid = [list(text[i*cols:(i+1)*cols]) for i in range(rows)]
    order = sorted(range(cols), key=lambda i: key[i])
    return ''.join(''.join(grid[r][c] for r in range(rows)) for c in order)

def columnar_decrypt(text: str, key: str) -> str:
    cols = len(key)
    rows = len(text) // cols
    order = sorted(range(cols), key=lambda i: key[i])
    columns = {}
    idx = 0
    for c in order:
        columns[c] = list(text[idx:idx+rows])
        idx += rows
    return ''.join(columns[c][r] for r in range(rows) for c in range(cols))

# ─── Playfair ─────────────────────────────────────────────────────────────────

def _playfair_square(key: str) -> list[list[str]]:
    key = key.upper().replace('J', 'I')
    seen, letters = set(), []
    for c in key + string.ascii_uppercase:
        if c not in seen and c != 'J':
            seen.add(c)
            letters.append(c)
    return [letters[i*5:(i+1)*5] for i in range(5)]

def _playfair_pos(square, ch):
    for r, row in enumerate(square):
        if ch in row:
            return r, row.index(ch)
    return None

def playfair_encrypt(text: str, key: str) -> str:
    square = _playfair_square(key)
    text = text.upper().replace('J', 'I')
    text = ''.join(c for c in text if c.isalpha())
    # Prepare digraphs
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else 'X'
        if a == b:
            pairs.append((a, 'X'))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    result = []
    for a, b in pairs:
        ra, ca = _playfair_pos(square, a)
        rb, cb = _playfair_pos(square, b)
        if ra == rb:
            result += [square[ra][(ca+1)%5], square[rb][(cb+1)%5]]
        elif ca == cb:
            result += [square[(ra+1)%5][ca], square[(rb+1)%5][cb]]
        else:
            result += [square[ra][cb], square[rb][ca]]
    return ''.join(result)

def playfair_decrypt(text: str, key: str) -> str:
    square = _playfair_square(key)
    text = text.upper().replace('J', 'I')
    text = ''.join(c for c in text if c.isalpha())
    pairs = [(text[i], text[i+1]) for i in range(0, len(text), 2)]
    result = []
    for a, b in pairs:
        ra, ca = _playfair_pos(square, a)
        rb, cb = _playfair_pos(square, b)
        if ra == rb:
            result += [square[ra][(ca-1)%5], square[rb][(cb-1)%5]]
        elif ca == cb:
            result += [square[(ra-1)%5][ca], square[(rb-1)%5][cb]]
        else:
            result += [square[ra][cb], square[rb][ca]]
    return ''.join(result)

# ─── Auto-detect & solve ───────────────────────────────────────────────────────

def auto_detect_classical(text: str) -> dict:
    """Try all classical ciphers and rank solutions."""
    results = []
    # Caesar
    for r in caesar_bruteforce(text)[:3]:
        results.append({'method': f"Caesar (shift={r['shift']})", 'text': r['text'], 'score': r['score']})
    # Atbash
    r = atbash(text)
    results.append({'method': 'Atbash', 'text': r, 'score': frequency_score(r)})
    # ROT13
    r = rot13(text)
    results.append({'method': 'ROT13', 'text': r, 'score': frequency_score(r)})
    # Affine
    for r in affine_bruteforce(text)[:3]:
        results.append({'method': f"Affine (a={r['a']},b={r['b']})", 'text': r['text'], 'score': r['score']})
    # Rail fence
    for r in rail_fence_bruteforce(text)[:3]:
        results.append({'method': f"Rail Fence ({r['rails']} rails)", 'text': r['text'], 'score': r['score']})
    # Vigenere
    for r in vigenere_crack(text)[:3]:
        results.append({'method': f"Vigenere (key={r['key']})", 'text': r['text'], 'score': r['score']})
    # Substitution
    r = substitution_crack_frequency(text)
    results.append({'method': 'Substitution (freq)', 'text': r['text'], 'score': r['score']})
    return sorted(results, key=lambda x: x['score'], reverse=True)
