"""
Encoding, Hashing & Data Utilities
Covers: Base encodings, hex, binary, various number bases, morse, NATO,
        hash cracking (wordlist/bruteforce), XOR analysis, entropy analysis
"""

import base64
import binascii
import hashlib
import string
import itertools
from typing import Optional

# ─── Base Encodings ───────────────────────────────────────────────────────────

def from_base64(data: str, url_safe: bool = False) -> bytes:
    data = data.strip()
    # Add padding
    pad = 4 - len(data) % 4
    if pad != 4:
        data += '=' * pad
    if url_safe:
        return base64.urlsafe_b64decode(data)
    return base64.b64decode(data)

def to_base64(data: bytes, url_safe: bool = False) -> str:
    if url_safe:
        return base64.urlsafe_b64encode(data).decode()
    return base64.b64encode(data).decode()

def from_base32(data: str) -> bytes:
    data = data.strip().upper()
    pad = 8 - len(data) % 8
    if pad != 8:
        data += '=' * pad
    return base64.b32decode(data)

def to_base32(data: bytes) -> str:
    return base64.b32encode(data).decode()

def from_base58(data: str) -> bytes:
    alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    base_count = len(alphabet)
    n = 0
    for char in data.encode():
        n = n * base_count + alphabet.index(char)
    result = []
    while n > 0:
        result.append(n % 256)
        n //= 256
    for char in data:
        if char == chr(alphabet[0]):
            result.append(0)
        else:
            break
    return bytes(reversed(result))

def to_base58(data: bytes) -> str:
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = int.from_bytes(data, 'big')
    result = ''
    while n > 0:
        result = alphabet[n % 58] + result
        n //= 58
    for byte in data:
        if byte == 0:
            result = '1' + result
        else:
            break
    return result

def from_base85(data: str) -> bytes:
    return base64.b85decode(data)

def to_base85(data: bytes) -> str:
    return base64.b85encode(data).decode()

def from_hex(data: str) -> bytes:
    data = data.strip().replace(' ', '').replace('0x', '').replace('\\x', '')
    return bytes.fromhex(data)

def to_hex(data: bytes, sep: str = '') -> str:
    return sep.join(f'{b:02x}' for b in data)

def from_binary(data: str) -> bytes:
    data = data.strip().replace(' ', '')
    result = []
    for i in range(0, len(data), 8):
        result.append(int(data[i:i+8], 2))
    return bytes(result)

def to_binary(data: bytes, sep: str = ' ') -> str:
    return sep.join(f'{b:08b}' for b in data)

def from_octal(data: str) -> bytes:
    data = data.strip().replace(' ', '')
    result = []
    for i in range(0, len(data), 3):
        result.append(int(data[i:i+3], 8))
    return bytes(result)

def to_octal(data: bytes) -> str:
    return ' '.join(f'{b:03o}' for b in data)

def from_decimal(data: str) -> bytes:
    """Space-separated decimal bytes to bytes."""
    return bytes(int(x) for x in data.strip().split())

def to_decimal(data: bytes) -> str:
    return ' '.join(str(b) for b in data)

def int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b'\x00'
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

# ─── Text Encodings ───────────────────────────────────────────────────────────

MORSE_CODE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--',
    '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...',
    ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-',
    '"': '.-..-.', '$': '...-..-', '@': '.--.-.'
}
MORSE_DECODE = {v: k for k, v in MORSE_CODE.items()}

def to_morse(text: str) -> str:
    return ' '.join(MORSE_CODE.get(c.upper(), '?') for c in text if c != ' ')

def from_morse(code: str) -> str:
    return ''.join(MORSE_DECODE.get(c, '?') for c in code.split())

NATO_ALPHABET = {
    'A': 'Alpha', 'B': 'Bravo', 'C': 'Charlie', 'D': 'Delta', 'E': 'Echo',
    'F': 'Foxtrot', 'G': 'Golf', 'H': 'Hotel', 'I': 'India', 'J': 'Juliet',
    'K': 'Kilo', 'L': 'Lima', 'M': 'Mike', 'N': 'November', 'O': 'Oscar',
    'P': 'Papa', 'Q': 'Quebec', 'R': 'Romeo', 'S': 'Sierra', 'T': 'Tango',
    'U': 'Uniform', 'V': 'Victor', 'W': 'Whiskey', 'X': 'X-ray', 'Y': 'Yankee',
    'Z': 'Zulu'
}
NATO_DECODE = {v.upper(): k for k, v in NATO_ALPHABET.items()}

def to_nato(text: str) -> str:
    return ' '.join(NATO_ALPHABET.get(c.upper(), c) for c in text)

def from_nato(words: str) -> str:
    return ''.join(NATO_DECODE.get(w.upper(), w[0]) for w in words.split())

# ─── XOR Operations ───────────────────────────────────────────────────────────

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def xor_with_key(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def single_byte_xor_score(data: bytes) -> tuple[int, bytes, float]:
    """Returns (key, decrypted, score)."""
    best_score = float('-inf')
    best_key = 0
    best_dec = b''
    for key in range(256):
        dec = bytes(b ^ key for b in data)
        score = sum(1 for c in dec if chr(c).lower() in ' etaoinshrdlu\n')
        score -= sum(10 for c in dec if c < 9 or (c > 13 and c < 32))
        if score > best_score:
            best_score = score
            best_key = key
            best_dec = dec
    return best_key, best_dec, best_score

def multi_byte_xor_crack(data: bytes, key_len: int) -> tuple[bytes, bytes]:
    """Crack repeating-key XOR."""
    key = bytearray()
    for i in range(key_len):
        block = data[i::key_len]
        k, _, _ = single_byte_xor_score(block)
        key.append(k)
    return bytes(key), xor_with_key(data, bytes(key))

def hamming_distance(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

def guess_xor_key_length(data: bytes, max_len: int = 40) -> list[tuple[int, float]]:
    """Guess XOR key length using normalized hamming distance."""
    results = []
    for kl in range(2, min(max_len + 1, len(data) // 2)):
        blocks = [data[i*kl:(i+1)*kl] for i in range(min(4, len(data) // kl))]
        if len(blocks) < 2:
            continue
        distances = []
        for i in range(len(blocks) - 1):
            dist = hamming_distance(blocks[i], blocks[i+1])
            distances.append(dist / kl)
        results.append((kl, sum(distances) / len(distances)))
    return sorted(results, key=lambda x: x[1])[:5]

def auto_crack_xor(data: bytes) -> list[dict]:
    """Auto crack XOR cipher."""
    results = []
    # Try single byte
    key, dec, score = single_byte_xor_score(data)
    results.append({'key': bytes([key]).hex(), 'key_len': 1, 'text': dec, 'score': score})
    
    # Try multi-byte
    for kl, _ in guess_xor_key_length(data):
        key_bytes, dec = multi_byte_xor_crack(data, kl)
        score = sum(1 for c in dec if chr(c).lower() in ' etaoinshrdlu')
        results.append({'key': key_bytes.hex(), 'key_len': kl, 'text': dec, 'score': score})
    
    return sorted(results, key=lambda x: x['score'], reverse=True)

# ─── Hashing ─────────────────────────────────────────────────────────────────

HASH_FUNCTIONS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha224': hashlib.sha224,
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512,
    'sha3_256': hashlib.sha3_256,
    'sha3_512': hashlib.sha3_512,
    'blake2b': hashlib.blake2b,
    'blake2s': hashlib.blake2s,
}

def hash_data(data: bytes, algorithm: str = 'sha256') -> str:
    fn = HASH_FUNCTIONS.get(algorithm.lower().replace('-', '_'))
    if not fn:
        raise ValueError(f"Unknown hash: {algorithm}")
    return fn(data).hexdigest()

def crack_hash_wordlist(target_hash: str, wordlist: list[str], algorithm: str = 'md5') -> str | None:
    target_hash = target_hash.lower().strip()
    fn = HASH_FUNCTIONS.get(algorithm.lower().replace('-', '_'))
    for word in wordlist:
        if fn(word.encode()).hexdigest() == target_hash:
            return word
    return None

def crack_hash_bruteforce(target_hash: str, charset: str = string.printable[:94],
                            max_len: int = 6, algorithm: str = 'md5') -> str | None:
    target_hash = target_hash.lower().strip()
    fn = HASH_FUNCTIONS.get(algorithm.lower().replace('-', '_'))
    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            attempt = ''.join(combo).encode()
            if fn(attempt).hexdigest() == target_hash:
                return ''.join(combo)
    return None

def crack_hash_digits(target_hash: str, max_len: int = 8, algorithm: str = 'md5') -> str | None:
    return crack_hash_bruteforce(target_hash, '0123456789', max_len, algorithm)

# ─── Entropy ─────────────────────────────────────────────────────────────────

def entropy(data: bytes) -> float:
    """Shannon entropy of bytes."""
    from collections import Counter
    import math
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())

def is_encrypted(data: bytes) -> bool:
    """Heuristic: entropy > 7.5 suggests encrypted/compressed."""
    return entropy(data) > 7.5

# ─── String Analysis ─────────────────────────────────────────────────────────

def strings_extract(data: bytes, min_len: int = 4) -> list[str]:
    """Extract printable strings from binary data."""
    result = []
    current = []
    for byte in data:
        ch = chr(byte)
        if ch.isprintable() and ch != '\n':
            current.append(ch)
        else:
            if len(current) >= min_len:
                result.append(''.join(current))
            current = []
    if len(current) >= min_len:
        result.append(''.join(current))
    return result

def auto_decode(data: str) -> list[dict]:
    """Try all decodings on a string."""
    results = []
    # Base64
    try:
        dec = from_base64(data)
        results.append({'method': 'Base64', 'result': dec, 'printable': dec.decode('utf-8', 'replace')})
    except Exception:
        pass
    # Hex
    try:
        dec = from_hex(data)
        results.append({'method': 'Hex', 'result': dec, 'printable': dec.decode('utf-8', 'replace')})
    except Exception:
        pass
    # Base32
    try:
        dec = from_base32(data)
        results.append({'method': 'Base32', 'result': dec, 'printable': dec.decode('utf-8', 'replace')})
    except Exception:
        pass
    # Binary
    try:
        clean = data.replace(' ', '').replace('\n', '')
        if all(c in '01' for c in clean) and len(clean) % 8 == 0:
            dec = from_binary(clean)
            results.append({'method': 'Binary', 'result': dec, 'printable': dec.decode('utf-8', 'replace')})
    except Exception:
        pass
    # ROT13
    from .classical import rot13
    dec = rot13(data)
    results.append({'method': 'ROT13', 'result': dec.encode(), 'printable': dec})
    # ROT47
    from .classical import rot47
    dec = rot47(data)
    results.append({'method': 'ROT47', 'result': dec.encode(), 'printable': dec})
    # URL decode
    try:
        from urllib.parse import unquote
        dec = unquote(data)
        if dec != data:
            results.append({'method': 'URL Decode', 'result': dec.encode(), 'printable': dec})
    except Exception:
        pass
    # HTML entities
    try:
        import html
        dec = html.unescape(data)
        if dec != data:
            results.append({'method': 'HTML Unescape', 'result': dec.encode(), 'printable': dec})
    except Exception:
        pass
    return results
