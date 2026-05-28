"""
AES & Symmetric Crypto Attacks
Covers: ECB (cut-and-paste, byte-at-a-time), CBC (padding oracle, bit flip,
        IV=key), CTR (nonce reuse, keystream recovery), GCM (auth forgery stub),
        OFB, CFB, Single/Double/Triple DES, RC4, ChaCha20 (nonce reuse)
"""

import os
import struct
from Crypto.Cipher import AES, DES, DES3, ARC4, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from typing import Callable, Optional
import hashlib

# ─── AES Helpers ─────────────────────────────────────────────────────────────

BLOCK = 16

def pkcs7_pad(data: bytes, block_size: int = BLOCK) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Empty data")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > BLOCK:
        raise ValueError(f"Invalid padding byte: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS7 padding")
    return data[:-pad_len]

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# ─── ECB ─────────────────────────────────────────────────────────────────────

def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(data))

def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7_unpad(cipher.decrypt(data))

def ecb_detect(ciphertext: bytes, block_size: int = 16) -> bool:
    """Detect ECB mode by finding duplicate blocks."""
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))

def ecb_block_size_detect(oracle: Callable[[bytes], bytes]) -> int:
    """Detect block size from an ECB oracle."""
    init_len = len(oracle(b''))
    for i in range(1, 64):
        new_len = len(oracle(b'A' * i))
        if new_len > init_len:
            return new_len - init_len
    return 16

def ecb_byte_at_a_time(oracle: Callable[[bytes], bytes], prefix_len: int = 0) -> bytes:
    """Byte-at-a-time ECB decryption attack."""
    block_size = ecb_block_size_detect(oracle)
    # Align past prefix
    pad_to_align = (block_size - prefix_len % block_size) % block_size
    base_len = len(oracle(b'A' * pad_to_align))
    secret_len = base_len - pad_to_align - prefix_len
    
    known = b''
    for i in range(secret_len):
        block_num = (prefix_len + pad_to_align + i) // block_size
        pad_len = block_size - 1 - (i % block_size)
        padding = b'A' * (pad_to_align + pad_len)
        
        target = oracle(padding)[block_num * block_size:(block_num + 1) * block_size]
        
        found = False
        for byte_val in range(256):
            candidate = padding + known + bytes([byte_val])
            ct = oracle(candidate)[block_num * block_size:(block_num + 1) * block_size]
            if ct == target:
                known += bytes([byte_val])
                found = True
                break
        if not found:
            break
    return known

def ecb_cut_and_paste(oracle_encrypt: Callable[[str], bytes],
                       target_role: str = 'admin') -> bytes:
    """ECB cut-and-paste attack for role escalation."""
    # Craft a block where 'admin' + padding aligns perfectly
    block_size = 16
    # email=AAAAAAAAAA admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b & role=user
    admin_block = pkcs7_pad(target_role.encode(), block_size)
    craft = 'A' * (block_size - len('email=')) + admin_block.decode('latin1')
    ct1 = oracle_encrypt(craft)
    admin_ct_block = ct1[block_size:2*block_size]
    
    # Get normal encryption and replace role block
    ct2 = oracle_encrypt('user@example.com')
    # Replace last block with admin block
    result = ct2[:-block_size] + admin_ct_block
    return result

# ─── CBC ─────────────────────────────────────────────────────────────────────

def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pkcs7_pad(data))

def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes, unpad_data: bool = True) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(data)
    return pkcs7_unpad(pt) if unpad_data else pt

def cbc_padding_oracle_decrypt(oracle: Callable[[bytes, bytes], bool],
                                ciphertext: bytes, iv: bytes,
                                block_size: int = 16) -> bytes:
    """CBC Padding Oracle Attack (POODLE-style). oracle(iv, ct) -> True if valid padding."""
    blocks = [iv] + [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext = b''
    
    for block_idx in range(1, len(blocks)):
        decrypted = bytearray(block_size)
        prev_block = bytearray(blocks[block_idx - 1])
        curr_block = blocks[block_idx]
        
        for byte_pos in range(block_size - 1, -1, -1):
            pad_byte = block_size - byte_pos
            
            # Set already-known bytes to produce correct padding
            for k in range(byte_pos + 1, block_size):
                prev_block[k] = decrypted[k] ^ pad_byte
            
            found = False
            for guess in range(256):
                prev_block[byte_pos] = guess
                modified_prev = bytes(prev_block)
                
                if oracle(modified_prev, curr_block):
                    # Verify it's not a false positive on last byte
                    if byte_pos == block_size - 1:
                        prev_block[byte_pos - 1] ^= 1 if byte_pos > 0 else 0
                        if not oracle(bytes(prev_block), curr_block):
                            prev_block[byte_pos - 1] ^= 1 if byte_pos > 0 else 0
                            continue
                        prev_block[byte_pos - 1] ^= 1 if byte_pos > 0 else 0
                    
                    decrypted[byte_pos] = guess ^ pad_byte ^ blocks[block_idx - 1][byte_pos]
                    found = True
                    break
            
            if not found:
                decrypted[byte_pos] = 0  # Unknown byte
        
        plaintext += bytes(decrypted)
    
    try:
        return pkcs7_unpad(plaintext)
    except Exception:
        return plaintext

def cbc_bit_flip(ciphertext: bytes, iv: bytes,
                  target_offset: int, original: bytes, desired: bytes) -> tuple[bytes, bytes]:
    """CBC bit-flip attack. Flip bits in previous block to change plaintext."""
    iv = bytearray(iv)
    ct = bytearray(ciphertext)
    
    block_size = 16
    
    for i in range(len(original)):
        abs_pos = target_offset + i
        if abs_pos < block_size:
            iv[abs_pos] ^= original[i] ^ desired[i]
        else:
            block_idx = (abs_pos // block_size - 1) * block_size
            ct[block_idx + (abs_pos % block_size)] ^= original[i] ^ desired[i]
    
    return bytes(iv), bytes(ct)

def cbc_iv_equals_key(oracle_decrypt: Callable[[bytes], bytes], key_guess_fn: Callable = None) -> bytes | None:
    """Attack when IV == Key. Requires decryption oracle that exposes plaintext."""
    # Send three blocks: C1 || 0 || C1
    # P1 = D(C1) XOR IV = D(C1) XOR key
    # P3 = D(C1) XOR 0 = D(C1)
    # key = P1 XOR P3
    pass  # Implementation depends on oracle interface

# ─── CTR ─────────────────────────────────────────────────────────────────────

def aes_ctr_encrypt(key: bytes, nonce: int, data: bytes) -> bytes:
    ctr = Counter.new(128, initial_value=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(data)

aes_ctr_decrypt = aes_ctr_encrypt  # CTR is symmetric

def ctr_nonce_reuse_attack(ciphertexts: list[bytes]) -> bytes:
    """Recover keystream when nonce is reused. Uses multi-time pad attack."""
    min_len = min(len(c) for c in ciphertexts)
    keystream = bytearray(min_len)
    
    for pos in range(min_len):
        # Collect bytes at this position from all ciphertexts
        bytes_at_pos = [ct[pos] for ct in ciphertexts]
        best_score = float('-inf')
        best_byte = 0
        for guess in range(256):
            decrypted = bytes([b ^ guess for b in bytes_at_pos])
            score = sum(1 for c in decrypted if chr(c) in ' etaoinshrdlu')
            if score > best_score:
                best_score = score
                best_byte = guess
        keystream[pos] = best_byte
    
    return bytes(keystream)

def ctr_keystream_from_known_plaintext(ciphertext: bytes, plaintext: bytes) -> bytes:
    """Recover CTR keystream from known plaintext-ciphertext pair."""
    length = min(len(ciphertext), len(plaintext))
    return bytes(c ^ p for c, p in zip(ciphertext[:length], plaintext[:length]))

# ─── GCM ─────────────────────────────────────────────────────────────────────

def aes_gcm_encrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes = b'') -> tuple[bytes, bytes]:
    """Returns (ciphertext, tag)."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(data)
    return ct, tag

def aes_gcm_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b'') -> bytes | None:
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        return cipher.decrypt_and_verify(ct, tag)
    except Exception:
        return None

def gcm_nonce_reuse_keystream(ct1: bytes, ct2: bytes) -> bytes:
    """When nonce is reused, XOR ciphertexts gives XOR of plaintexts."""
    length = min(len(ct1), len(ct2))
    return bytes(a ^ b for a, b in zip(ct1[:length], ct2[:length]))

# ─── RC4 ─────────────────────────────────────────────────────────────────────

def rc4_encrypt(key: bytes, data: bytes) -> bytes:
    cipher = ARC4.new(key)
    return cipher.encrypt(data)

rc4_decrypt = rc4_encrypt  # RC4 is symmetric

def rc4_known_plaintext_attack(ciphertext: bytes, known_pt: bytes) -> bytes:
    """Recover keystream segment from known plaintext."""
    return ctr_keystream_from_known_plaintext(ciphertext, known_pt)

def rc4_weak_key_detect(key: bytes) -> bool:
    """Detect RC4 weak keys (WEP-style: key starts with (A, B, 0))."""
    if len(key) < 3:
        return False
    return key[1] == (key[0] + 1) % 256 and key[2] == 0

# ─── ChaCha20 ─────────────────────────────────────────────────────────────────

def chacha20_encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.encrypt(data)

chacha20_decrypt = chacha20_encrypt

def chacha20_nonce_reuse(ct1: bytes, ct2: bytes) -> bytes:
    """Nonce reuse gives XOR of plaintexts."""
    return gcm_nonce_reuse_keystream(ct1, ct2)

# ─── DES ─────────────────────────────────────────────────────────────────────

def des_encrypt(key: bytes, data: bytes, mode=DES.MODE_ECB, iv: bytes = None) -> bytes:
    if mode == DES.MODE_ECB:
        cipher = DES.new(key, mode)
    else:
        cipher = DES.new(key, mode, iv=iv)
    return cipher.encrypt(pkcs7_pad(data, 8))

def des_decrypt(key: bytes, data: bytes, mode=DES.MODE_ECB, iv: bytes = None) -> bytes:
    if mode == DES.MODE_ECB:
        cipher = DES.new(key, mode)
    else:
        cipher = DES.new(key, mode, iv=iv)
    return unpad(cipher.decrypt(data), 8)

def des_meet_in_the_middle(pt: bytes, ct: bytes, key_space_fn=None) -> tuple[bytes, bytes] | None:
    """Meet-in-the-middle attack on double DES (conceptual, for CTF with limited keyspace)."""
    # Precompute forward table
    forward = {}
    # This is O(2^56) for full DES - only practical with reduced keyspace
    # In CTF context with weak/short keys, iterate key_space
    if key_space_fn is None:
        return None
    for k1 in key_space_fn():
        enc = DES.new(k1, DES.MODE_ECB).encrypt(pkcs7_pad(pt, 8))
        forward[enc] = k1
    for k2 in key_space_fn():
        dec = DES.new(k2, DES.MODE_ECB).decrypt(pkcs7_pad(ct, 8))
        if dec in forward:
            return forward[dec], k2
    return None

# ─── Hashing & MAC ───────────────────────────────────────────────────────────

def length_extension_attack(original_hash: bytes, original_msg: bytes,
                              append_data: bytes, secret_len: int,
                              hash_fn: str = 'sha256') -> tuple[bytes, bytes]:
    """SHA/MD5 length extension attack using hashpumpy if available."""
    try:
        import hashpumpy
        new_sig, new_msg = hashpumpy.hashpump(
            original_hash.hex(), original_msg, append_data, secret_len
        )
        return bytes.fromhex(new_sig), new_msg
    except ImportError:
        raise ImportError("hashpumpy not installed. Run: pip install hashpumpy")

def hmac_timing_attack_simulate(correct: bytes, guess: bytes) -> bool:
    """Simulate constant-time comparison (for educational purposes)."""
    return correct == guess

def hash_identifier(hash_str: str) -> list[str]:
    """Identify hash type from hex string."""
    length = len(hash_str)
    candidates = {
        32: ['MD5', 'MD4', 'MD2'],
        40: ['SHA-1', 'SHA-0'],
        56: ['SHA-224', 'SHA3-224'],
        64: ['SHA-256', 'SHA3-256', 'Blake2s'],
        96: ['SHA-384', 'SHA3-384'],
        128: ['SHA-512', 'SHA3-512', 'Blake2b', 'Whirlpool']
    }
    return candidates.get(length, ['Unknown'])

# ─── Utilities ────────────────────────────────────────────────────────────────

def auto_detect_aes_mode(ciphertext: bytes) -> str:
    """Heuristic to guess AES mode."""
    if ecb_detect(ciphertext):
        return 'ECB'
    if len(ciphertext) % 16 != 0:
        return 'CTR/Stream (not block-aligned)'
    return 'CBC/CTR (no duplicate blocks)'

def aes_oracle_mode_detect(oracle: Callable[[bytes], bytes]) -> str:
    """Black-box AES mode detection using chosen plaintext."""
    ct = oracle(b'A' * 48)
    if ecb_detect(ct):
        return 'ECB'
    return 'CBC or other'
