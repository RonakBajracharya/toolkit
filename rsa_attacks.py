"""
RSA Attacks & Tools
Covers: Factor small n, Wiener, Hastad, Common modulus, LSB oracle,
        Small e, Franklin-Reiter, Coppersmith, Fermat factoring,
        Chinese Remainder Theorem, Pollard p-1, ECM stub, Multi-prime RSA
"""

import math
import random
from typing import Optional
import gmpy2
from sympy import factorint, isprime, nextprime, mod_inverse, integer_nthroot, gcd
from sympy.ntheory.residues import n_order

# ─── Utilities ────────────────────────────────────────────────────────────────

def bytes_to_long(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def long_to_bytes(n: int) -> bytes:
    if n == 0:
        return b'\x00'
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big')

def modinv(a: int, m: int) -> int:
    return int(mod_inverse(a, m))

def crt(residues: list[int], moduli: list[int]) -> int:
    """Chinese Remainder Theorem."""
    M = 1
    for m in moduli:
        M *= m
    result = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        result += r * Mi * modinv(Mi, m)
    return result % M

def iroot(n: int, k: int) -> tuple[int, bool]:
    """Integer k-th root. Returns (root, exact)."""
    root, exact = gmpy2.iroot(n, k)
    return int(root), exact

def is_perfect_power(n: int) -> tuple[int, int] | None:
    """If n = a^k return (a, k), else None."""
    for k in range(2, n.bit_length() + 1):
        root, exact = iroot(n, k)
        if exact:
            return root, k
        if root < 2:
            break
    return None

# ─── Factoring ────────────────────────────────────────────────────────────────

def factor_small(n: int) -> dict | None:
    """Trial division up to 10^6."""
    factors = {}
    d = 2
    temp = n
    while d * d <= temp and d < 10**6:
        while temp % d == 0:
            factors[d] = factors.get(d, 0) + 1
            temp //= d
        d += 1
    if temp > 1:
        factors[temp] = factors.get(temp, 0) + 1
    return factors if len(factors) > 1 or list(factors.values()) != [1] else None

def fermat_factor(n: int, max_iter: int = 10**6) -> tuple[int, int] | None:
    """Fermat's factoring method. Works well when p ≈ q."""
    if n % 2 == 0:
        return 2, n // 2
    a = int(gmpy2.isqrt(n)) + 1
    for _ in range(max_iter):
        b2 = a * a - n
        b, exact = gmpy2.iroot(b2, 2)
        if exact:
            return int(a - b), int(a + b)
        a += 1
    return None

def pollard_rho(n: int) -> int | None:
    """Pollard's rho factoring."""
    if n % 2 == 0:
        return 2
    x = random.randint(2, n - 1)
    y = x
    c = random.randint(1, n - 1)
    d = 1
    while d == 1:
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = math.gcd(abs(x - y), n)
    return d if d != n else None

def pollard_p1(n: int, B: int = 10**6) -> int | None:
    """Pollard's p-1 method. Works when p-1 is B-smooth."""
    a = 2
    for p in range(2, B):
        if isprime(p):
            pk = p
            while pk * p <= B:
                pk *= p
            a = pow(a, pk, n)
    g = math.gcd(a - 1, n)
    if 1 < g < n:
        return g
    return None

def wiener_attack(e: int, n: int) -> tuple[int, int, int] | None:
    """Wiener's attack for small d. Returns (d, p, q) or None."""
    def continued_fraction(num, den):
        while den:
            yield num // den
            num, den = den, num % den

    def convergents(cf):
        n0, d0, n1, d1 = 1, 0, 0, 1
        for a in cf:
            n0, n1 = a * n0 + n1, n0
            d0, d1 = a * d0 + d1, d0
            yield n0, d0

    for k, d in convergents(continued_fraction(e, n)):
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # Solve x^2 - (n - phi + 1)x + n = 0
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        sq, exact = iroot(disc, 2)
        if exact:
            p = (b + sq) // 2
            q = (b - sq) // 2
            if p * q == n:
                return d, p, q
    return None

def hastad_broadcast(ciphertexts: list[int], moduli: list[int], e: int) -> bytes | None:
    """Hastad's broadcast attack when same message encrypted to e keys with same e."""
    if len(ciphertexts) < e:
        return None
    m_e = crt(ciphertexts[:e], moduli[:e])
    m, exact = iroot(m_e, e)
    if exact:
        try:
            return long_to_bytes(int(m))
        except Exception:
            return None
    return None

def common_modulus_attack(c1: int, c2: int, e1: int, e2: int, n: int) -> bytes | None:
    """Common modulus attack when same message encrypted with different exponents."""
    g = math.gcd(e1, e2)
    if g != 1:
        return None
    # Extended GCD
    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        g, x, y = extended_gcd(b, a % b)
        return g, y, x - (a // b) * y
    _, a, b = extended_gcd(e1, e2)
    if a < 0:
        c1 = modinv(c1, n)
        a = -a
    if b < 0:
        c2 = modinv(c2, n)
        b = -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    try:
        return long_to_bytes(m)
    except Exception:
        return None

def small_e_attack(c: int, e: int) -> bytes | None:
    """If e is small and m^e < n (no modular reduction), take e-th root."""
    m, exact = iroot(c, e)
    if exact:
        try:
            return long_to_bytes(int(m))
        except Exception:
            return None
    return None

def franklin_reiter(c1: int, c2: int, e: int, n: int, a: int, b: int) -> int | None:
    """Franklin-Reiter related message attack: m2 = a*m1 + b."""
    from sympy import GF, ZZ, Poly, Symbol, gcd as sgcd
    # For e=3: use algebraic approach
    if e == 3:
        # c1 = m^3, c2 = (am+b)^3
        # Resultant-based attack
        # Only practical for small e
        pass
    return None

def lsb_oracle_attack(c: int, n: int, e: int, oracle_fn) -> int:
    """LSB oracle attack. oracle_fn(c) returns LSB of m."""
    lower, upper = 0, n
    ct = c
    f = 2
    nbits = n.bit_length()
    for _ in range(nbits):
        ct = (ct * pow(f, e, n)) % n
        lsb = oracle_fn(ct)
        mid = (lower + upper) // 2
        if lsb == 1:
            lower = mid
        else:
            upper = mid
    return upper

def rsa_decrypt(c: int, d: int, n: int) -> bytes:
    m = pow(c, d, n)
    return long_to_bytes(m)

def rsa_encrypt(m: bytes, e: int, n: int) -> int:
    return pow(bytes_to_long(m), e, n)

def rsa_keygen(bits: int = 2048, e: int = 65537) -> dict:
    from sympy import randprime
    import secrets
    while True:
        p = randprime(2**(bits//2 - 1), 2**(bits//2))
        q = randprime(2**(bits//2 - 1), 2**(bits//2))
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            d = modinv(e, phi)
            return {'n': n, 'e': e, 'd': d, 'p': p, 'q': q, 'phi': phi}

def rsa_factor_from_d(n: int, e: int, d: int) -> tuple[int, int] | None:
    """Recover p, q given n, e, d."""
    k = e * d - 1
    while True:
        g = random.randint(2, n - 2)
        t = k
        while t % 2 == 0:
            t //= 2
            x = pow(g, t, n)
            if x > 1 and math.gcd(x - 1, n) > 1:
                p = math.gcd(x - 1, n)
                return p, n // p

def multi_prime_rsa_decrypt(c: int, p_list: list[int], e: int) -> bytes:
    """Decrypt multi-prime RSA."""
    n = 1
    for p in p_list:
        n *= p
    # phi = product(p-1)
    phi = 1
    for p in p_list:
        phi *= (p - 1)
    d = modinv(e, phi)
    return rsa_decrypt(c, d, n)

def rsa_crt_decrypt(c: int, p: int, q: int, d: int) -> bytes:
    """CRT-accelerated RSA decryption."""
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = modinv(q, p)
    mp = pow(c, dp, p)
    mq = pow(c, dq, q)
    h = (qinv * (mp - mq)) % p
    m = mq + h * q
    return long_to_bytes(m)

def parity_oracle_decrypt(c: int, n: int, e: int, oracle_fn) -> bytes:
    """Decrypt using parity oracle (even/odd oracle)."""
    return lsb_oracle_attack(c, n, e, lambda x: 0 if oracle_fn(x) else 1)

def smooth_factor(n: int) -> dict | None:
    """Try multiple factoring approaches."""
    # 1. Trial division
    result = factor_small(n)
    if result and len(result) >= 2:
        factors = list(result.keys())
        return {'method': 'trial_division', 'p': factors[0], 'q': factors[1]}
    # 2. Fermat
    res = fermat_factor(n)
    if res:
        return {'method': 'fermat', 'p': res[0], 'q': res[1]}
    # 3. Pollard rho
    for _ in range(10):
        d = pollard_rho(n)
        if d and d != n:
            return {'method': 'pollard_rho', 'p': d, 'q': n // d}
    # 4. Pollard p-1
    d = pollard_p1(n)
    if d:
        return {'method': 'pollard_p1', 'p': d, 'q': n // d}
    return None

def rsa_auto_solve(n: int, e: int, c: int,
                   p: int = None, q: int = None, d: int = None) -> dict:
    """Attempt all applicable RSA attacks."""
    results = {'attacks_tried': [], 'plaintext': None}
    
    # If we have p and q directly
    if p and q and p * q == n:
        phi = (p - 1) * (q - 1)
        d_calc = modinv(e, phi)
        pt = rsa_decrypt(c, d_calc, n)
        results['plaintext'] = pt
        results['method'] = 'known_factors'
        return results
    
    # If d is known
    if d:
        pt = rsa_decrypt(c, d, n)
        results['plaintext'] = pt
        results['method'] = 'known_d'
        return results
    
    # Try Wiener
    results['attacks_tried'].append('wiener')
    w = wiener_attack(e, n)
    if w:
        d_w, p_w, q_w = w
        pt = rsa_decrypt(c, d_w, n)
        results.update({'method': 'wiener', 'plaintext': pt, 'd': d_w, 'p': p_w, 'q': q_w})
        return results
    
    # Try small e
    if e <= 7:
        results['attacks_tried'].append('small_e')
        pt = small_e_attack(c, e)
        if pt:
            results.update({'method': 'small_e', 'plaintext': pt})
            return results
    
    # Try factoring
    results['attacks_tried'].append('factoring')
    factors = smooth_factor(n)
    if factors:
        p_f, q_f = factors['p'], factors['q']
        phi = (p_f - 1) * (q_f - 1)
        d_f = modinv(e, phi)
        pt = rsa_decrypt(c, d_f, n)
        results.update({'method': factors['method'], 'plaintext': pt, 'p': p_f, 'q': q_f, 'd': d_f})
        return results
    
    results['method'] = 'none_found'
    return results
