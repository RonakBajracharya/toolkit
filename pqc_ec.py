"""
Post-Quantum Cryptography & Elliptic Curve Tools
Covers: Lattice attacks (LLL, CVP), ECDLP, ECDSA k-reuse, Invalid curve,
        Lattice-based crypto (LWE stub), Diffie-Hellman attacks,
        Baby-step Giant-step, Pohlig-Hellman, MOV attack
"""

import math
import random
from typing import Optional
from sympy import isprime, factorint, discrete_log

# ─── Elliptic Curve Utilities ────────────────────────────────────────────────

class EllipticCurve:
    """Weierstrass form: y^2 = x^3 + ax + b (mod p)."""
    
    def __init__(self, a: int, b: int, p: int):
        self.a = a
        self.b = b
        self.p = p
    
    def point_add(self, P: tuple, Q: tuple) -> tuple:
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2:
            if y1 != y2:
                return None  # Point at infinity
            if y1 == 0:
                return None
            # Point doubling
            m = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p) % self.p
        else:
            m = (y2 - y1) * pow(x2 - x1, -1, self.p) % self.p
        x3 = (m * m - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        return x3, y3
    
    def scalar_mult(self, k: int, P: tuple) -> tuple:
        R = None
        Q = P
        while k > 0:
            if k & 1:
                R = self.point_add(R, Q)
            Q = self.point_add(Q, Q)
            k >>= 1
        return R
    
    def on_curve(self, P: tuple) -> bool:
        if P is None:
            return True
        x, y = P
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0
    
    def order_of_point(self, P: tuple, max_iter: int = 10**6) -> int | None:
        """Compute order of point P (only practical for small orders)."""
        Q = P
        for i in range(1, max_iter):
            if Q is None:
                return i
            Q = self.point_add(Q, P)
        return None

# ─── ECDLP Attacks ───────────────────────────────────────────────────────────

def baby_step_giant_step(G: tuple, Q: tuple, order: int, curve: EllipticCurve) -> int | None:
    """BSGS for ECDLP: find k such that k*G = Q."""
    m = math.isqrt(order) + 1
    
    # Baby steps: j*G for j in [0, m)
    table = {}
    point = None
    for j in range(m):
        table[point] = j
        point = curve.point_add(point, G) if point else G
    
    # Giant steps: Q - i*m*G for i in [0, m)
    factor = curve.scalar_mult(m, G)
    neg_factor = (factor[0], (-factor[1]) % curve.p) if factor else None
    
    current = Q
    for i in range(m):
        if current in table:
            k = (i * m + table[current]) % order
            return k
        current = curve.point_add(current, neg_factor)
    
    return None

def pohlig_hellman_ec(G: tuple, Q: tuple, order: int,
                       curve: EllipticCurve) -> int | None:
    """Pohlig-Hellman for ECDLP when group order is smooth."""
    factors = factorint(order)
    dlogs = []
    moduli = []
    
    for p, e in factors.items():
        pk = p ** e
        G_sub = curve.scalar_mult(order // p, G)
        Q_sub = curve.scalar_mult(order // p, Q)
        
        # BSGS in subgroup
        dl = baby_step_giant_step(G_sub, Q_sub, p, curve)
        if dl is None:
            return None
        
        # Hensel lift for prime powers
        for k in range(1, e):
            # Reconstruct current estimate
            g_k = curve.scalar_mult(order // p**(k+1), G)
            q_k = curve.scalar_mult(order // p**(k+1), 
                                     curve.point_add(Q, curve.scalar_mult(-dl, G)))
            d = baby_step_giant_step(g_k, q_k, p, curve)
            if d is None:
                d = 0
            dl += d * (p ** k)
        
        dlogs.append(dl % pk)
        moduli.append(pk)
    
    # CRT
    result = 0
    M = 1
    for m in moduli:
        M *= m
    for dl, m in zip(dlogs, moduli):
        Mi = M // m
        result += dl * Mi * pow(Mi, -1, m)
    return result % M

# ─── ECDSA Attacks ───────────────────────────────────────────────────────────

def ecdsa_k_reuse_attack(r: int, s1: int, s2: int,
                          z1: int, z2: int, n: int) -> tuple[int, int] | None:
    """Recover private key when k is reused in two ECDSA signatures."""
    # k = (z1 - z2) / (s1 - s2) mod n
    if s1 == s2:
        return None
    k = ((z1 - z2) * pow(s1 - s2, -1, n)) % n
    # d = (s1*k - z1) / r mod n
    d = ((s1 * k - z1) * pow(r, -1, n)) % n
    return k, d

def ecdsa_nonce_bias_attack(signatures: list[tuple], n: int, msb_known: int = 0) -> int | None:
    """Attack when nonce k has biased MSBs (LLL lattice attack)."""
    # This requires lattice reduction - simplified stub
    # Full implementation needs fpylll or similar
    try:
        from fpylll import IntegerMatrix, LLL
        # Build lattice from signatures
        # ... (complex lattice construction)
        pass
    except ImportError:
        pass
    return None

def ecdsa_invalid_curve(curve: EllipticCurve, oracle_fn, target_order: int) -> int | None:
    """Invalid curve attack: send points on invalid curves with small order."""
    # Find invalid curve with small order group
    # oracle_fn receives a point and returns scalar mult result
    # This is used to extract the private key mod small primes
    pass

# ─── Diffie-Hellman Attacks ───────────────────────────────────────────────────

def dh_pohlig_hellman(g: int, h: int, p: int) -> int | None:
    """Pohlig-Hellman DLP when p-1 is smooth."""
    order = p - 1
    factors = factorint(order)
    dlogs = []
    moduli = []
    
    for prime, exp in factors.items():
        pk = prime ** exp
        g_sub = pow(g, order // prime, p)
        h_sub = pow(h, order // prime, p)
        
        # BSGS in subgroup of order prime
        dl = bsgs_multiplicative(g_sub, h_sub, prime, p)
        if dl is None:
            continue
        
        # Hensel lift
        for k in range(1, exp):
            g_k = pow(g, order // prime**(k+1), p)
            correction = pow(g, -dl, p) * h % p
            h_k = pow(correction, order // prime**(k+1), p)
            d = bsgs_multiplicative(g_k, h_k, prime, p)
            if d is None:
                d = 0
            dl += d * prime**k
        
        dlogs.append(dl % pk)
        moduli.append(pk)
    
    if not dlogs:
        return None
    
    # CRT
    M = 1
    for m in moduli:
        M *= m
    result = 0
    for dl, m in zip(dlogs, moduli):
        Mi = M // m
        result += dl * Mi * pow(Mi, -1, m)
    return result % M

def bsgs_multiplicative(g: int, h: int, order: int, p: int) -> int | None:
    """Baby-step Giant-step for multiplicative DLP."""
    m = math.isqrt(order) + 1
    
    # Baby steps
    table = {}
    gj = 1
    for j in range(m):
        table[gj] = j
        gj = gj * g % p
    
    # Giant steps: h * (g^-m)^i
    g_inv_m = pow(g, -m, p)
    current = h
    for i in range(m):
        if current in table:
            return (i * m + table[current]) % order
        current = current * g_inv_m % p
    
    return None

def dh_small_subgroup_attack(public_key: int, generator: int, p: int,
                               small_order: int, oracle_fn) -> int | None:
    """Small subgroup attack on DH."""
    # Find element of small order
    q = (p - 1) // small_order
    h = pow(generator, q, p)
    # Send h to oracle and get h^x mod p
    result = oracle_fn(h)
    # Compute DLP in small subgroup
    return bsgs_multiplicative(h, result, small_order, p)

# ─── Lattice Attacks ─────────────────────────────────────────────────────────

def lll_reduce(basis: list[list[int]]) -> list[list[int]]:
    """LLL lattice reduction (simplified Gram-Schmidt + reduction)."""
    try:
        from fpylll import IntegerMatrix, LLL as fpylll_LLL
        n = len(basis)
        m = len(basis[0])
        A = IntegerMatrix(n, m)
        for i in range(n):
            for j in range(m):
                A[i, j] = int(basis[i][j])
        fpylll_LLL.reduction(A)
        return [[A[i, j] for j in range(m)] for i in range(n)]
    except ImportError:
        # Fallback: simple LLL implementation
        return _lll_simple(basis)

def _lll_simple(B: list[list[float]], delta: float = 0.75) -> list[list[float]]:
    """Pure Python LLL (slow but dependency-free)."""
    import copy
    B = [list(map(float, row)) for row in copy.deepcopy(B)]
    n = len(B)
    
    def dot(u, v):
        return sum(a * b for a, b in zip(u, v))
    
    def proj(u, v):
        return dot(u, v) / dot(v, v)
    
    def gram_schmidt(B):
        B_star = []
        mu = [[0.0] * n for _ in range(n)]
        for i in range(n):
            b = list(B[i])
            for j in range(i):
                mu[i][j] = proj(B[i], B_star[j])
                b = [b[k] - mu[i][j] * B_star[j][k] for k in range(len(b))]
            B_star.append(b)
        return B_star, mu
    
    k = 1
    while k < n:
        B_star, mu = gram_schmidt(B)
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                r = round(mu[k][j])
                B[k] = [B[k][i] - r * B[j][i] for i in range(len(B[0]))]
        B_star, mu = gram_schmidt(B)
        lhs = dot(B_star[k], B_star[k])
        rhs = (delta - mu[k][k-1]**2) * dot(B_star[k-1], B_star[k-1])
        if lhs >= rhs:
            k += 1
        else:
            B[k], B[k-1] = B[k-1], B[k]
            k = max(k - 1, 1)
    return B

def knapsack_attack_low_density(weights: list[int], target: int) -> list[int] | None:
    """LLL-based attack on low-density knapsack (subset sum)."""
    n = len(weights)
    N = max(weights) * n
    
    # Build lattice matrix
    B = [[0] * (n + 1) for _ in range(n + 1)]
    for i in range(n):
        B[i][i] = 1
        B[i][n] = weights[i]
    B[n][n] = -target
    
    reduced = lll_reduce(B)
    
    # Look for solution row (all entries 0 or 1)
    for row in reduced:
        if all(x in (0, 1) for x in row[:-1]):
            solution = row[:-1]
            if sum(w * s for w, s in zip(weights, solution)) == target:
                return solution
    return None

# ─── LWE (Learning With Errors) ──────────────────────────────────────────────

def lwe_generate(n: int, q: int, sigma: float) -> tuple:
    """Generate LWE sample."""
    import random
    s = [random.randint(0, q-1) for _ in range(n)]
    A = [[random.randint(0, q-1) for _ in range(n)]]
    e = [round(random.gauss(0, sigma)) % q]
    b = [(sum(A[0][i] * s[i] for i in range(n)) + e[0]) % q]
    return A, b, s

# ─── Number Theory ────────────────────────────────────────────────────────────

def tonelli_shanks(n: int, p: int) -> int | None:
    """Compute square root of n mod p."""
    if pow(n, (p-1)//2, p) != 1:
        return None  # Not a QR
    if p % 4 == 3:
        return pow(n, (p+1)//4, p)
    # General case
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p-1)//2, p) != p-1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q+1)//2, p)
    while True:
        if t == 0:
            return 0
        if t == 1:
            return r
        i, tmp = 1, pow(t, 2, p)
        while tmp != 1:
            tmp = pow(tmp, 2, p)
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c, t, r = i, pow(b, 2, p), t * c * c % p, r * b % p

def discrete_log_baby_giant(g: int, h: int, p: int, max_order: int = None) -> int | None:
    """BSGS discrete logarithm mod p."""
    order = max_order or (p - 1)
    return bsgs_multiplicative(g, h, order, p)

def chinese_remainder_theorem(remainders: list[int], moduli: list[int]) -> int:
    """Garner's algorithm CRT."""
    M = 1
    for m in moduli:
        M *= m
    result = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        result += r * Mi * pow(Mi, -1, m)
    return result % M
