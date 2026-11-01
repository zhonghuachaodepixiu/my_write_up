#!/usr/bin/env python3

import cmath, hashlib, json, math, os, random, struct, sys, time
from fractions import Fraction
import numpy as np
from fpylll import IntegerMatrix, LLL, GSO
import math, random, struct, time
from secret import flag

def poly_mul(a, b, N):
    r = [0] * N
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if bj:
                    k = i + j
                    if k >= N:
                        r[k - N] -= ai * bj
                    else:
                        r[k] += ai * bj
    return r

def poly_mulmod(a, b, N, q):
    return [x % q for x in poly_mul(a, b, N)]

def poly_sub(a, b):
    return [x - y for x, y in zip(a, b)]

def norm2(a):
    return sum(x * x for x in a)

def poly_adj(a, N):
    return [a[0]] + [-a[N - i] for i in range(1, N)]


_RHO = {}
def rho_table(n):
    if n not in _RHO:
        _RHO[n] = np.exp(1j * math.pi * (2 * np.arange(n) + 1) / n)
    return _RHO[n]

def fft(a):
    n = len(a)
    k = np.arange(n)
    M = np.exp(1j * math.pi * np.outer(k, 2 * np.arange(n) + 1) / n)   # M[k, j] = rho_j^k
    return np.asarray(a, dtype=complex) @ M                             # result[j] = a(rho_j)

def splitfft(F):
    n = len(F); h = n // 2
    rho = rho_table(n)
    E = 0.5 * (F[:h] + F[h:])
    O = (F[:h] - F[h:]) / (2 * rho[:h])
    return E, O


_PSI_CACHE = {}

def _psi(q, N):
    """primitive 2N-th root of unity mod q with psi^N = -1"""
    key = (q, N)
    if key in _PSI_CACHE:
        return _PSI_CACHE[key]
    if q == 12289:
        g = 11
    else:
        g = _primitive_root(q)
    assert (q - 1) % (2 * N) == 0, "2N must divide q-1"
    psi = pow(g, (q - 1) // (2 * N), q)
    while pow(psi, N, q) != q - 1 or pow(psi, 2 * N, q) != 1:
        # search
        psi = (psi * g) % q
    _PSI_CACHE[key] = psi
    return psi

def _primitive_root(q):
    from sympy import factorint
    phi = q - 1
    fac = factorint(phi)
    for g in range(2, q):
        if all(pow(g, phi // p, q) != 1 for p in fac):
            return g
    raise ValueError

def _cntt(a, w, q):
    n = len(a)
    if n == 1:
        return a[:]
    even = _cntt(a[0::2], w * w % q, q)
    odd = _cntt(a[1::2], w * w % q, q)
    out = [0] * n
    hh = n // 2
    wk = 1
    for k in range(hh):
        t = odd[k] * wk % q
        out[k] = (even[k] + t) % q
        out[k + hh] = (even[k] - t) % q
        wk = wk * w % q
    return out

def ntt(a, N, q, inverse=False):
    """negacyclic NTT mod (q, x^N+1): A_j = a(psi^{2j+1}).
    inverse: from A recover a (a_i psi^i = (1/N) sum_j A_j w^{-ij}, untwist)."""
    psi = _psi(q, N)
    w = psi * psi % q
    if not inverse:
        b = [a[i] * pow(psi, i, q) % q for i in range(N)]
        return _cntt(b, w, q)
    winv = pow(w, q - 2, q)
    B = _cntt([x % q for x in a], winv, q)
    ninv = pow(N, q - 2, q)
    return [B[i] * ninv % q * pow(psi, q - 1 - i, q) % q for i in range(N)]

def poly_inv_modq(a, N, q):
    """a^{-1} in Z_q[x]/(x^N+1) via NTT."""
    A = ntt(list(a), N, q)
    if any(x == 0 for x in A):
        return None
    inv = [pow(x, q - 2, q) for x in A]
    return ntt(inv, N, q, inverse=True)

def _xgcd_int(a, b):
    old_r, r = abs(a), abs(b)
    old_s, s = 1, 0
    old_t, t = 0, 1
    sa, sb = (1 if a >= 0 else -1), (1 if b >= 0 else -1)
    while r:
        qq = old_r // r
        old_r, r = r, old_r - qq * r
        old_s, s = s, old_s - qq * s
        old_t, t = t, old_t - qq * t
    return old_r, old_s * sa, old_t * sb

def ntru_solve_tower(f, g, q, N):
    if N == 1:
        d, s, t = _xgcd_int(f[0], g[0])
        if q % d:
            return None
        # s*f + t*g = d  ->  f*(t*q/d) - g*(-s*q/d) = q
        return ([-t * (q // d)], [s * (q // d)])
    # norms: fN = f(x)*f(-x), gN = g(x)*g(-x)  (even polys -> half size)
    fm = [(-c if i & 1 else c) for i, c in enumerate(f)]
    gm = [(-c if i & 1 else c) for i, c in enumerate(g)]
    fN = poly_mul(f, fm, N)      # even coefficients only
    gN = poly_mul(g, gm, N)
    fN = fN[0::2]
    gN = gN[0::2]
    sol = ntru_solve_tower(fN, gN, q, N // 2)
    if sol is None:
        return None
    Fp, Gp = sol
    def spread(p):
        out = [0] * N
        for i, c in enumerate(p):
            out[2 * i] = c
        return out
    F = poly_mul(gm, spread(Fp), N)
    G = poly_mul(fm, spread(Gp), N)
    return (F, G)

def _poly_mul_frac(a, b, N):
    from fractions import Fraction
    r = [Fraction(0)] * N
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if bj:
                    k = i + j
                    if k >= N:
                        r[k - N] -= ai * bj
                    else:
                        r[k] += ai * bj
    return r

def _inv_tower(M, N):
    from fractions import Fraction
    if N == 1:
        return [Fraction(1) / M[0]]
    Mm = [(-c if i & 1 else c) for i, c in enumerate(M)]
    M2 = _poly_mul_frac(M, Mm, N)        # even poly in x -> poly in y = x^2
    inv2 = _inv_tower(M2[0::2], N // 2)
    # inv(x) = M(-x) * inv2(x^2)  mod Phi_N
    exp = [Fraction(0)] * N
    for i, c in enumerate(inv2):
        exp[2 * i] = c
    return _poly_mul_frac(Mm, exp, N)

def babai_reduce(f, g, F, G, N, rounds=4):
    from fractions import Fraction
    adjf = poly_adj(f, N); adjg = poly_adj(g, N)
    M = [Fraction(x) for x in
         [a + b for a, b in zip(poly_mul(f, adjf, N), poly_mul(g, adjg, N))]]
    Minv = _inv_tower(M, N)
    for _ in range(rounds):
        v = [Fraction(a + b) for a, b in
             zip(poly_mul(F, adjf, N), poly_mul(G, adjg, N))]
        wfrac = _poly_mul_frac(v, Minv, N)
        w = [int(c + (Fraction(1, 2) if c >= 0 else -Fraction(1, 2))) for c in wfrac]
        if not any(w):
            break
        fw = poly_mul(f, w, N); gw = poly_mul(g, w, N)
        F = [a - b for a, b in zip(F, fw)]
        G = [a - b for a, b in zip(G, gw)]
    try:
        rows = []
        vf, vg = f[:], g[:]
        for _ in range(N):
            rows.append(vf + vg)
            vf = [-vf[-1]] + vf[:-1]
            vg = [-vg[-1]] + vg[:-1]
        B = IntegerMatrix(N, 2 * N)
        for i in range(N):
            for j in range(2 * N):
                B[i, j] = rows[i][j]
        LLL.reduction(B)
        Mx = GSO.Mat(B, update=True)
        t = list(F) + list(G)
        for _ in range(2):
            coeffs = Mx.babai(t)
            for ci, cc in enumerate(coeffs):
                if cc:
                    for j in range(2 * N):
                        t[j] -= cc * B[ci, j]
        F, G = t[:N], t[N:]
    except Exception:
        pass
    return F, G

def sample_gauss(N, sigma, rng):
    return [int(round(rng.gauss(0, sigma))) for _ in range(N)]

def keygen(N=128, q=12289, sigma=19.16, rng=None, tries=60, verbose=False):
    rng = rng or random.Random()
    for attempt in range(tries):
        f = sample_gauss(N, sigma, rng)
        g = sample_gauss(N, sigma, rng)
        if poly_inv_modq(f, N, q) is None:
            continue
        sol = ntru_solve_tower(f, g, q, N)
        if sol is None:
            continue
        F, G = sol
        lhs = poly_sub(poly_mul(f, G, N), poly_mul(g, F, N))
        if lhs[0] % q or any(x % q for x in lhs[1:]):
            continue
        t0 = time.time()
        F, G = babai_reduce(f, g, F, G, N)
        if verbose:
            print(f"   [babai] {time.time()-t0:.1f}s")
        lhs = poly_sub(poly_mul(f, G, N), poly_mul(g, F, N))
        if lhs[0] % q or any(x % q for x in lhs[1:]):
            continue
        nfg = norm2(f) + norm2(g)
        nFG = norm2(F) + norm2(G)
        if nFG > 400 * q * N:      # far looser than falcon; retry if pathological
            continue
        h = poly_mulmod(g, poly_inv_modq(f, N, q), N, q)
        return dict(N=N, q=q, f=f, g=g, F=F, G=G, h=h, nfg=nfg, nFG=nFG)
    raise RuntimeError("keygen failed")

def falcon_tree(fh, gh, Fh, Gh, q):
    G00 = gh * np.conj(gh) + fh * np.conj(fh)
    G01 = gh * np.conj(Gh) + fh * np.conj(Fh)
    G11 = Gh * np.conj(Gh) + Fh * np.conj(Fh)
    Ltop = G01 / G00
    Dright = G11 - Ltop * np.conj(Ltop) * G00
    return [Ltop, _T(G00), _T(Dright)]

def _T(E):
    n = len(E)
    if n == 1:
        return [float(np.real(E[0]))]
    Ee, Eo = splitfft(E)
    L = np.conj(Eo) / Ee
    return [L, _T(Ee), _T(Ee - L * np.conj(L) * Ee)]

def flatten_tree(tree):
    nodes, leaves = [], []
    def rec(t):
        if isinstance(t[0], float):
            leaves.extend(t)
            return
        nodes.append(t[0])
        rec(t[1]); rec(t[2])
    rec(tree)
    return nodes, leaves

def expanded_doubles(key):
    N, q = key["N"], key["q"]
    fh, gh, Fh, Gh = fft(key["f"]), fft(key["g"]), fft(key["F"]), fft(key["G"])
    tree = falcon_tree(fh, gh, Fh, Gh, q)
    nodes, leaves = flatten_tree(tree)
    vals = []
    for arr in (fh, gh, Fh, Gh):
        vals += [float(arr[i].real) for i in range(N)] + [float(arr[i].imag) for i in range(N)]
    for nd in nodes:
        vals += [float(v.real) for v in nd] + [float(v.imag) for v in nd]
    vals += [float(v) for v in leaves]
    return vals, (fh, gh, Fh, Gh, tree, nodes, leaves)

def dump_blob(vals):
    return struct.pack("<%dd" % len(vals), *vals)

def corrupt_blob(blob, rho10, rho01=0.0, rng=None):
    rng = rng or random.Random()
    flipbits = list(range(56)) + [63]
    out = bytearray(blob)
    for di in range(len(blob) // 8):
        x = int.from_bytes(out[8 * di:8 * di + 8], "little")
        for bit in flipbits:
            if (x >> bit) & 1:
                if rng.random() < rho10:
                    x ^= 1 << bit
            elif rho01 and rng.random() < rho01:
                x ^= 1 << bit
        out[8 * di:8 * di + 8] = x.to_bytes(8, "little")
    return bytes(out)

N = 128
Q = 12289
SIGMA = 19.16


def keystream(key: bytes, length: int) -> bytes:
    out = b""
    ctr = 0
    while len(out) < length:
        out += hashlib.sha256(key + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return out[:length]


def try_instance(seed, dseed, rho):
    rng = random.Random(seed)
    key = keygen(N, Q, SIGMA, rng)
    vals, parts = expanded_doubles(key)
    blob = dump_blob(vals)
    decay = random.Random(seed * 31 + dseed)
    cblob_full = corrupt_blob(blob, rho, rho01=RHO01, rng=decay)
    head = 8 * 128
    cblob = cblob_full[head * 8:]

    ff = poly_mul(key["f"], poly_adj(key["f"], N), N)
    gg = poly_mul(key["g"], poly_adj(key["g"], N), N)
    D = [a + b for a, b in zip(ff, gg)]
    return key, cblob, D


RHO10 = 0.01
RHO01 = 0.001

sysrng = random.SystemRandom()
seed = sysrng.randrange(1, 2 ** 62)
dseed = sysrng.randrange(1, 2 ** 30)
key, cblob, D = try_instance(seed, dseed, RHO10)

canon = ",".join(str(c) for c in D).encode()
fk = hashlib.sha256(b"frozen:" + canon).digest()
ct = bytes(a ^ b for a, b in zip(flag, keystream(fk, len(flag))))

pub = dict(N=N, q=Q, sigma=SIGMA, h=[int(x) for x in key["h"]], rho_hint=RHO10)

print("pubkey =", json.dumps(pub))
print("memory =", cblob.hex())
print("flag   =", ct.hex())
