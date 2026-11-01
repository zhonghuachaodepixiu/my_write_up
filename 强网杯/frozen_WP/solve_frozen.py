#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Solver for the "frozen" Falcon-memory challenge.

Reads the three hint lines returned by the remote service (task.py is only the
generator; the seed is fresh for every connection, so all three lines must come
from one and the same connection)

    pubkey = {"N":128,"q":12289,"sigma":19.16,"h":[...],"rho_hint":0.01}
    memory = <hex of the cold-boot corrupted expansion>
    flag   = <hex of the encrypted flag>

and prints the plaintext flag.

Two independent attacks are implemented:

  A) MEMORY attack (numpy only, fast)
     The blob holds a Falcon LDL tree.  The T(G00) and T(Dright) subtrees are
     functions of V = G00(rho_j):  at every node, L = s*rho with
     s=(E_left-E_right)/(E_left+E_right), and the node's ratio is
     (1+s)/(1-s).  Fitting those homogeneous log-ratio constraints plus the
     leaves recovers V, hence D = f*f^* + g*g^* = IFFT(V), which is exactly
     the value that keys the flag.

  B) LATTICE attack (needs fpylll, slow but robust)
     h = g/f mod q, so (f,g) is a very short vector of the NTRU lattice
     [[I,H],[0,qI]]  (norm ~ sigma*sqrt(2N) = 306 vs. ~429 gaussian
     heuristic).  LLL/BKZ finds it; every short vector and every negacyclic
     rotation of it is a candidate key.

Both end with the same oracle: decrypt and keep the printable plaintext.

usage:  python3 solve_frozen.py instance.txt
        python3 solve_frozen.py            (reads stdin)
"""
import hashlib
import json
import os
import math
import re
import sys

import numpy as np

# --------------------------------------------------------------------------
# ring helpers  (Z[x]/(x^N+1))
# --------------------------------------------------------------------------


def rho_table(n):
    return np.exp(1j * np.pi * (2 * np.arange(n) + 1) / n)


def fft(a):
    n = len(a)
    M = np.exp(1j * np.pi * np.outer(np.arange(n), 2 * np.arange(n) + 1) / n)
    return np.asarray(a, dtype=complex) @ M


def ifft_half(F, n):
    M = np.exp(1j * np.pi * np.outer(np.arange(n), 2 * np.arange(n) + 1) / n)
    return np.real(np.conj(M) @ np.asarray(F, dtype=complex)) / n


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


def poly_adj(a, N):
    return [a[0]] + [-a[N - i] for i in range(1, N)]


def keystream(key, length):
    out = b""
    ctr = 0
    while len(out) < length:
        out += hashlib.sha256(key + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return out[:length]


def canon_bytes(D):
    return ",".join(str(int(c)) for c in D).encode()


# --------------------------------------------------------------------------
# candidate -> plaintext oracle
# --------------------------------------------------------------------------
def decrypt(D, ct):
    fk = hashlib.sha256(b"frozen:" + canon_bytes(D)).digest()
    return bytes(a ^ b for a, b in zip(ct, keystream(fk, len(ct))))


def printable(b):
    return all(32 <= c < 127 or c in (9, 10, 13) for c in b)


# ==========================================================================
#  A)  memory / LDL-tree attack
# ==========================================================================
def blob_layout(N):
    K = int(round(math.log2(N)))
    ltop = 2 * N            # Ltop is N complex doubles
    sub = N * K             # doubles of the nodes of one _T subtree
    return ltop, sub


def parse_memory(data, N):
    """Return observed log-ratios (DFS order) + the log of the stored leaves."""
    d = np.frombuffer(data, dtype="<f8")
    ltop_d, sub_d = blob_layout(N)
    logr1, ok1, logr2, ok2 = [], [], [], []
    p = ltop_d

    def walk(n, p, logr, ok):
        if n == 1:
            return p
        h = n // 2
        L = d[p:p + h] + 1j * d[p + h:p + 2 * h]
        p += 2 * h
        s = np.real(L * np.conj(rho_table(n)[:h]))
        good = np.abs(s) < 1.0 - 1e-9
        with np.errstate(divide="ignore", invalid="ignore"):
            lr = np.log(np.abs(1.0 + s)) - np.log(np.abs(1.0 - s))
        for j in range(h):
            logr.append(lr[j] if good[j] else 0.0)
            ok.append(bool(good[j]))
        p = walk(h, p, logr, ok)
        p = walk(h, p, logr, ok)
        return p

    p = walk(N, p, logr1, ok1)
    assert p == ltop_d + sub_d, "memory layout mismatch"
    p = walk(N, p, logr2, ok2)
    assert p == ltop_d + 2 * sub_d, "memory layout mismatch"
    leaf = d[p:p + 2 * N].astype(float)
    lmask = leaf > 0
    with np.errstate(divide="ignore", invalid="ignore"):
        obs_leaf = np.log(np.where(lmask, leaf, 1.0))
    return dict(logr=np.asarray(logr1 + logr2), ok=np.asarray(ok1 + ok2),
                obs_leaf=obs_leaf, lmask=lmask, raw=d)


def forward_batch(Y, N, q):
    """Model log-ratios (both subtrees) and log-leaves for a batch of log V."""
    Y = np.atleast_2d(np.asarray(Y, dtype=float))
    V = np.exp(Y)
    lr, lf = [], []

    def tree(E):
        if E.shape[1] == 1:
            lf.append(np.log(E[:, 0:1]))
            return
        h = E.shape[1] // 2
        El, Er = E[:, :h], E[:, h:]
        s = (El - Er) / (El + Er)
        with np.errstate(divide="ignore", invalid="ignore"):
            lr.append(np.log1p(s) - np.log1p(-s))
        Me = 0.5 * (El + Er)
        tree(Me)
        tree(Me * (1.0 - s * s))

    tree(V)
    tree(q * q / V)
    return np.hstack(lr), np.hstack(lf)


def residuals(Y, N, q, t):
    Y = np.atleast_2d(np.asarray(Y, dtype=float))
    lr, lf = forward_batch(Y, N, q)
    e1 = lr[:, t["ok"]] - t["logr"][t["ok"]]
    e2 = lf[:, t["lmask"]] - t["obs_leaf"][t["lmask"]]
    e = np.hstack([e1, e2])
    return np.nan_to_num(e, nan=1e3, posinf=1e3, neginf=-1e3)


def gn_step(y, N, q, t, delta):
    e = residuals(y, N, q, t)[0]
    w = np.minimum(1.0, delta / np.maximum(np.abs(e), 1e-300))
    eps = 1e-7
    Yb = np.repeat(y[None, :], N + 1, axis=0)
    Yb[1:] += np.eye(N) * eps
    E = residuals(Yb, N, q, t)
    J = ((E[1:] - E[0]) / eps).T
    Jw = J * w[:, None]
    H = Jw.T @ Jw
    g = Jw.T @ (e * w)
    H[np.diag_indices(N)] += 1e-11 * (np.trace(H) / N + 1.0)
    try:
        dy = np.linalg.solve(H, -g)
    except np.linalg.LinAlgError:
        return y
    f0 = float(np.sum(np.minimum(e * e, delta * delta)))
    lam = 1.0
    for _ in range(30):
        yn = y + lam * dy
        en = residuals(yn, N, q, t)[0]
        if float(np.sum(np.minimum(en * en, delta * delta))) < f0:
            break
        lam *= 0.5
    return y + lam * dy


def memory_attack(data, N, q, ct, verbose=True):
    t = parse_memory(data, N)

    # ---- 1. robust fit of the scale-invariant part -----------------------
    y = np.zeros(N)
    for delta in (3.0, 1.0, 0.3, 0.1, 0.03, 0.01):
        for _ in range(6):
            y = gn_step(y, N, q, t, delta)
    for delta in (1e-3, 1e-4, 1e-5):
        for _ in range(8):
            y = gn_step(y, N, q, t, delta)
    V = np.exp(y)
    a = 0.5 * (V[:N // 2] + V[N // 2:])           # Ee of the root: accurate

    # ---- 2. each root pair ratio is measured twice ----------------------
    # a pair swap leaves the whole rest of the tree invariant, so the odd
    # part of D is fixed by these 64 ratios alone.  L must be s*rho, which
    # gives a perfect corruption detector: |Im(L conj rho)| == 0.
    rho = rho_table(N)[:N // 2]
    ltop_d, sub_d = blob_layout(N)
    t1, c1 = _root_ratio(t["raw"], ltop_d, N // 2, rho, +1.0)
    t2, c2 = _root_ratio(t["raw"], ltop_d + sub_d, N // 2, rho, -1.0)

    tfit = np.log(V[:N // 2]) - np.log(V[N // 2:])
    ts = np.where(c1, t1, np.where(c2, t2, tfit))
    unknown = [j for j in range(N // 2) if not (c1[j] or c2[j])]
    if verbose:
        print(f"   [mem] root ratios: {N//2 - len(unknown)}/{N//2} resolved, "
              f"{len(unknown)} unknown")

    def build(ts):
        e = np.exp(ts)
        return np.concatenate([2 * a * e / (1 + e), 2 * a / (1 + e)])

    cands = []
    for j in range(N // 2):
        if c1[j] and c2[j] and abs(t1[j] - t2[j]) < 1e-7:
            cands.append([0.5 * (t1[j] + t2[j])])
        else:
            c = [x for x, ok in ((t1[j], c1[j]), (t2[j], c2[j])) if ok]
            if not c:
                c = [t1[j], t2[j], tfit[j]]
            cands.append(c)

    # ---- 3. solve the small combinatorial part with an integer penalty --
    ts = np.array([c[0] for c in cands])
    for _ in range(3):
        for j in range(N // 2):
            if len(cands[j]) < 2:
                continue
            best = (integrality_penalty(build(ts)), ts[j])
            for c in cands[j]:
                tt = ts.copy()
                tt[j] = c
                p = integrality_penalty(build(tt))
                if p < best[0]:
                    best = (p, c)
            ts[j] = best[1]

    # ---- 4. decrypt / verify, with a bounded search on the weak pairs ---
    def margin(j):
        if len(cands[j]) < 2:
            return -1.0
        ps = []
        for c in cands[j]:
            tt = ts.copy()
            tt[j] = c
            ps.append(integrality_penalty(build(tt)))
        return max(ps) - min(ps)

    order = sorted(range(N // 2), key=margin)
    tried = set()

    def attempt(tt):
        V = build(tt)
        D = [int(round(x)) for x in ifft_half(V, N)]
        key = bytes(canon_bytes(D))
        if key in tried:
            return None
        tried.add(key)
        pt = decrypt(D, ct)
        return pt if printable(pt) else None

    pt = attempt(ts)
    if pt:
        return pt
    # fine local repair of the weak ratios (the fit is often already close)
    weak = [j for j in range(N // 2) if len(cands[j]) > 1 or not (c1[j] or c2[j])]
    for _ in range(2):
        for j in weak:
            best = (integrality_penalty(build(ts)), 0.0)
            for off in np.linspace(-0.02, 0.02, 17):
                tt = ts.copy()
                tt[j] += off
                p = integrality_penalty(build(tt))
                if p < best[0]:
                    best = (p, off)
            ts[j] += best[1]
        pt = attempt(ts)
        if pt:
            return pt

    # flip the least confident pairs (breadth first, bounded)
    # the least-confident ratio pairs are re-tried exhaustively (2^k combos);
    # widen with FROZEN_WIDE=20 if the default fails
    cap = int(os.environ.get("FROZEN_WIDE", "16"))
    simple = [j for j in order if len(cands[j]) > 1][:cap]
    for mask in range(1, 1 << len(simple)):
        tt = ts.copy()
        for i, j in enumerate(simple):
            if mask >> i & 1:
                tt[j] = cands[j][-1]
        pt = attempt(tt)
        if pt:
            return pt
    return None


def _root_ratio(raw, off, h, rho, sign):
    L = raw[off:off + h] + 1j * raw[off + h:off + 2 * h]
    s = np.real(L * np.conj(rho))
    phase = np.abs(np.imag(L * np.conj(rho))) / np.maximum(np.abs(L), 1e-300)
    with np.errstate(divide="ignore", invalid="ignore"):
        t = sign * (np.log(np.abs(1.0 + s)) - np.log(np.abs(1.0 - s)))
    clean = (phase < 1e-9) & (np.abs(s) < 1.0 - 1e-9)
    t = np.where(clean, t, 0.0)
    return t, clean


def integrality_penalty(V):
    D = ifft_half(V, len(V))
    return float(np.sum((D - np.round(D)) ** 2))


# ==========================================================================
#  B)  lattice attack on the public key
# ==========================================================================
def ntru_basis(h, q, N):
    """rows span {(u,v) : u*h = v mod q} with u*h the negacyclic product."""
    B = [[0] * (2 * N) for _ in range(2 * N)]
    for i in range(N):
        B[i][i] = 1
        for j in range(N):
            k = i - j
            s = h[k % N]
            if k < 0:
                s = -s
            B[i][N + j] = s
    for i in range(N):
        B[N + i][N + i] = q
    return B


def rotate(v, N):
    return [-v[-1]] + list(v[:-1])


def lattice_attack(h, q, N, ct, verbose=True):
    try:
        from fpylll import IntegerMatrix, LLL, BKZ
    except Exception:
        if verbose:
            print("   [lat] fpylll not installed -> skipping lattice attack")
        return None
    rows = ntru_basis(h, q, N)
    B = IntegerMatrix(2 * N, 2 * N)
    for i in range(2 * N):
        for j in range(2 * N):
            B[i, j] = rows[i][j]
    LLL.reduction(B)
    target = 4.0 * 19.16 * math.sqrt(2 * N)      # a few times ||(f,g)||
    for beta in (20, 30, 40, 50, 60, 80, 100):
        if beta > 2 * N:
            break
        if verbose:
            print(f"   [lat] BKZ-{beta} ...")
        BKZ.reduction(B, BKZ.Param(block_size=beta, max_loops=4))
        for i in range(2 * N):
            u = [int(B[i, j]) for j in range(N)]
            v = [int(B[i, j]) for j in range(N, 2 * N)]
            if math.sqrt(sum(x * x for x in u + v)) > target:
                continue
            for _ in range(N):
                D = [x + y for x, y in zip(poly_mul(u, poly_adj(u, N), N),
                                           poly_mul(v, poly_adj(v, N), N))]
                pt = decrypt(D, ct)
                if printable(pt):
                    return pt
                u = rotate(u, N)
                v = rotate(v, N)
    return None


# ==========================================================================
def main(argv):
    raw = open(argv[1], encoding="utf-8", errors="ignore").read() if len(argv) > 1 \
        else sys.stdin.read()
    pub = json.loads(re.search(r"pubkey\s*=\s*(\{.*?\})\s*\n", raw, re.S).group(1))
    mem = re.search(r"memory\s*=\s*([0-9a-fA-F]+)", raw).group(1)
    ct = bytes.fromhex(re.search(r"flag\s*=\s*([0-9a-fA-F]+)", raw).group(1))
    N, q, h = pub["N"], pub["q"], pub["h"]
    data = bytes.fromhex(mem)
    print(f"[*] N={N} q={q} memory={len(data)} bytes ciphertext={len(ct)} bytes")

    pt = memory_attack(data, N, q, ct)
    if pt:
        print("[+] flag (memory attack):", pt)
        return 0
    print("[-] memory attack did not produce a printable plaintext")
    pt = lattice_attack(h, q, N, ct)
    if pt:
        print("[+] flag (lattice attack):", pt)
        return 0
    print("[-] lattice attack failed (increase BKZ block size / max_loops)")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
