# frozen 解密脚本

## 用法

1. 连上题目服务，把返回的三行 hint 原样存成一个文件，例如 `ins.txt`
   （`seed` 每次连接都随机，所以三行必须来自**同一次**连接）：

```
pubkey = {"N": 128, "q": 12289, ...}
memory = 2aaa0713...
flag   = c855f4d2...
```

2. 运行（Win11 或 Kali 都一样）：

```bash
pip install numpy            # 通常已有
python3 solve_frozen.py ins.txt
# 或者从标准输入
python3 solve_frozen.py < ins.txt
```

成功时输出：`[+] flag (memory attack): b'flag{...}'`

## 依赖

| 路径 | 依赖 | 速度 |
|---|---|---|
| 记忆体攻击（默认，先跑） | 只要 `numpy` | 约 2 秒 |
| 格攻击（兜底） | `pip install fpylll cysignals` | 几分钟到几小时，取决于 BKZ |

格攻击在 Kali 上装 `fpylll` 即可；没装会自动跳过并提示。

## 原理（为什么内存泄漏能直接还原 flag）

`task.py` 用 `sha256(b"frozen:" + D)` 做密钥，其中 `D = f·f* + g·g*`，
`f*` 表示 `f(x^-1)`。所以只要拿到 `D` 就够了。

存进内存的 blob 是 Falcon 的 LDL 树：`Ltop`、`T(G00)`、`T(Dright)`、叶子。
它的每个节点满足

```
L = s·rho_j ,  s = (E_left - E_right)/(E_left + E_right)
该节点的比值  (1+s)/(1-s) = E_left / E_right
```

而 `T(G00)` 与 `T(Dright)` 都是 `V = G00(rho_j) = D(rho_j)` 的函数
（因为 Gram 行列式恒为 q²：`G00·G11 - |G01|² = q²`，故 `Dright = q²/G00`）。
把 `y = log V` 当作未知量、用鲁棒最小二乘拟合这些比值与叶子，就能还原 `V`，
再 `D = IFFT(V)` 取整即可——`D` 的系数都是整数，这一步自带极强的校验。

关键细节：

* 树对每个根对 `(j, j+N/2)` 的交换**完全不敏感**（交换后 level-1 的平均值不变，
  整棵树以下都不变），所以 `D` 的奇数部分只由 64 个根比值决定；
* 每个根比值在两个子树里各存了一份，而正常节点的 `L` 必满足
  `Im(L·conj(rho)) = 0` —— 这是一个 100% 准确的“位翻转检测器”，
  据此把两份测量里没坏的那份挑出来（实测：被判为干净的 100% 是精确值）；
* 两棵树的根都坏掉的少数几对，用 `D` 的整数性 + 解密可打印性做有限枚举。

## 兜底：格攻击

`h = g/f mod q`，所以 `(f,g)` 是 NTRU 格 `[[I,H],[0,qI]]` 里的短向量
（范数 ≈ σ√(2N) = 306，而高斯启发值 ≈ 429）。脚本用 LLL + BKZ(20,30,...,100)
逐步加块，把每个短向量及其 128 个负循环旋转都当作密钥试解密。
如果默认块大小不够，可以改脚本里的 `for beta in (...)` 加大，或调 `max_loops`。
