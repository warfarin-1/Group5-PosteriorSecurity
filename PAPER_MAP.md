# 论文精读 — Incognito Signature（§3.2 + §4.1 + 附录 D.1）

> 这是 `复现计划.md` 里提到的 `docs/PAPER_MAP.md` 初稿：论文公式 ↔ 未来代码函数 的逐步对照 + 关键推导。
> 建 repo 后移到 `docs/PAPER_MAP.md`，边写代码边更新。
> 论文：ePrint 2025/855，§3.2（通用构造）、§4.1（Schnorr 实例化）、附录 D.1（π'_b 细节）。
> 附录 D.1 有 OCR 噪声，本文的推导已重新独立验算，以本文为准。
> **本文只覆盖 Incognito 线（Track-DL）**。Concealed 线（§5.3 Boneh-Boyen + Groth-Sahai，§6 组合）的对应精读见 `PAPER_MAP_CONCEALED.md`（待写）。

---

## 0. 记号约定

| 记号 | 含义 |
|---|---|
| G, p, g | secp256k1 群、阶（256-bit 素数）、固定生成元 |
| Z_p | 标量域，运算全部 mod p |
| 粗体 **v** | 长度 n 的向量 |
| **1**_n | 全 1 向量 (1,…,1) |
| **0**_n | 全 0 向量 |
| **y**_n | 幂向量 (1, y, y², …, y^{n-1})，y ∈ Z_p |
| **a** ∘ **b** | Hadamard（逐分量）积 (a_1b_1, …, a_nb_n) |
| ⟨**a**, **b**⟩ | 内积 Σ a_i b_i ∈ Z_p |
| **g**^**a** | 多标量乘 ∏ g_i^{a_i} ∈ G（**g** 是生成元向量，**a** 是标量向量） |
| pk^**b** | ∏ pk_i^{b_i}，pk = {pk_1,…,pk_n} 是环里的 n 个公钥 |
| n | 环大小（decoy 公钥数 + 1），**Bulletproof 要求是 2 的幂** |

**one-hot 向量 b**：只有第 j 位为 1、其余为 0 的 0/1 向量。它满足两条等价约束：
- **b** ∘ **b** = **b**（每位 b_i ∈ {0,1}，即二元）
- ⟨**b**, **1**_n⟩ = 1（恰好一位是 1）

---

## 1. §3.2 通用构造（Generic Construction）

### 1.1 思路

标准签名的验证式 `Verify(σ, m, pk) = 1` 里出现了签名者公钥 pk。要匿名化，就是**把这个 pk 藏进一个由 n 个公钥组成的集合里**，且不泄露是哪一个。

方法：引入 one-hot 向量 **b**（第 j 位是 1，j 是真实签名者在环里的下标），则
```
pk_j = ∏_{i=1}^n pk_i^{b_i} = pk^b
```
于是验证式改写成 `Verify(σ, m, pk^b) = 1`。再用一个 **NIZKAoK（非交互零知识知识论证）π** 证明"我知道满足下述关系的见证"，把 σ、pk_j、**b** 全部藏进 π 里。

### 1.2 关系（relation）

```
u（公开陈述） := (m, pk)                     // pk 是 n 个公钥的集合
w（秘密见证） := (σ, pk_j, b)

关系 R:  Verify(σ, m, pk_j) = 1
       ∧ pk_j = ∏_{i=1}^n pk_i^{b_i}
       ∧ (b − 1_n) ∘ b = 0_n                 // b 二元
       ∧ ⟨b, 1_n⟩ = 1                        // b 恰一位为 1
```

### 1.3 三个算法

| 算法 | 输入 | 输出 | 代码位置（规划） |
|---|---|---|---|
| `IS.Setup(param)` | 标准签名参数 | param_I = { τ ← K(1^λ) }（NIZKAoK 的 CRS） | `params.py` |
| `IS.Convert(σ, m, pk*, pk)` | 标准签名 σ、消息 m、真实公钥 pk*、公钥集 pk（pk* ∈ pk） | 若 `Verify(σ,m,pk*)=0` 输出 ⊥；否则 σ_I = π | `incognito_*.py::convert` |
| `IS.CVerify(σ_I, m, pk)` | 匿名签名、消息、公钥集 | 1 / 0 | `incognito_*.py::cverify` |

**正确性**：`IS.CVerify(IS.Convert(σ, m, pk*, pk), m, pk) = 1`。

### 1.4 两条安全性质（Theorem 3.1 / 3.2）

| 性质 | 依赖 | 证明骨架 | 我们如何测（→ `tests/`） |
|---|---|---|---|
| **不可伪造性**（w.r.t. insider corruption） | 底层签名不可伪造 + NIZKAoK 有 witness-extended emulation | 模拟器把挑战公钥 pk\* 随机塞进环的某位；正常回答 signing/corruption/conversion 三个 oracle（A 若腐化 pk\* 则失败，损失因子 1/n）；A 产出伪造后，用 witness-extended emulation 从 π 抽出 (σ\*, b, a)：由 **a**∘**b** = **0** 推出 **b** 二元、由 ⟨**b**,**1**⟩ = 1 推出恰一位为 1 ⟹ 环里某个 pk_j 上有合法签名；若 pk_j = pk\*（概率 ≥ 1/n）则 (σ\*, m\*) 是底层签名的伪造 | `test_unforgeability.py`：篡改 π 各字段 → CVerify 必拒；非法 b → prover 失败 |
| **（强）后置匿名性** | NIZKAoK 零知识 | π 不泄露 σ、pk_j、下标 j 的任何信息；C_pk 是完美隐藏的 Pedersen 承诺 | `test_anonymity.py`：重复 T 次，攻击者猜中率 ≈ 1/n |

> §3.2 的通用构造给的是 **strong anonymity**。但 §4.1 的 Schnorr 具体实例化为了避免"对哈希原像做 zk-SNARK"，退了一档到 **anonymity w.r.t. non-signer**（原因见 §2.1 note）。

---

## 2. §4.1 Incognito Schnorr Signature

### 2.1 标准 Schnorr 回顾

```
Setup:  (G, p, g, H: {0,1}* × G → Z_p)
KeyGen: sk = x ←$ Z_p ;  pk = g^x
Sign(m, x):   r ←$ Z_p ;  R = g^r ;  c = H(m, R) ;  z = r + c·x ;   σ = (c, z)
Verify(σ, m, pk):   R' = g^z · pk^{−c} ;   accept ⇔ c == H(m, R')
```
恒等式：`g^z = g^{r + cx} = R · pk^c`，且 `c = H(m, R)`。

> **关键观察**：Schnorr 验证要算 `c = H(m, R = g^z·pk^{−c})`——pk 在哈希函数**里面**。按 §3.2 通用构造要藏 pk 就得对"哈希原像"做 zk-SNARK，太重。
> **论文的做法**：换一个具体构造，**把 R 直接放进匿名签名**（不藏 R）。代价：签名者自己生成过 R，看到 R 就能把 σ_I 连回自己的签名 ⟹ 只剩 **对非签名者匿名**（strong anonymity 需要藏 R，本构造不做）。
> → 这是我们报告 §5.3 要讲的"简化/权衡"，也进 `AMBIGUITIES.md`。

### 2.2 `IS.Setup`（§4.1）→ `params.py`

```
param_I = {
  h        ←$ G                       // Pedersen 盲化基点
  g_vec = (g_1, …, g_n)  ←$ G^n        // Bulletproof 左生成元向量
  h_vec = (h_1, …, h_n)  ←$ G^n        // Bulletproof 右生成元向量
  H_g : Z_p × G^n → G                 // hash-to-curve，导出承诺基点 g_0
  H_z : G^2 → Z_p                     // π_z 的 FS 挑战
  H_w : G^5 → Z_p^2                   // 输出 (y, w)
  H_x : G^2 × Z_p^2 → Z_p             // 输出 x
  H_d : Z_p^5 → Z_p                   // 输出 d（合并 Eq.6/Eq.7）
}
```
- h、g_vec、h_vec 用 **nothing-up-my-sleeve** 方式导出（域分离哈希到曲线，种子如 `"IS/gen/g/{i}"`），保证无人知道相互间的离散对数关系——soundness 证明依赖这点。
- n 若不是 2 的幂：用 decoy 公钥补齐到下一个 2^k（`params.py::pad_ring`），报告说明对匿名集语义的影响。
- **待定（AMBIGUITIES）**：H_g 的 hash-to-curve 具体方法（RFC 9380 SSWU vs try-and-increment）。

### 2.3 `IS.Convert`（Schnorr）→ `incognito_schnorr.py::convert`

输入 σ = (c, z)、m、pk\*、pk = {pk_1,…,pk_n}，pk_j = pk\*。

**Step 0 — 恢复 R、检查合法性**
```
若 pk* ∉ pk 或 Verify(σ, m, pk*) = 0:  return ⊥
R = g^z · pk_j^{−c}
```
使得 `g^z = R · (pk^b)^c`，b 为 j 处的 one-hot，c = H(m, R)。

**Step 1 — 承诺真实公钥 pk_j**（`commit.py`）
```
g_0 = H_g(c, pk)                       // 承诺基点，绑定到 c 和整个环
β  ←$ Z_p
C_pk = g_0^β · pk_j   ( = g_0^β · pk^b )   // Pedersen，完美隐藏
```

**Step 2 — π_z：Σ-协议证明知道 (z, β)**（`sigma_z.py`）

要证明的线性关系：`g^z · g_0^{βc} = R · C_pk^c`
（验证：R·C_pk^c = R·(g_0^β pk_j)^c = R·pk_j^c·g_0^{βc} = g^z·g_0^{βc} ✓，因为 g^z = R·pk_j^c）

```
r_z, r_β  ←$ Z_p
R_z = g^{r_z} · g_0^{r_β · c}                 // commit
c_z = H_z(R_z, C_pk)                          // Fiat-Shamir 挑战
s_z = r_z + c_z · z                           // response
s_β = r_β + c_z · β
π_z = (R_z, s_z, s_β)
```

**Step 3 — π'_b：证明 b 是 one-hot 且 C_pk 承诺的是 pk^b**（`onehot.py`，见 §3）

**输出**：`σ_I = (R, C_pk, π_z, π'_b)`

### 2.4 `IS.CVerify`（Schnorr）→ `incognito_schnorr.py::cverify`

```
c   = H(m, R)
g_0 = H_g(c, pk)

# --- 检查 π_z = (R_z, s_z, s_β) ---
c_z = H_z(R_z, C_pk)
assert  g^{s_z} · g_0^{s_β·c}  ==  R_z · R^{c_z} · C_pk^{c·c_z}

# --- 检查 π'_b ---（见 §3.4）
```

π_z 验证式推导：
```
LHS = g^{r_z + c_z z} · g_0^{(r_β + c_z β)c}
    = (g^{r_z} g_0^{r_β c}) · (g^z g_0^{βc})^{c_z}
    = R_z · (R · C_pk^c)^{c_z}
    = R_z · R^{c_z} · C_pk^{c·c_z}   ✓
```

### 2.5 为什么这样就够了（正确性直觉）

- π'_b ⟹ **b** 是 one-hot 且 `C_pk = g_0^β · pk_j`（环里第 j 个公钥，j 隐藏）
- π_z ⟹ 存在 z 使 `(R, z)` 是 `C_pk` 所承诺公钥的合法 Schnorr 签名（`g^z = R·pk_j^c`, `c = H(m,R)`）
- 合起来：环里**某个**公钥在 m 上有合法 Schnorr 签名，但验证者看不出是哪个
- 匿名性：C_pk 完美隐藏；π_z、π'_b 零知识

---

## 3. 附录 D.1 — π'_b 的完整构造

> 这是整个项目的技术核心。目标：证明 `b ∈ {0,1}^n`、`⟨b,1_n⟩ = 1`、且 `C_pk = g_0^β · pk^b`，证明大小 **O(log n)**。

### 3.1 从约束到单条内积等式

令 **a** := **b** − **1**_n。则：
- `b ∈ {0,1}^n`  ⟺  `a ∘ b = 0`（因为 a_i·b_i = (b_i−1)b_i = 0 ⟺ b_i ∈ {0,1}）
- `a = b − 1_n`  这条本身也要证（否则 prover 可乱选 a）

用随机挑战 **y**_n 把"向量等于 0"降成"标量等于 0"（Schwartz–Zippel）：
```
⟨b, a∘y_n⟩ = 0            (A)  ← a∘b = 0 的随机线性组合
⟨b − 1_n − a, y_n⟩ = 0    (B)  ← a = b − 1_n
⟨b, 1_n⟩ = 1              (C)
```
再用随机挑战 w 把三条合成一条：
```
w²·(C) + w·(B) + (A):
   w²·⟨b,1_n⟩ + w·⟨b−1_n−a, y_n⟩ + ⟨b, a∘y_n⟩ = w²
```

**关键改写**（附录给结论，下面是独立验算）：
```
⟨ b − w·1_n ,  y_n∘(a + w·1_n) + w²·1_n ⟩  =  w² − w³n + (w − w²)·⟨1_n, y_n⟩     (★)
```

<details>
<summary>展开验算（组员务必自己推一遍）</summary>

左边拆 4 项：
```
⟨b, y_n∘(a+w·1_n)⟩ + ⟨b, w²·1_n⟩ − w⟨1_n, y_n∘(a+w·1_n)⟩ − w⟨1_n, w²·1_n⟩
```
- 项1 = ⟨b, a∘y_n⟩ + w⟨b, y_n⟩
- 项2 = w²⟨b, 1_n⟩
- 项3 = −w⟨a, y_n⟩ − w²⟨1_n, y_n⟩
- 项4 = −w³·n          （⟨1_n,1_n⟩ = n）

合并：`⟨b,a∘y_n⟩ + w⟨b−a, y_n⟩ + w²⟨b,1_n⟩ − w²⟨1_n,y_n⟩ − w³n`

honest 时 a = b−1_n ⟹ b−a = 1_n ⟹ w⟨b−a,y_n⟩ = w⟨1_n,y_n⟩；
且 ⟨b,a∘y_n⟩ = 0，⟨b,1_n⟩ = 1：

`= 0 + w⟨1_n,y_n⟩ + w² − w²⟨1_n,y_n⟩ − w³n = w² − w³n + (w−w²)⟨1_n,y_n⟩`  ✓ = (★) 右边
</details>

于是问题变成证明 `⟨l, r⟩ = t_0`，其中（**盲化前**）：
```
l "=" b − w·1_n
r "=" y_n∘(a + w·1_n) + w²·1_n
t_0 = w² − w³n + (w − w²)·⟨1_n, y_n⟩      // 常数，验证者可自算，无需见证
```

### 3.2 盲化 + 多项式承诺（π_b，O(n) 版）→ `onehot.py::prove_linear`

```
α, ρ, ζ  ←$ Z_p ；  s_a, s_b  ←$ Z_p^n           // 盲化标量 / 盲化向量

A    = h^α · g_vec^b · h_vec^a                   // 向量 Pedersen 承诺 (b, a)
S    = h^ρ · g_vec^{s_b} · h_vec^{s_a}           // 承诺盲化向量
S_pk = g_0^ζ · pk^{s_b}                          // 额外：把 s_b 也绑到 pk 基（供 Eq.7）

(y, w) = H_w(A, S, S_pk, g_0, C_pk)              // FS 挑战

# 一次多项式（系数是向量）
l(X) = (b − w·1_n) + s_b·X
r(X) = y_n∘(a + w·1_n + s_a·X) + w²·1_n
t(X) = ⟨l(X), r(X)⟩ = t_0 + t_1·X + t_2·X²
   t_0 = w² − w³n + (w−w²)⟨1_n, y_n⟩
   t_1 = ⟨s_b, y_n∘(a+w·1_n) + w²·1_n⟩ + ⟨b − w·1_n, y_n∘s_a⟩
   t_2 = ⟨s_b, y_n∘s_a⟩

τ_1, τ_2  ←$ Z_p
T_1 = g^{t_1}·h^{τ_1} ；  T_2 = g^{t_2}·h^{τ_2}   // 对 t_1, t_2 的 Pedersen 承诺

x = H_x(T_1, T_2, y, w)                          // FS 挑战

l = l(x) ；  r = r(x) ；  t̂ = t(x)
τ_x = τ_2·x² + τ_1·x       // t̂ 的盲化（t_0 无盲化，验证者自算）
μ   = α + ρ·x              // A·S^x 的盲化
ν   = β + ζ·x              // C_pk·S_pk^x 的盲化

π_b = (A, S, S_pk, T_1, T_2, τ_x, μ, ν, t̂, l, r)     // 大小 O(n)（l, r 是 n 维）
```

**π_b 的验证（4 条等式）→ `onehot.py::verify_linear`**：
```
(4)  t̂ = ⟨l, r⟩
(5)  g^{t̂}·h^{τ_x} = g^{t_0} · T_1^x · T_2^{x²}          其中 t_0 = w²−w³n+(w−w²)⟨1_n,y_n⟩
(6)  h^μ · g_vec^l · h'_vec^r = A · S^x · g_vec^{−w·1_n} · h'_vec^{w·y_n + w²·1_n}
(7)  g_0^ν · pk^l = C_pk · pk^{−w·1_n} · S_pk^x
```
其中 **h'_vec** 定义（把 y_n 的权重折进右生成元）：
```
h'_i := h_i^{y^{−(i−1)}}     即  h'_vec = (h_1, h_2^{y^{-1}}, h_3^{y^{-2}}, …, h_n^{y^{-(n-1)}})
```

<details>
<summary>Eq.(6) 验算</summary>

RHS 的 A·S^x = h^{α+ρx}·g_vec^{b+s_b x}·h_vec^{a+s_a x} = h^μ·g_vec^{b+s_b x}·h_vec^{a+s_a x}

g_vec 指数：`b + s_b x − w·1_n = l` ✓

h 侧：需证 `h'_vec^r = h_vec^{a+s_a x} · h'_vec^{w·y_n + w²·1_n}`
- r_i = y^{i-1}(a_i + w + s_{a,i}x) + w²  ⟹  r_i·y^{-(i-1)} = (a_i + w + s_{a,i}x) + w²y^{-(i-1)}
- 故 h'_vec^r = h_vec^{a + w·1_n + s_a x} · h'_vec^{w²·1_n}
- 而 RHS：h_vec^{a+s_a x} · h'_vec^{w·y_n} · h'_vec^{w²·1_n}；其中 h'_vec^{w·y_n} = ∏(h_i^{y^{-(i-1)}})^{w y^{i-1}} = h_vec^{w·1_n}
- ⟹ RHS h 侧 = h_vec^{a + w·1_n + s_a x}·h'_vec^{w²·1_n} = h'_vec^r ✓
</details>

Eq.(7) 验算：`g_0^ν·pk^l = g_0^{β+ζx}·pk^{b−w·1_n+s_b x} = (g_0^β pk^b)·(g_0^ζ pk^{s_b})^x·pk^{−w·1_n} = C_pk·S_pk^x·pk^{−w·1_n}` ✓

> **实现建议**：先做到这里（π_b 线性版），用随机合法 one-hot **b** 跑通 (4)–(7)，再拿它给下面压缩版做对拍基准。

### 3.3 压缩为 O(log n)（π'_b）→ `onehot.py::prove` + `ipa.py`

用 `d = H_d(x, τ_x, μ, ν, t̂)` 把 Eq.(6) 和 Eq.(7)^d 相乘合并：
```
(8)  g_0^{dν}·h^μ·(g_vec ∘ pk^d)^l·h'_vec^r
     = A·S^x·C_pk^d·S_pk^{xd}·(g_vec ∘ pk^d)^{−w·1_n}·h'_vec^{w·y_n + w²·1_n}
```
定义 `P := (g_vec ∘ pk^d)^l · h'_vec^r`。从 (8) 解出（**验证者能从公开值算出 P**）：
```
P = A·S^x·C_pk^d·S_pk^{xd}·(g_vec∘pk^d)^{−w·1_n}·h'_vec^{w·y_n+w²·1_n}·g_0^{−dν}·h^{−μ}
```
然后对 `(P, t̂)`、见证 `(l, r)`、生成元 `G := g_vec ∘ pk^d` 与 `H := h'_vec`，跑 **Bulletproofs 内积论证** 得 π_B（证明 `P = G^l·H^r ∧ ⟨l,r⟩ = t̂`，只发 2⌈log₂n⌉+2 个元素而不是 l, r 两个 n 维向量）。

```
π'_b = (A, S, S_pk, T_1, T_2, τ_x, μ, ν, t̂, π_B)
```

**π'_b 验证 → `onehot.py::verify`**：
```
(y, w) = H_w(A, S, S_pk, g_0, C_pk)
x = H_x(T_1, T_2, y, w)
assert  g^{t̂}·h^{τ_x} == g^{w²−w³n+(w−w²)⟨1_n,y_n⟩}·T_1^x·T_2^{x²}       // Eq.(5)
d = H_d(x, τ_x, μ, ν, t̂)
h'_vec = (h_1, h_2^{y^{-1}}, …, h_n^{y^{-(n-1)}})
P = A·S^x·C_pk^d·S_pk^{xd}·(g_vec∘pk^d)^{−w·1_n}·h'_vec^{w·y_n+w²·1_n}·g_0^{−dν}·h^{−μ}
verify_IPA(π_B, P, t̂, G = g_vec∘pk^d, H = h'_vec)                       // Eq.(4)+(8)
```

### 3.4 Bulletproofs 内积论证（π_B）→ `ipa.py`

标准递归折半协议（[Bünz et al. 2018] §3）。证明 `P = G^l·H^r·u^{⟨l,r⟩}` 型陈述（这里把 t̂ 用一个额外基点 u 绑定，或按论文把 t̂ 单独验），n → n/2 每轮：
```
每轮 k（当前长度 m = n/2^{k-1}）:
  L_k = G_{[m/2:]}^{l_{[:m/2]}} · H_{[:m/2]}^{r_{[m/2:]}} · u^{⟨l_{[:m/2]}, r_{[m/2:]}⟩}
  R_k = G_{[:m/2]}^{l_{[m/2:]}} · H_{[m/2:]}^{r_{[:m/2]}} · u^{⟨l_{[m/2:]}, r_{[:m/2]}⟩}
  u_k = Hash(L_k, R_k)                       // FS 挑战
  G' = G_{[:m/2]}^{u_k^{-1}} ∘ G_{[m/2:]}^{u_k}
  H' = H_{[:m/2]}^{u_k}     ∘ H_{[m/2:]}^{u_k^{-1}}
  l' = l_{[:m/2]}·u_k     + l_{[m/2:]}·u_k^{-1}
  r' = r_{[:m/2]}·u_k^{-1} + r_{[m/2:]}·u_k
⌈log₂ n⌉ 轮后 l, r 各剩 1 个标量 (a, b)
π_B = ( {(L_k, R_k)}_{k=1..log n},  a,  b )
```
验证者用同样的 u_k 把 P 和生成元折叠到最后，检查 `P_final == G_final^a · H_final^b · u^{a·b}`。

> **n 必须是 2 的幂** ← 折半递归。这是 `params.py::pad_ring` 的原因。

### 3.5 大小核对（验证目标）

| 部件 | G 元素 | Z_p 元素 |
|---|---|---|
| π_B（IPA） | 2⌈log₂n⌉ | 2 (a, b) |
| π'_b 其余 (A,S,S_pk,T_1,T_2 / τ_x,μ,ν,t̂) | 5 | 4 |
| **π'_b 小计** | **2 log n + 5** | **6** |
| π_z (R_z / s_z,s_β) | 1 | 2 |
| σ_I 其余 (R, C_pk) | 2 | 0 |
| **σ_I 总计** | **2 log n + 8** | **8** |

按压缩点 33 B、标量 32 B：`(2⌈log₂n⌉+8)·33 + 8·32`
→ n=2: **586**，n=8: **718**，n=64: **916**，n=1024: **1180**，n=4096: **1312** —— **与论文 Table 1 完全一致**。
若我们实现出来的大小对不上这几个数，就是 π'_b 结构写错了（强诊断信号）。

### 3.6 安全性质（附录 D.2，Lemma D.3 / D.4 / D.5）

| 性质 | 怎么来的 | 对我们的意义 |
|---|---|---|
| 完备性 | honest 的 l(x), r(x) 满足 (4)–(8)（附录 D.2 逐式验算） | `test_onehot.py` 正例 |
| Witness-extended emulation（soundness） | 3 个不同 x 的 transcript → 抽 t_1,t_2,τ_1,τ_2；2 个不同 x 对 Eq.(6) → 抽 (α,b,a,ρ,s_b,s_a)；代入 ⟨l,r⟩=t(X) 比系数 → "不含 x 的项"给出 ⟨b,a∘y_n⟩=0 ∧ ⟨b−1_n−a,y_n⟩=0 ∧ ⟨b,1_n⟩=1；再对 n 个不同 y ⟹ b 二元 ∧ a=b−1_n ∧ Σb=1 ⟹ **b one-hot**。对 Eq.(7) 2 个不同 x → 抽 β,ζ ⟹ C_pk = g_0^β·pk^b | soundness 不能直接测，但可测"非法 b 造不出证明" |
| Perfect HVZK（零知识） | 模拟器随机选 x,w,y,d,μ,ν,t̂ 和 S,T_2,S_pk，反解 T_1,A；π_B 用 Bulletproof 的 HVZK 模拟器；挑战用随机预言机编程 | `test_anonymity.py`：σ_I 各字段与 j 统计独立 |

### 3.7 Fiat–Shamir 依赖链（实现必须严格照此顺序）

```
g_0  = H_g( c , pk )                          ← c = H(m, R)
(y,w) = H_w( A , S , S_pk , g_0 , C_pk )
x     = H_x( T_1 , T_2 , y , w )
d     = H_d( x , τ_x , μ , ν , t̂ )
u_k   = Hash( L_k , R_k )   （IPA 每轮）
```
这条链是 unforgeability 证明里防"conversion-oracle 重放"的关键（g_0 绑定到 c 和 pk，c_z 绑定到 C_pk）。`transcript.py` 每个 H_* 用独立域分离前缀（如 `b"IS-secp256k1/H_w"`），hash-to-scalar 用 SHA-256 → int mod p 加拒绝采样。

---

## 4. §4.2 Incognito (EC)DSA —— 只有 Step 0 / π_z 变，π'_b 完全复用

标准 (EC)DSA（GenDSA 框架）：
```
Sign(m,x):   k ←$ Z_p ;  r = f(g^k) ;  s = k^{-1}(H(m) + r·x) ;   σ = (r, s)
                          // ECDSA: f(P) = P.x mod p
Verify(σ,m,pk):   K = (g^{H(m)}·pk^r)^{s^{-1}} ;   accept ⇔ r == f(K)
```
Incognito 版验证式：`K^s = g^{H(m)}·(pk^b)^r`

`IS.Convert`（ECDSA）：
```
Step 0:  K = (g^{H(m)}·pk_j^r)^{s^{-1}}
Step 1:  g_0 = H_g(K, m, pk)             // 注意：比 Schnorr 版多了 m
         C_pk = g_0^β · pk_j
Step 2 (π_z for s):
         r_z, r_β ←$ Z_p
         R_z = K^{r_z} · g_0^{r_β·r}
         c_z = H_z(R_z, C_pk)
         s_z = r_z + c_z·s ;  s_β = r_β + c_z·β
Step 3:  π'_b —— 与 Schnorr 版完全相同
输出:    σ_I = (K, C_pk, π_z, π'_b)
```
`IS.CVerify`（ECDSA）π_z 检查：
```
g_0 = H_g(K, m, pk) ;  r = f(K) ;  c_z = H_z(R_z, C_pk)
assert  K^{s_z}·g_0^{s_β·r}  ==  R_z·(g^{H(m)}·C_pk^{r})^{c_z}
```
→ 代码上 `incognito_ecdsa.py` 相对 `incognito_schnorr.py` 改动 < 30 行；`onehot.py` / `ipa.py` 零改动。

---

## 5. 公式 ↔ 函数 对照表（边写边补）

| 论文 | 公式/步骤 | 代码函数 | 状态 |
|---|---|---|---|
| §4.1 | 标准 Schnorr Sign/Verify | `schnorr.py::sign/verify` | ⬜ |
| §4.2 | 标准 (EC)DSA Sign/Verify | `ecdsa_std.py::sign/verify` | ⬜ |
| §4.1 IS.Setup | 生成元向量 + H_* | `params.py::setup` / `transcript.py` | ⬜ |
| §4.1 Step 1 | C_pk = g_0^β·pk_j | `commit.py::pedersen` | ⬜ |
| §4.1 Step 2 | π_z (R_z, s_z, s_β) | `sigma_z.py::prove/verify` | ⬜ |
| D.1 §3.2 | π_b 线性版 (4)–(7) | `onehot.py::prove_linear/verify_linear` | ⬜ |
| D.1 §3.3 | π'_b 压缩版 + Eq.(8) | `onehot.py::prove/verify` | ⬜ |
| D.1 §3.4 | Bulletproof IPA | `ipa.py::prove/verify` | ⬜ |
| §4.1 | IS.Convert / IS.CVerify (Schnorr) | `incognito_schnorr.py` | ⬜ |
| §4.2 | IS.Convert / IS.CVerify (ECDSA) | `incognito_ecdsa.py` | ⬜ |
| §1.1 | 双层 CBDC 场景 | `demo/cbdc_demo.py` | ⬜ |

---

## 6. 待澄清清单（→ `AMBIGUITIES.md`）

1. **H_g 的 hash-to-curve 方法**：论文只写签名 `H_g: Z_p × G^n → G`，没给构造。拟用 RFC 9380 secp256k1 SSWU 或 try-and-increment。
2. **g_vec, h_vec, h 的生成方式**：论文说 "random independent generators"，我们用域分离哈希到曲线的 NUMS 方式。
3. **环大小非 2 的幂**：Bulletproof 折半要求 n = 2^k，用 decoy 补齐——对"匿名集大小"的语义有轻微影响（真实匿名集是 n，但其中若干是 padding decoy）。
4. **π_B 里 t̂ 的绑定方式**：论文把 Eq.(5)（t 多项式检查）和 IPA 分开写；标准 Bulletproof 用额外基点 u 把 ⟨l,r⟩ 绑进 P。需确认按论文的分离写法实现。
5. **H_w 输出 Z_p^2 = (y, w)**：两个挑战从一次哈希取——拟用 `SHA256(prefix ‖ inputs ‖ 0) → y`, `SHA256(prefix ‖ inputs ‖ 1) → w`。
6. **s_z / s_β 与 π_z 的 R_z 命名**：论文 π_z 的 response 记号 (s_z, s_β) 与 π'_b 里的 s_b（盲化向量）易混，代码里分别叫 `resp_z / resp_beta` 和 `blind_b`。

---

## 7. 一个可手算的最小检查（建议 M1 前每人做一遍）

取玩具曲线（如 p 为 19 位素数的小 secp 类曲线）、n = 2、j = 1（真实签名者是环里第 1 个）：
1. 手动 KeyGen 两个密钥，对固定 m 做标准 Schnorr Sign，验证 `g^z = R·pk_1^c`
2. b = (1, 0)，a = (0, −1)，取小的 y, w，手算 (★) 左右两边看是否相等
3. 取 s_a, s_b 为小向量，算 l(x), r(x), t̂，验证 Eq.(4) `t̂ = ⟨l,r⟩` 和 Eq.(5)
4. 算 C_pk、S_pk，验证 Eq.(7)

能手推通 (★) 和 Eq.(4)(5)(7)，写 `onehot.py` 时就不会盲调。
