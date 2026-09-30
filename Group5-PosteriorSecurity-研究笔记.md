# Group 5 — Posterior Security: Anonymity and Message Hiding of Standard Signatures

## 基本信息

- **论文**：Tsz Hon Yuen, Ying-Teng Chen, Shimin Pan, Jiangshan Yu, Joseph K. Liu. *Posterior Security: Anonymity and Message Hiding of Standard Signatures*. ACM CCS 2025.
- **DOI**：10.1145/3719027.3744797
- **ePrint 全文（免费）**：https://eprint.iacr.org/2025/855
- **官方开源代码**：https://github.com/incognito-sig/incognito （Rust + `k256` 库，secp256k1曲线，小型参考实现，仓库仅2次提交，自带 `bench_wallet` / `bench_retail` / `bench_settlement` 三个基准测试）
- **所属作业选项**：FIT5163 A2 — Programming Option（40%），Group ID 5（原 Group 7，2026-09-30 因课题重排改号）
- **Tutor**：Ying-Teng Chen（本单元 Teaching Associate，同时也是本论文作者之一）

## 要解决的问题

很多场景下用户的私钥被锁在硬件（HSM）或第三方托管钱包里，只能通过标准化接口拿到一个**标准签名**（比如普通 ECDSA/Schnorr），没法在签名当下加匿名性或隐私特性。现有的匿名签名方案（ring signature、group signature）都要求"生成签名时就用特殊的匿名算法"，无法适配这种"签名已经生成、之后才想加隐私"的场景。

论文提出"**后置安全性 (posterior security)**"：先用标准算法正常签名，再由一个**不掌握私钥的第三方（converter）**把标准签名事后转换成具备匿名性/消息隐藏特性的版本。典型应用场景是两层央行数字货币（CBDC）：用户在第一层用标准钱包签名（便于银行合规审计），商业银行作为 converter 在第二层跨行结算前把签名匿名化，防止其他银行看到具体是谁转了多少钱。

## 核心技术方案

论文定义了两个新的密码学原语：

1. **Incognito Signature（匿名签名）**：把一个标准签名转成"这个签名是环里 N 个公钥中某一个签的，但外部看不出具体是谁"。
   - 核心是一个 NIZKAoK（非交互零知识证明），证明存在一个 one-hot 向量 `b`（只有一位是1，其余是0），使得 `pk = ∏ pk_i^{b_i}`，且原始签名对这个 `pk` 验证通过
   - 对 Schnorr/ECDSA，论文给出具体构造：先对真实签名者的公钥做 Pedersen 承诺 `C_pk`，再用类似 **Bulletproof** 的技术把 `b` 的证明压缩到 **O(log n)** 大小（而不是线性于环大小 n）
   - 论文正文强调这是**第一个实用的匿名 ECDSA 方案**：比现有唯一的ECDSA匿名方案 zkAttest 小 152～337 倍

2. **Concealed Signature（消息隐藏签名）**：把签名的消息隐藏进一个承诺（commitment）里，验证者只能验证承诺而看不到明文消息
   - 具体实例化用的是 **Boneh-Boyen 签名**，需要**配对（pairing）密码学**，跟 Incognito Signature 用的离散对数群是不同的数学基础

两者可以组合成 "incognito concealed signature"，同时提供匿名性和消息隐藏。

## 可行性评估

| 维度 | 评估 |
|---|---|
| 系统/硬件依赖 | ✅ **无**。纯密码学原语，不涉及TEE、不涉及区块链网络部署，本身就是一个自包含的 Sign/Convert/Verify(/Decom) 组件 |
| 官方参考代码 | ✅ 有专门的小型参考实现（github.com/incognito-sig/incognito），代码量不大，自带对应CBDC钱包/零售/结算三个应用场景的benchmark，比Group5那种生产级代码库好参考得多 |
| 核心密码学难度 | ⚠️ 高。核心ZK证明（Bulletproof式one-hot向量证明）技术含量不低，涉及内积论证(inner product argument)、承诺的同态性质，容易写错 |
| 现成对比基线 | ✅ 强。论文 Table 1 / Figure 1 直接给出 zkAttest、DualRing-EC 的签名大小和运行时间数字，复现实验后可以直接量化对比，report的"Evaluation and Critical Comparison"部分有据可依 |
| 与FIT5163课程知识的贴合度 | 较高，直接建立在Schnorr/ECDSA标准签名验证方程上，对应 Week 7-8 的 Digital Signature I/II 内容 |
| 论文新旧程度 | 2025年CCS刚发表，几乎没有二手资料/教程，全靠自己啃论文，但也意味着 Q&A 更看重理解深度而不是"抄现成解读" |
| 范围复杂度 | ⚠️ 如果 Incognito Signature + Concealed Signature 都做，工作量翻倍，且后者需要配对密码学这个新的数学门槛 |

## 建议的实现范围

**建议**：只做 **Incognito Signature**（针对 Schnorr 和/或 ECDSA），**排除 Concealed Signature**
- 理由：Concealed Signature 需要配对密码学（Boneh-Boyen签名），是相对独立的第二个贡献，和 Incognito Signature 不共享太多代码/数学基础，做两个等于做两个不同的项目
- 在报告里按作业规范 3.1 节要求说明：为什么选 Incognito Signature 作为核心组件、为什么排除 Concealed Signature、这个裁剪对"完整复现论文贡献"的影响

**语言建议**：默认**纯 Python 环境**跑（保持跟 Group 5 一致的默认选择），用支持 secp256k1 群运算的库（如 `coincurve`、`fastecdsa` 或标准 `cryptography` 库的EC模块）实现。
- 备选方案：由于官方仓库是小型 Rust 实现（不像 Group5 的 Substrate 代码那样庞大），如果组里 Rust 基础较好，直接对照官方代码用 Rust 实现也是可行的路径，好处是能直接复用官方的 benchmark 结构、方便逐行对比数字。但默认建议还是 Python，优先保证组内都能读懂、调试快。

## 工作量深度评估

### 组件拆解

| 组件 | 论文位置 | 复杂度 | 说明 |
|---|---|---|---|
| 标准 Schnorr / ECDSA sign+verify | §4.1, §4.2 | 低 | 用现成库实现或自己按标准公式写，几十行代码 |
| Pedersen Commitment `C_pk` | §4.1 step 1 | 低 | 跟 Group5 的承诺方案是同一类原语，容易复用 |
| ZK Proof for z/s (`π_z`) | §4.1 step 2 | 低-中 | 标准 Sigma 协议，跟 Group5 的 NIZK解密正确性证明（Fig9）结构类似 |
| **ZK Proof for one-hot 向量 (`π'_b`, Bulletproof式)** | §4.1 step 3 + 附录 | **高** | 核心难点，O(log n) 大小的内积论证，需要仔细研究附录里的具体构造 |
| IS.Convert / IS.CVerify 整体组装 | §3.2, §4.1, §4.2 | 中 | 把上面几块拼起来，Schnorr版本和ECDSA版本结构几乎一样（差别只在 R vs K 的计算方式） |
| 安全测试（匿名性+不可伪造性） | 对应§3.1安全模型 | 中 | 需要设计统计测试验证匿名性，以及篡改测试验证可靠性 |
| 基准测试复现（对比论文Table1/Fig1） | §4.3 | 中 | 测不同环大小n下的签名/证明大小、Sign/Convert/Verify耗时，跟论文数字对比 |
| ~~Concealed Signature (Boneh-Boyen)~~ | §5 | ~~高~~ | **建议排除**，需要配对库，数学门槛更高 |

### 建议实现阶段

| 阶段 | 任务 | 负责 |
|---|---|---|
| 1 | 全员精读论文（含附录里 Bulletproof one-hot 证明的具体构造）；选定语言/库；实现标准 Schnorr/ECDSA sign+verify + Pedersen commitment | 全员 |
| 2 | **π'_b (one-hot向量ZK证明)**（最难，优先做，权重也最大） | 2人主攻 |
| 3 | π_z (Sigma协议) + IS.Convert/IS.CVerify整体组装（Schnorr版本先跑通，再扩展到ECDSA版本） | 另外2人 |
| 4 | 系统集成：把两者拼成完整的 Incognito Signature 流程，跑通端到端 demo | 全员 |
| 5 | 安全测试（匿名性统计测试、篡改测试）+ 复现论文 Table1/Figure1 风格的基准测试，直接对比论文数字（包括跟 zkAttest、DualRing-EC 的比较） | 全员 |
| 6 | 报告撰写、slides、Q&A 彩排（注意：每人都要能单独回答关于全部组件的问题） | 全员 |

### 主要风险点

1. **π'_b 的 Bulletproof 式构造**是论文里语焉不详的部分（正文说"Details are given in the appendix"），需要花时间精读附录，必要时对照 Bulletproofs 原始论文（Bünz et al. 2018）理解内积论证的原理
2. **千万别把 Concealed Signature 也做进去**——配对密码学是完全独立的数学门槛（跟离散对数群运算不是一回事），会大幅拉长工期
3. 环大小 n 建议先在小范围测试（n=2,4,8）验证正确性，再扩展到论文测的 n=64/1024/4096 做基准复现
4. 报告里"Research Gaps"部分可以直接用论文自己的表述：作者承认目前只考虑"完全匿名"，不同程度的匿名性/可追责性（accountability）留作未来工作；Concealed Signature 和 Incognito Signature 目前需要不同的数学工具（离散对数 vs 配对），能否统一也是一个开放问题——这些都能作为你们的批判性分析素材

## 硬件/环境需求

比另一个偏系统方向的课题（TEE/区块链方向，当时对比时叫 Group 5，2026-09-30 重排后编号未知）更轻量——**默认纯 Python 环境跑**，不需要虚拟机/云服务器/Docker，也不需要 TEE 硬件或区块链网络（那个课题才需要考虑，我们（现 Group 5）从一开始就不涉及）。

| 项 | 需求 |
|---|---|
| TEE / 特殊硬件 | 不需要 |
| 区块链网络 | 不需要 |
| 配对密码学库（pairing） | 不需要（前提是排除 Concealed Signature） |
| 多方分布式部署 | 不需要——Incognito Signature 只有"签名者"和"converter"两个角色，可以在同一进程内用函数调用模拟，不需要多方协议 |
| 计算量 | 环大小n≤4096时，椭圆曲线运算+哈希，单次证明生成/验证是毫秒到秒级（论文原始benchmark: sign<0.2ms, convert<1s @ n=1024），普通CPU轻松胜任 |
| GPU | 不需要 |

**结论**：一台普通笔记本（Windows/Mac/Linux 均可）就能完成开发、测试和演讲现场 demo。

**Windows 上的坑**：同 Group5 笔记里提到的，优先选纯 Python 实现的EC库，避免需要编译C扩展的库在 Windows 上装环境的麻烦。

## 后续研究清单

在正式动手写代码前，建议提前研究：

### A. 密码学工程选型
- **底层群的选择**：论文用 secp256k1（跟比特币/以太坊的ECDSA兼容），Python里选一个成熟支持secp256k1点运算的库（如 `coincurve`，它是 libsecp256k1 的绑定，性能好且不用自己实现椭圆曲线运算）
- **精读附录里 π'_b 的具体构造**：正文只给了高层描述，具体的 Bulletproof 式证明步骤在附录，这是实现前必须搞懂的部分

### B. 建议提前泛读的背景论文
| 论文 | 为什么要读 |
|---|---|
| Bünz et al. 2018, *Bulletproofs* | π'_b 证明技术的源头，理解内积论证(inner product argument)原理 |
| Groth & Kohlweiss 2015, *One-out-of-many proofs* | 论文相关工作里提到的对比技术，zkAttest 也用了这个技术，理解它有助于说清楚"为什么Bulletproof式方案更高效" |
| zkAttest（论文引用[17]） | 你们要复现对比的baseline，github.com/cloudflare/zkp-ecdsa 有对应实现可以参考 |
| DualRing（论文引用[34]） | 另一个对比baseline，理解它的O(log n)构造方式 |

### C. 实操/管理类准备
- 提前找 Teaching Team 确认排除 Concealed Signature 的裁剪范围是否可接受
- 尽早建好共享 git 仓库 + 任务看板，保留贡献记录
- 提前搭好 IEEE 报告模板（Overleaf）
- 明确记录本次AI辅助研究的使用方式，按作业AI政策要求做disclosure

### D. 安全测试设计
- **匿名性测试**：固定一组公钥，随机选一个生成 incognito signature，重复多次统计验证者/攻击者无法以高于 1/n 的概率猜中真实签名者
- **不可伪造性测试**：篡改 `π'_b` 或 `C_pk` 中的某一部分，确认 `CVerify` 会拒绝
- **边界情况测试**：环里的公钥不包含真实签名公钥时，`IS.Convert` 应该输出 ⊥（拒绝）；环大小 n=1 的退化情况
- **基准复现**：测不同环大小(n=2,8,64,1024,4096)下的签名/证明大小，验证确实是 O(log n) 增长，并与论文 Table 1 的具体数字对比

## 待确认/下一步

- [ ] 联系 Teaching Team 确认只做 Incognito Signature（排除 Concealed Signature）这个裁剪范围是否可接受
- [ ] 精读 ePrint 全文附录，梳理 π'_b 的具体数学构造和步骤
- [ ] 评估官方 GitHub 仓库（incognito-sig/incognito）代码是否可以直接参考/复用（若使用需在代码和报告中明确注明来源）
- [ ] 确认组内是否有人具备椭圆曲线/离散对数密码学基础（Sigma协议、Fiat-Shamir变换）
- [ ] 联系 Ying-Teng Chen（Tutor兼论文作者）确认实现细节上的疑问
