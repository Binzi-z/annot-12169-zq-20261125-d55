# 安全隔离清单的放行承诺复核（Windows / Python 3.12 标准库）

题面见 `task/PROMPT.txt`。本仓库用 **仅 Python 3.12 标准库** 在 Windows 上实现了一个
**合成的**隔离放行工具：所有制品、密钥、根、角色均为本地确定性合成数据，不含任何真实
凭据或第三方依赖。

它回答题面中的事故：*重新验过、但尚未完成安全签发的制品，为什么重启后不该仅凭“它出现在
允许目录里”就被信任？* 答案是把**签名记录 + 实际文件摘要 + 撤销/任命状态**作为唯一事实源，
允许目录只是可被重建/隔离的派生状态。

---

## 1. 一键运行

在仓库根目录（原生 PowerShell/cmd 用 `py -3.12`，Git Bash 可用 `python`）：

```bat
py -3.12 run_all.py
```

它会依次执行并在结束时写出 **`REPORT.md`** 与 **`verification_report.json`**（根目录各一份，
`artifacts/reports/` 下一份 JSON/MD 副本），全部通过时退出码为 `0`，否则为 `1`：

1. 纯标准库 Ed25519 的 RFC 8032 测试向量自检；
2. `unittest` 套件（含三个真实双线程屏障用例，使用临时目录，速度快）；
3. 两个工作线程 + `threading.Barrier` 的三种确定性屏障复测；
4. 小模型穷举短交错；
5. 生成一个干净的黄金演练工作区 `artifacts/drill`；
6. **60,000 条 / 120 个分目录**模拟记录的“局部撤销 vs 全量”对照并报告真实计数。

常用参数：

```bat
py -3.12 run_all.py --quick            :: 用 1,200 条 / 12 目录做快速版
py -3.12 run_all.py --skip-unittest
py -3.12 run_all.py --scale-records 60000 --scale-shards 120 --partial-shards 4
```

单独跑测试：

```bat
py -3.12 -m unittest discover -s tests -v
```

---

## 2. 两个独立命令行工具

### 2.1 放行工具 `allowtool.py`

```bat
py -3.12 allowtool.py init
py -3.12 allowtool.py write-artifact --name app.bin --text "synthetic payload"
py -3.12 allowtool.py promote --id ALLOW-0001 ^
    --source artifacts\drill\quarantine\app.bin ^
    --issuer issuer.ivan --controllers ctrl.alice,ctrl.bob ^
    --seat SEAT-ISSUER-MAIN
py -3.12 allowtool.py revoke --target issuer.ivan --freeze-seat SEAT-ISSUER-MAIN
py -3.12 allowtool.py appoint --holder issuer.iris --seat SEAT-ISSUER-MAIN
py -3.12 allowtool.py barrier-cases
```

### 2.2 单独的重建工具 `reconstruct.py`（题面要求的“单独工具”）

它**不相信允许目录、状态位或已存水位**，而是从“磁盘上的真实文件 + 签名决定记录 +
合成 PKI/撤销/任命”重建真正允许的制品集合：

```bat
py -3.12 reconstruct.py --root artifacts\drill
py -3.12 reconstruct.py --root artifacts\drill --json
py -3.12 reconstruct.py --root artifacts\drill --quarantine
py -3.12 reconstruct.py --root artifacts\drill --update-watermark
```

退出码：`0` 干净；`4` 发现差异（孤儿/摘要不符/撤销/冲突/审计缺口/水位异常）；`2` 用法错误。
`--quarantine` 只把不允许的文件**移动**到 `quarantine_reconstructed/`，绝不删除。

---

## 3. 需求 → 实现对照

| 题面要求 | 实现位置 | 关键保证 |
|---|---|---|
| 每份允许决定绑定**安全规则代** | `isolation/rules.py`、`decision.py` | 决定签名体含 `rule_generation` 与 `rules_hash`；规则代由 `rules.admin` 的 Ed25519 签名发布；校验代次存在且哈希一致，可选 `--current-rules` 强制当前代 |
| 绑定**实际文件摘要** | `engine.py`（放行时现场 SHA-256）、`reconstructor.py`（重建时重新哈希磁盘文件） | 签名体含 `digest`/`size`/`rel_path`；按 `(相对路径, 实际sha256)` 精确匹配，同号不同摘要无法冒认 |
| **两个独立控制人的签名** | `isolation/decision.py`、`pki.py` | 签发人 + 两名控制人共 3 个 Ed25519 签名覆盖同一规范字节；两人必须是不同主体、证书有效且链到**不同固定根**；同根 `alice+cara` 判 `CONTROLLERS_SAME_ROOT`；控制人必须持 `cert_type=controller`，且不得与签发人是同一把钥匙 |
| **撤销的签发人不能经同根代理补位** | `pki.py: TrustView.evaluate_issuer`、`engine.appoint_successor` | 撤销签发人即冻结其席位；同根代理 `proxy.pia` 与同根克隆 `issuer.ivan2` 一律 `SAME_ROOT_PROXY_BACKFILL`，即使伪造别的 `seat` 提示或事后“任命”也无效；`proxy_for` 被撤销主体另加 `REVOKED_PRINCIPAL_PROXY`；只有**重新锚定到不同根**并经治理密钥签名任命的 `issuer.iris` 才能接任（任命同根继任会被工具直接拒绝） |
| **两个工作线程分别提交撤销/晋升，屏障复测三种情况** | `isolation/scenarios.py` | 每例真实 `threading.Thread` ×2 + `threading.Barrier(2)` + 有序事件，确定性无线程 sleep：①撤销先持久化 ②目录已改但审计回执丢失（含 hard / receipt-only 两变体）③同号不同摘要（冲突子例 + 屏障竞态子例） |
| **从文件和签名记录重建真正允许的制品** | `isolation/reconstructor.py`、`reconstruct.py` | 分类：`ALLOWED / ORPHAN_NO_DECISION / DIGEST_MISMATCH / PATH_BINDING_MISMATCH / ID_DIGEST_CONFLICT / BLOCKED:<原因>` 与 `missing`；冲突 fail-closed；可隔离 |
| **历史水位可复验** | `isolation/ledger.py` | 审计为哈希链（seq 连续 + `prev_hash` + 事件哈希）；`watermark.json` 与 `watermark_history.jsonl` 的每个历史点都能据链重算复验；可检测 `MATCH/STALE/DIVERGED/UNREADABLE/CHAIN_BROKEN` 并用 `--update-watermark` 修复 |
| **小模型穷举短交错** | `isolation/modelcheck.py` | 2 种步骤序 × 7 个故障世界 × `C(6,4)=15` 个保序交错 = **210 个交错**，每个交错的 **7 个前缀（共 1,470 个崩溃/重启点状态）**；校验“无见证不得 ALLOW / 有见证不得误拒”不变量；并给出朴素“在允许目录里就信任”模型的真实反例 |
| **六万条分目录模拟记录，局部撤销 vs 全量，报告实际目录/文件数** | `isolation/scale.py` | 默认 **120 个分片目录 × 500 = 60,000 个真实制品文件** + 每目录 `records.jsonl`（两条独立模拟 HMAC 标签）；局部只查 4 个目录并与全量结果的对应切片逐条比对；计数全部来自真实遍历与哈希 |

---

## 4. 三种屏障复测在证明什么

1. **`revoke_first_durable`（撤销先持久化）**：屏障对齐两线程后，强制撤销线程先把
   `issuer.ivan` 的治理签名撤销记录、哈希链事件和水位全部落盘（fsync + 原子替换），
   此时晋升线程仍停在提交线性化点之前；主线程确认“撤销在持久策略中可见、席位冻结、
   尚无决定文件”，再放行晋升线程。晋升在提交时重读持久策略 → `ISSUER_REVOKED` 被拒，
   允许目录为空。随后同根代理/克隆、未治理的异根继任均被拒，治理改锚后的 `issuer.iris`
   才成功。
2. **`dir_changed_audit_receipt_lost`（目录已改动但审计日志丢回执）**：
   - `hard`：危险的“先写目录后提交”窗口中崩溃——文件已在允许目录，但签名决定与审计回执
     都没了 → 重建判 `ORPHAN_NO_DECISION`，绝不允许，`--quarantine` 可移走；
   - `receipt_only`：签名决定还在、哈希链审计追加/水位回执丢了 → 仍可凭签名记录重建为
     `ALLOWED`，但明确标记 `audit_receipt_missing`，且因此 `clean=False`；水位指针被改旧后
     可重算并修复为 `MATCH`，历史水位点仍可复验。
3. **`same_number_different_digest`（同号不同摘要）**：两个有效签名记录共用 `DUP-C` 却绑定
   不同摘要 → `ID_DIGEST_CONFLICT`，该号不授权任何文件；屏障竞态子例让“EVIL 摘要的同号晋升”
   先提交并覆盖文件，随后撤销该号 → 重建把磁盘上的 EVIL 文件判为
   `BLOCKED:DECISION_REVOKED`。核心不变量：**决定号不是身份，`(路径, 实际摘要)` 才是。**

---

## 5. 规模对照的“实际检查数”（由遍历/哈希现场统计）

默认参数（`60000 / 120`，每目录 500，局部分片 4）下，`run_all.py` 会实测并写入报告：

| 扫描 | 实际目录 | 实际 SHA-256 的制品文件 | 读取的记录文件 | 文件总数 |
|---|---:|---:|---:|---:|
| 局部撤销复测 | **4** | **2,000** | 4 | 2,004 |
| 全量重建 | **120** | **60,000** | 120 | 60,120 |

局部批撤销其中每目录第 `j % 5 == 0` 条，共 **400** 条；等价性对照 **2,000** 条目标记录，
要求局部状态与全量切片 **0 不一致**（`scale.ok`）。以上数字由代码构造与计数口径唯一确定，
耗时与 HMAC 校验数则是运行时实测值，记录在 `REPORT.md` / `verification_report.json`。

---

## 6. 代码地图

```
allowtool.py                 # 放行/撤销/任命/屏障 CLI
reconstruct.py               # 独立重建 CLI（题面“单独工具”）
run_all.py                   # 一键自检 + 生成 REPORT.md / verification_report.json
isolation/
  ed25519.py                 # 纯标准库 Ed25519 + RFC8032 向量自检
  util.py                    # 规范 JSON、摘要、原子持久写、safe_rel_path、计数器
  pki.py                     # 合成根/证书、独立性、撤销、同根代理反补位状态机
  rules.py                   # 安全规则代与规则哈希签名
  decision.py                # 允许决定的绑定/签名/验证（fail-closed 包装）
  ledger.py                  # 哈希链审计 + 水位/历史复验
  workspace.py               # 目录布局、初始化、策略状态装载、治理签名
  engine.py                  # 晋升/撤销/任命 + 提交线性化点 + 丢回执故障注入
  reconstructor.py           # 从文件+签名记录重建真正允许集合
  scenarios.py               # 双线程 Barrier 三场景
  modelcheck.py              # 短交错穷举模型（可 python -m isolation.modelcheck）
  scale.py                   # 60k 分目录模拟 + 局部/全量对照
  report.py                  # Markdown 报告渲染
tests/test_isolation.py      # 快速 unittest（含三场景与小规模等价性）
```

运行后数据位于 git-ignored 的 `artifacts/`（合成密钥库也在其中，文件头带
`THROWAWAY DRILL KEYS` 警告）。

---

## 7. 安全说明

- Ed25519 为教学/演练用的经典大整数参考实现，仅服务少量安全关键签名；60k 批量路径使用
  快速 HMAC-SHA256 模拟“两个独立控制人标签”，代码与报告中均明确区分。
- 合成密钥由公开角色名确定性派生，**绝不可用于真实环境**。真实部署应换用受保护密钥库、
  文件锁/跨进程线性化与经过审计的签名实现。
