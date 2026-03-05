# 架构 V2：高性能轻量 AST + LLM Agent

## 1. 架构目标

构建可用于大仓库、可长时间稳定运行的 Nil 风险审查系统，满足三件事：

1. 结论可信：`risky/safe` 必须有证据链。
2. 运行可控：全仓任务可中断恢复、可观测、可复跑。
3. 人机协同：静态系统打地基，LLM 负责语义裁决，不互相越权。

核心策略：

**确定性候选与证据（下限） + LLM 语义裁决（上限）**

不是“全 AST”，也不是“全 LLM”。

## 2. 第一性原理

产品价值不在“代码量大、规则多”，而在：

1. 找到真实高危 Nil 风险；
2. 尽可能减少误报；
3. 输出可审计、可复现的结论。

可抽象为：

`单位时间可信发现 = 候选召回质量 × 证据质量 × 裁决稳定性`

## 3. 分层架构

### L0 作业运行时（Job Runtime）

职责：

1. 管理单次全仓作业生命周期：
   `INIT -> STATIC -> QUEUE -> LLM -> VERIFY -> FINALIZE`
2. 提供 checkpoint/resume。
3. 统计阶段耗时、失败重试、队列积压。

目标：

- 不依赖人工反复触发命令；
- 支持 24 小时连续跑完单次全仓任务。

### L1 仓库快照层（Repository Snapshot）

职责：

1. 文件发现与 UTF-8 约束。
2. 配置加载（sink rules / contracts / macro config）。
3. 输入快照固化（文件 hash、版本签名）。

目标：

- 同一快照下结果可复现。

### L2 候选层（Candidate Engine）

双通道：

1. `ast_exact`（主通道）  
   用语法树精确提取真实调用和操作数。
2. `lexical_fallback`（兜底）  
   AST 不可用或文件解析失败时启用。

职责：

1. 候选去重；
2. 标记候选来源和置信等级；
3. 只“找案”，不“判案”。

### L3 轻量 AST 证据层（Static Evidence Engine）

职责（只做有性价比的本地可证明逻辑）：

1. guard / assert / defaulting / loop-index / reassignment 失效；
2. bounded origin/field-path 风险信号；
3. bounded wrapper/return-slot 证据；
4. 结构化 `unknown_reason`。

输出：

1. `safe_static | unknown_static`；
2. `StaticProof[]`；
3. `StaticRiskSignal[]`；
4. `analysis_mode / unknown_reason`。

边界：

1. 不做全程序符号执行；
2. 不做无界过程间控制流推导。

### L4 上下文解析层（Context Resolver）

职责：

1. 生成最小可判定证据包（本地上下文 + 相关函数摘要 + 相关片段）；
2. 严格预算控制（depth/lines/summaries）；
3. 仅在 uncertain 重试时扩展到二跳；
4. 外部依赖通过“索引查询”按需补证，不做运行时全目录暴力搜索。

输出：

- `EvidencePacket`

### L5 LLM Agent 裁决层（Adjudication）

职责：

1. 默认只处理 `unknown_static`；
2. 消费结构化证据包；
3. 输出严格 schema JSON（禁止自由文本判决）。

边界：

1. Agent 不直接浏览仓库；
2. 证据不足必须给 `uncertain`，不允许强行 `safe/risky`。

### L6 证据校验与判决合成（Verify + Compose）

职责：

1. 校验 agent 证据锚点与 provenance 一致性；
2. 合并静态证据、风险信号、agent 结论；
3. 执行置信度闸门，生成最终 `Verdict`。

规则：

- 没有可验证证据，不得给高置信结论。

### L7 报告与治理输出（Reporting）

职责：

1. markdown/json 审查报告；
2. proposal/export/analytics；
3. autofix 导出；
4. 阶段指标与质量指标输出。

## 4. 数据契约

必须稳定且可版本化的核心契约：

1. `CandidateCase`
2. `StaticAnalysisResult`
3. `StaticProof` / `StaticRiskSignal`
4. `EvidencePacket`
5. `AdjudicationRecord`
6. `Verdict`

要求：

- 阶段间禁止传递不可校验的自由文本结论。

## 5. 性能策略

### 5.1 AST 性能

1. `parse once`：单文件单轮只解析一次；
2. AST 派生索引缓存（`file_hash + parser_version + rule_version`）；
3. 选择性 AST：先筛候选文件，再做 AST；
4. 文件级预算：超时降级并记录原因，不允许静默失败。

### 5.2 LLM 性能

1. uncertain-first 路由；
2. context 预算 + 二跳按需重试；
3. 后端缓存键稳定化（backend/model/skill/prompt hash）。

### 5.3 大仓稳定性

1. 每阶段可恢复；
2. 有界重试 + 降级策略；
3. 退化模式可观测、可审计。

## 6. 质量护栏

1. 缺少安全证据 != 风险成立；
2. 缺少风险证据 != 安全成立；
3. `unknown` 必须结构化归因；
4. 高置信必须来自可验证证据；
5. `unknown` 积压是产品改进输入，不是终态。

## 7. 为什么是这个架构

### 不是“重型 AST 全包”

Lua 动态语义下，重型 AST 完备推理成本过高，边际收益递减快。

### 不是“LLM 全包”

纯 LLM 在可复现、可审计、批量稳定性上不够工程化。

### 最优平衡

1. 轻量 AST 负责“定位准 + 证据硬”；
2. LLM 负责“语义判定 + 不确定争议处理”；
3. 最终以证据校验闸门收敛输出质量。

## 8. 交付原则

V2 应作为一次受控重构交付，不继续在旧路径上叠补丁。

重构过程中允许模块边界重划、旧测试淘汰与重建，但必须保证：

1. 质量指标可比；
2. 运行行为可解释；
3. 结果输出可审计。

