# LuaNilGuard 最佳架构（V2.1）

## 1. 目标与约束

目标是把工具稳定做成“高价值 Nil 风险筛查引擎”，而不是“全语义 Lua 编译器”。

必须同时满足：

1. 高可信：`safe/risky` 结论可追溯，有证据链。
2. 高可控：全仓任务可暂停、可恢复、可复跑。
3. 高性价比：静态层负责硬证据，LLM 只处理静态无法定论部分。

核心原则：

`Deterministic Static Floor + Agent Semantic Ceiling + Verification Gate`

## 2. 分层职责（当前最佳划分）

### L0. Repository Snapshot & Input Gate

职责：

1. 仓库发现（Lua 文件、配置、预处理文件）。
2. UTF-8 强约束与输入一致性门禁。
3. 快照化输入，保证同一输入可复现输出。

边界：

1. 不在此层做风险判定。
2. 不在此层做深度上下文扩展。

### L1. Candidate Engine（双通道）

职责：

1. `ast_exact` 主通道：基于语法树精确提取 sink 候选。
2. `lexical_fallback` 兜底：AST 不可用/解析失败时保底召回。
3. 候选标准化与去重（位置 + sink + arg）。
4. 明确标注 `candidate_source`。

边界：

1. 只发现“可能风险点”，不做安全/风险结论。

### L2. Static Evidence Kernel（轻量 AST）

职责：

1. 输出 `safe_static` / `unknown_static`。
2. 产出结构化 `StaticProof` / `StaticRiskSignal`。
3. 产出 `unknown_reason`（禁止静默回退）。

内建高价值证明：

1. guard/assert/defaulting。
2. loop index non-nil + reassignment invalidation。
3. bounded wrapper / return-slot / field-path 证据。
4. 宏字典与模块加载类非 nil 事实（如 `module(..., package.seeall)` 生态）。

边界：

1. 不做无界过程间分析。
2. 不做全局完备调用图求解。

### L3. Context Resolver（预算驱动）

职责：

1. 构建最小可判定 `EvidencePacket`。
2. 控制预算（depth / context lines / summaries）。
3. 首轮一跳，只有 uncertain 才允许二跳扩展。

边界：

1. 外部依赖缺证据时保持 `uncertain`，不臆断。

### L4. Agent Adjudication（uncertain-first）

职责：

1. 默认只处理 `unknown_static`。
2. 严格 schema 输出，不接受自由文本判决。
3. 记录 backend/model/skill/prompt 维度元数据以支持缓存与审计。

边界：

1. Agent 不直接“自由浏览仓库”。
2. 无证据不能输出高置信结论。

### L5. Verify & Verdict Composer

职责：

1. 合成静态证据与 agent 结论。
2. 应用证据门槛，防止弱证据高置信。
3. 输出可解释 `VerificationSummary`。

规则：

1. `safe_static` 在 uncertain-first 路由下可直接通过 verify 产出 `safe`/`safe_verified`。
2. 对冲突结论保守降级，不激进升级。

### L6. Run Orchestrator（持久化作业）

职责：

1. 阶段机：`INIT -> STATIC -> QUEUE -> LLM -> VERIFY -> FINALIZE`。
2. 持久化：`runs / file_tasks / case_tasks / adjudication_records / verdict_snapshots`。
3. 断点恢复：`run-start / run-resume / run-status / run-report / run-export-json`。

目标：

1. 支持长时全仓作业。
2. 支持失败恢复与重跑不重复。

### L7. Reporting & Governance

职责：

1. Markdown/JSON 报告。
2. 提案与分析（proposal export / analytics）。
3. 运行指标观测（候选来源、静态/LLM分层、失败归因）。

## 3. 关键数据契约

稳定契约如下：

1. `CandidateCase`（含 `candidate_source`）。
2. `StaticAnalysisResult`（含 `analysis_mode/unknown_reason`）。
3. `StaticProof` / `StaticRiskSignal`（含 kind/provenance/depth）。
4. `EvidencePacket`（静态证据 + 上下文 + 知识事实）。
5. `AdjudicationRecord`（agent 输出）。
6. `Verdict`（最终输出 + verification summary）。

契约要求：

1. 阶段之间只传结构化数据。
2. 任意高置信结论必须可回溯到结构化证据。

## 4. 性能与规模化策略

1. Parse-once：单文件单轮只解析一次，再分发 call/receiver/length/binary 索引。
2. Uncertain-first：把 LLM 调用量压缩到必要最小。
3. 预算化上下文：避免 prompt 膨胀和不稳定时延。
4. 作业持久化：中断恢复避免全量重算。

## 5. 非目标（明确不做）

1. 完整 Lua 语义解释器级推理。
2. 无界跨文件全图精确分析。
3. 自动写回线上 contracts/代码作为默认行为。

## 6. 质量护栏（发布前必须满足）

1. `unknown` 必须有 `unknown_reason` 或可解释原因。
2. 关键 sink（string/concat/pairs/ipairs/#/compare/arithmetic）回归稳定。
3. uncertain-first 默认开启且回归通过。
4. run 作业链路支持恢复且统计正确。
5. 文档、CLI、测试行为一致。

## 7. 为什么这是“当前最佳”

1. 比“全 AST”更可落地：成本可控且支持大仓运行。
2. 比“全 LLM”更可审计：下限由静态证据兜底。
3. 比混乱混搭更稳定：阶段职责清晰，失败可定位，演进可持续。

## 8. 当前实现状态（2026-03-05）

### 8.1 Context Resolver

1. 上下文预算已统一为结构化 budget（首轮/二跳两个固定档位）。
2. 二跳触发规则已固定为：`unknown_static` + 首轮仍 `uncertain` + backend 明确支持扩展重试。
3. 二跳触发结果已进入持久化运行指标（可回放、可统计）。

### 8.2 Verify Gate

1. `safe/risky` 高置信升级均由结构化静态分数门槛控制。
2. 弱风险证据不再默认升级为 `risky_verified/high`。
3. 新增冲突降级规则：强安全证据与强风险证据冲突时统一降级为 `uncertain`，并输出结构化 `VerificationSummary`（`structured_conflict_downgrade`）。

### 8.3 Run Observability

1. `run-status` / `run-report` 已输出阶段指标：
   - STATIC（总量/safe_static/unknown_static）
   - QUEUE（llm_enqueued）
   - LLM（llm_processed/llm_second_hop）
   - VERIFY（safe_verified/risky_verified）
   - FINALIZE（completed/failed）
2. 已输出 `unknown_reason` 分布（针对 `unknown_static`）。
3. `run-export-json` 契约已固定为对象：`{"run": {...}, "findings": [...]}`，其中 `run` 包含阶段指标和 `unknown_reason_distribution`。

### 8.4 状态结论

1. V2.1 主链路已成为默认执行路径。
2. Plan5 定义的执行性收口项（P5-5~P5-8）已完成并通过全量回归。
