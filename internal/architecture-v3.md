# LuaNilGuard V3 目标系统架构

## 1. 系统定位

LuaNilGuard 是一个高精度 Lua nil 风险筛查引擎。

目标 bug 类型：一个可能为 `nil` 的值被传入不接受 `nil` 的操作，导致运行时崩溃、非预期提前退出或静默的控制流错误。

核心设计原则：**Precision > Recall**。

- 宁可漏报边缘风险，不可用猜测性警告淹没开发者。
- 只有强证据支撑的风险才进入最终报告。
- 不确定的 case 触发更多自动化分析，而非立即升级给人类。

系统核心公式：

```
Deterministic Static Floor + Single-Pass Semantic Ceiling + Statistical Calibration Gate
```

与 历史版本 的区别：历史版本 使用 `Agent Semantic Ceiling`（多角色对抗），V3 替换为 `Single-Pass Semantic Ceiling`（单次结构化判定）并新增 `Statistical Calibration Gate`（离线统计校准）。

## 2. 分层架构

### L0. Repository Snapshot & Input Gate

职责（与 历史版本 一致）：

1. 仓库发现（Lua 文件、配置、预处理文件）。
2. UTF-8 强约束与输入一致性门禁。
3. 快照化输入，保证同一输入可复现输出。

**V3 扩展**：增加文件指纹（hash + mtime），为增量分析提供变更检测基础。

### L1. Candidate Engine（双通道）

职责（与 历史版本 一致）：

1. `ast_exact` 主通道：基于语法树精确提取 sink 候选。
2. `lexical_fallback` 兜底：AST 不可用时保底召回。
3. 候选标准化与去重（位置 + sink + arg）。
4. 标注 `candidate_source`。

**V3 扩展**：按文件粒度产出 candidate 并记录来源文件指纹，支持依赖图追踪。

### L2. Static Evidence Kernel

职责（与 历史版本 一致）：

1. 输出 `safe_static` / `unknown_static`。
2. 产出结构化 `StaticProof` / `StaticRiskSignal`。
3. 产出 `unknown_reason`（禁止静默回退）。

内建高价值证明（与 历史版本 一致）：

1. guard / assert / defaulting。
2. loop index non-nil + reassignment invalidation。
3. bounded wrapper / return-slot / field-path 证据。
4. 宏字典与模块加载类非 nil 事实。

**V3 扩展——标注验证器**：

1. 解析 Lua 注释中的 nil 标注（兼容 LuaLS / EmmyLua 风格）。
2. 验证标注与函数体的一致性（比推断简单一个数量级）。
3. 已标注函数的标注作为跨函数推理的 ground truth。
4. 未标注函数保守处理（与 precision-first 一致）。
5. 标注覆盖率作为可度量的质量指标。

### L3. Context Resolver（预算驱动）

职责（与 历史版本 一致）：

1. 构建最小可判定 `EvidencePacket`。
2. 控制预算（depth / context lines / summaries）。
3. 首轮一跳，只有 uncertain 才允许二跳扩展。
4. 外部依赖缺证据时保持 `uncertain`。

**V3 扩展——依赖追踪**：

1. 每个 `StaticResult` 记录其依赖的 `FunctionSummary` / `MacroFact` / `AnnotationFact` ID。
2. 上下文预算扩大（因单次判定节省的 token 重新分配到更好的上下文组装）。

### L4. Single-Pass Adjudication（替换多 Agent 模型）

**历史版本（已废弃）**：Prosecutor → Defender → Judge 三角色裁决。

**V3（目标）**：单次结构化判定。

1. 精心设计的单个 prompt，要求 LLM 同时输出 `risk_path`、`safety_evidence`、`status`、`confidence`。
2. 严格 JSON schema 输出，不接受自由文本判决。
3. 不做角色分裂——LLM 在同一上下文中同时考虑攻防两面。
4. 默认只处理 `unknown_static`。
5. 记录 backend/model/skill/prompt 维度元数据以支持缓存与审计。

替换理由：

1. 三角色看同一个 `EvidencePacket`，对抗只是 prompt 层面的角色扮演，不是信息层面的真正对抗。
2. 3 倍 token 成本，单 case 从 3 次调用降至 1 次。
3. Judge 的二阶推理（推理关于推理的推理）不可靠。
4. Verify gate 已用结构化分数门槛控制 verdict，多 Agent 的增量价值在下降。

Prompt 合同（从 SKILL.md 继承的不变原则）：

- Unknown is not risk.
- Absence of proof is not proof of bug.
- 只从提供的代码和声明的事实推理。
- 不做投机性 bug 声称。
- `uncertain` 是不完整证据的默认结论。

### L5. Calibration & Verdict Composer（替换 Verify Gate）

**历史版本**：合成静态证据与 agent 结论，应用证据门槛。

**V3（目标）**：在 历史版本 基础上增加离线统计校准层。

1. 合成静态证据与单次判定结论（保持）。
2. 应用证据门槛防止弱证据高置信（保持）。
3. 冲突降级规则（保持）。
4. **新增：离线校准层**。

离线校准层工作方式：

1. 收集历史判定结果，按 `(sink_type, unknown_reason, confidence)` 分桶统计实际精度。
2. 若模型对某类 case 说 "risky/high" 但历史上 30% 是错的，自动降级为 "risky/medium"。
3. 置信度来自统计，而非 LLM 自评。
4. 冷启动策略：校准数据不足时（< 30 个同桶样本），保持 LLM 原始输出不做校准。

### L6. Incremental Run Orchestrator（从批处理升级为依赖图驱动）

**历史版本**：批处理流水线 `INIT → STATIC → QUEUE → LLM → VERIFY → FINALIZE`，SQLite 持久化支持断点恢复。

**V3（目标）**：保留批处理作为全量模式，新增增量模式。

全量模式（保持 历史版本）：

- 阶段机不变。
- 持久化表结构不变。
- 断点恢复不变。

增量模式（新增）：

1. 依赖图模型：将分析产物建模为依赖图节点，节点之间有显式依赖边。

```
File(a.lua) ──→ Candidates(a.lua) ──→ StaticResult(case_001) ──→ Verdict(case_001)
                     │
File(helper.lua) ──→ FunctionSummary(helper.resolve) ─────────────┘
```

2. 变更传播：当文件变化时，失效该文件的 `FunctionSummary`，沿依赖边传播，只重新分析被失效的子图。
3. `run-incremental` 命令：接受 `--changed-files` 参数，只重算受影响子图。
4. 全量回退：依赖图不完整或脏数据时，自动降级为全量 run。
5. 增量结果与全量结果一致性 > 99%（可通过全量对照测试验证）。

### L7. Reporting & Governance

职责（与 历史版本 一致）：

1. Markdown / JSON 报告。
2. 提案与分析（proposal export / analytics）。
3. 运行指标观测（候选来源、静态/LLM 分层、失败归因）。

**V3 扩展**：

1. 新增 `annotation-coverage` 报告：输出标注覆盖率。
2. 校准数据统计报告：各 sink 类型的历史精度、校准修正量。

## 3. 关键数据契约

### 3.1 继承自 历史版本（稳定不变）

1. `CandidateCase`（含 `candidate_source`）。
2. `StaticAnalysisResult`（含 `analysis_mode` / `unknown_reason`）。
3. `StaticProof` / `StaticRiskSignal`（含 kind / provenance / depth）。
4. `EvidencePacket`（静态证据 + 上下文 + 知识事实）。
5. `Verdict`（最终输出 + verification summary）。

### 3.2 V3 变更

1. **`AdjudicationRecord`**：从 `prosecutor + defender + judge` 三字段简化为单个 `judgment` 字段（单次判定输出）。旧 `RoleOpinion` 模型废弃。
2. **`AnnotationFact`**（新增）：标注解析产物，包含 function_id / param_nullability / return_nullability / annotation_source。
3. **`FactDependency`**（新增）：依赖追踪记录，包含 fact_id / depends_on_file / depends_on_function / depends_on_annotation。
4. **`CalibrationBucket`**（新增）：校准分桶记录，包含 sink_type / unknown_reason / predicted_confidence / sample_count / actual_precision。
5. **`CandidateCase`**：新增 `file_fingerprint` 字段，支持增量变更检测。

### 3.3 契约要求

1. 阶段之间只传结构化数据。
2. 任意高置信结论必须可回溯到结构化证据。
3. 校准修正必须可审计（原始 confidence + 校准后 confidence + 校准依据）。

## 4. 新增子系统

### 4.1 标注解析器

- 独立于 Tree-sitter AST，解析 Lua 注释中的 nil 标注。
- 兼容 LuaLS / EmmyLua 已有标注风格。
- 输出 `AnnotationFact` 结构化数据。
- 与现有 `function_contracts.json` 并存，标注优先级高于 contract。

### 4.2 依赖图引擎

- SQLite 表 `fact_dependencies`，记录 `(fact_id, depends_on_file, depends_on_function)` 关系。
- 变更检测：比对文件指纹。
- 失效传播：BFS 沿依赖边标记脏节点。
- 保守策略：不追求 100% 增量覆盖，依赖图不完整时自动降级。

### 4.3 校准数据库

- SQLite 表 `calibration_buckets`，按 `(sink_type, unknown_reason)` 分桶。
- 在 `adjudication_records` 表中扩展 `(predicted_status, predicted_confidence, actual_outcome)` 字段。
- 生成校准查找表，在 L5 阶段修正 LLM confidence。
- 冷启动保护：样本不足时不校准。

## 5. 性能与规模化策略

1. Parse-once：单文件单轮只解析一次（保持 历史版本）。
2. Uncertain-first：只将 `unknown_static` 送入 LLM（保持 历史版本）。
3. Single-pass：每个 LLM case 只调用 1 次（V3 新增，从 3 次降至 1 次）。
4. Token 再分配：省下的 2/3 token 预算用于更好的上下文组装（V3 新增）。
5. 预算化上下文（保持 历史版本）。
6. 增量分析：PR 场景只重算受影响子图（V3 新增）。
7. 作业持久化：中断恢复避免全量重算（保持 历史版本）。

## 6. 非目标（明确不做）

继承自 历史版本：

1. 完整 Lua 语义解释器级推理。
2. 无界跨文件全图精确分析。
3. 自动写回线上 contracts / 代码作为默认行为。

V3 新增：

4. 多角色 Agent 对抗裁决（由单次结构化判定替代）。
5. 仓库级语义编译系统（由渐进式标注引导替代）。
6. Runtime 信号注入（远期可选，不在 V3 范围内）。
7. 自动化大规模 Autofix（仅保留最小修复建议能力）。

## 7. 与 历史版本 的迁移兼容策略

1. **L4（裁决层）**：在 `adjudication.py` 中新增 single-pass 路径，与多 Agent 路径并存，通过 A/B flag 切换。验证精度后再移除旧路径。
2. **L6（编排层）**：SQLite schema 增加依赖追踪表，现有 `run-start` 不变，新增 `run-incremental` 入口。
3. **L2（静态层）**：标注系统作为 `function_contracts.json` 的上位替代，优先级高于 contract 但 contract 仍保留为兜底。
4. **数据迁移**：新增表和字段均为增量添加，不破坏现有 SQLite 数据。
5. **CLI**：所有新命令独立新增，不修改现有命令语义。

## 8. 质量护栏

1. `unknown` 必须有 `unknown_reason` 或可解释原因。
2. 关键 sink 回归稳定（string / concat / pairs / ipairs / # / compare / arithmetic）。
3. uncertain-first 默认开启且回归通过。
4. 单次判定精度 >= 多 Agent 对抗（A/B 对比测试验证）。
5. 增量结果与全量结果一致性 > 99%。
6. 校准层运行后，高置信 verdict 的实际精度可度量且持续改善。
7. 文档、CLI、测试行为一致。
