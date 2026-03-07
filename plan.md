# LuaNilGuard V3 整体重构计划（最新）

## 执行锁定基线（2026-03-07）

本节为当前唯一执行基线。后续实现、验证、文档与回归均以本节为准，直到全部验收项达成为止；下文历史阶段记录仅保留参考价值。

### 一、完全达成目标（Definition of Done）

1. Tree-sitter 硬依赖
   - 任何分析命令在 Tree-sitter 不可用时直接失败。
   - 运行时不再存在 AST 缺失后的语义降级分支。
2. AST-lite（零推断）
   - AST 只保留：函数边界定位、候选定位、上下文切片、证据抽取。
   - 运行主链路不再使用 `proof/risk_signal` 做安全/风险裁决。
   - 不做跨函数 contract/return 推理。
3. 主裁决权交给 LLM
   - 默认 backend 改为 LLM backend（不再默认 heuristic）。
   - 主路径固定为“候选 + 结构化上下文 + 规则事实 + LLM 仲裁”。
   - heuristic 仅保留为测试桩或显式调试选项，不参与默认裁决。
4. 规则前置裁剪强化
   - `domain_knowledge.json` 继续作为零 AST 快速裁剪入口。
   - `id.lua` / `*_id.lua` 默认全跳过继续保留。
   - 裁剪规则命中需具备可追踪原因字段。
5. 可观测性优先
   - 必须可查询：已裁剪、已送审、LLM 输出、最终结果。
   - 核心指标内建输出：裁剪率、送审率、LLM 解决率、端到端时延。

### 二、实施计划（严格执行顺序）

1. 收敛运行时架构
   - 移除运行主链路中的 legacy 语义分支与相关统计口径。
   - 清理 AST fallback 语义路径，只保留结构化提取失败即失败。
2. 重做候选生命周期可观测模型
   - 在 run DB 增加候选事件表（collect/prune/queue/llm/final）。
   - `run-status`、`run-export-json`、`docs/run-tuning.md` 同步新指标与 SQL。
3. 切换默认仲裁到 LLM
   - CLI 默认 backend 改为 LLM。
   - 报错信息与 doctor 指南补齐（无模型/无凭据时清晰失败）。
4. 规则裁剪与大文件策略对齐
   - 保留现有默认规则并补充“命中原因”记录。
   - 确认 skip 文件不进入扫描与宏缓存链路。
5. 测试与文档收口
   - 删除不再适配的重逻辑测试，补齐 AST-lite/LLM 主链路测试。
   - README 中英文与 `docs/run-tuning.md` 更新到最终口径。
   - 最终验收：全量测试通过 + 指标查询样例可跑通。

### 三、验收标准（全部满足才算完成）

1. `pytest` 全量通过。
2. `run-status` 可直接看到四个核心指标（裁剪率、送审率、LLM 解决率、端到端时延）。
3. SQL 查询可覆盖裁剪与送审全链路。
4. Tree-sitter 不可用时分析命令统一失败。

### 四、执行状态（2026-03-07）

1. [x] 已完成：默认 backend 切换为 LLM（`codex`），`heuristic` 仅保留调试/测试用途。
2. [x] 已完成：domain 裁剪候选纳入 `case_tasks`，可追踪 `analysis_mode=domain_pruned`。
3. [x] 已完成：`run-status`/`run-export-json` 输出裁剪率、送审率、LLM 解决率、端到端时延。
4. [x] 已完成：运行主路径 AST-lite 不再做语义证明裁决；AST 上下文构建失败直接报错，不走语义降级。
5. [x] 已完成：全量测试通过（`PYTHONPATH=src pytest -q` → `522 passed`）。

## 最新定稿（2026-03-07）

本节为当前生效的最终方案，优先级高于下文历史阶段记录。

### 一、架构定稿

1. Tree-sitter 保持硬依赖（不做无 AST 降级路径）。
2. AST 改为 AST-lite（零推断）：
   - 仅用于函数边界定位、候选表达式精确定位、上下文切片。
   - 不再承担安全/风险证明职责。
3. 候选与领域规则前置：
   - 候选收集保持轻量词法扫描。
   - `domain_knowledge.json` 负责快速裁剪（如 `_name_.*`、`_cmd_.*`、全大写宏）。
4. 评审主权交给 LLM：
   - 主路径为“候选 + 上下文证据 + 规则事实 + LLM 仲裁”。
   - AST 不再输出 `proof/risk_signal` 作为核心仲裁依据。
5. 运行可观测性优先：
   - 必须可查询全量候选（被裁剪/已送审/最终状态）。
   - 指标重点转为裁剪率、送审率、LLM 解决率、端到端时延。

### 二、预期目标

1. 复杂度下降：显著减少 AST 规则维护负担。
2. 性能提升：在 3000+ 行函数和超大 Lua 文件场景下保持响应稳定。
3. 体验优化：减少规则迭代噪音，提升首轮可用结果速度。
4. 职责清晰：
   - AST = 定位与取证
   - LLM = 语义仲裁
   - 规则 = 前置裁剪与领域约束

### 三、实施完成标准

1. 主运行路径默认 AST-lite，AST 语义证明不再主导裁决。
2. Tree-sitter 仍为强制前置依赖。
3. `domain_knowledge.json` 与大文件跳过策略可持续生效。
4. 文档和运行观测字段反映 AST-lite 策略。
5. 全量测试通过。

### 四、当前落地结果（2026-03-07）

1. 已完成 AST-lite 主路径切换：
   - `review_source/review_repository/review_repository_file` 默认 `analysis_profile=ast_lite`。
   - AST 仅用于函数内定位与 origin/context 切片；不再输出静态 `proof/risk_signal` 作为主裁决依据。
2. 已保留 legacy 兼容分支：
   - `analyze_candidate` 支持 `analysis_profile=legacy|ast_lite`，便于对照和回归。
3. 已完成运行可观测字段同步：
   - 运行状态与基准输出新增 `ast_lite_cases`。
   - CLI/JSON 输出已展示 AST-lite 计数。
4. 已更新文档：
   - `README.md`、`README.zh-CN.md`、`docs/run-tuning.md` 已同步 AST-lite 口径。
5. 已完成全量测试验证：
   - `PYTHONPATH=src pytest -q` 结果：`522 passed`。

## 执行专项（2026-03-07）：Backend 交互可视化与可重放审计

### 一、目标与边界

1. 用户可查看 backend 的真实交互过程：请求构建、命令执行、重试、解析、失败点与耗时。
2. 用户可查看可审计的判定依据，而不是不可控的原始 chain-of-thought。
3. 用户可按 `run_id + case_id` 回放一次裁决全链路，支持复盘与争议仲裁。
4. 非目标：不要求每个第三方 backend 提供内部思维文本；不在默认输出中暴露敏感信息。

### 二、推荐方案（执行基线）

1. Decision Trace Contract（结构化判定轨迹）
   - 为每次 case 裁决固化统一结构：`verdict`、`risk_path`、`safety_evidence`、`counterarguments_considered`、`missing_evidence`、`evidence_refs(file:line)`、`uncertainty_reason`。
   - 以结构化字段承载“思考摘要”，避免依赖 provider 私有 CoT 格式。
2. Replay Capsule（可重放胶囊）
   - 对每个 case 保存复盘最小闭包：`evidence_packet`、最终 prompt、backend 调用轨迹、解析后的裁决、最终 verdict。
   - 支持离线重放与调试，不依赖现场环境重现。
3. Span Telemetry（运行追踪）
   - 记录 backend 调用 span：开始/结束时间、attempt、超时、失败、fallback、缓存命中、耗时。
4. 分级可见性
   - `summary`：仅元数据与结构化摘要（默认）。
   - `debug`：额外保存 prompt 与结构化响应文本。
   - `forensic`：保存完整 stdout/stderr 与原始包络（需显式开启）。

### 三、数据模型改造（Run DB）

1. 新增表 `backend_call_events`
   - 主键：`event_id`
   - 关键字段：`run_id`、`case_id`、`attempt_no`、`stage`、`status`、`backend_name`、`backend_model`、`backend_executable`、`protocol`
   - 交互字段：`command_json`、`prompt_sha256`、`prompt_text`、`response_text`、`stderr_text`、`parsed_payload_json`
   - 诊断字段：`error_class`、`error_message`、`fallback_used`、`cache_hit`
   - 时间字段：`started_at`、`ended_at`、`elapsed_ms`、`created_at`
2. 新增表 `case_replay_capsules`
   - 主键：`(run_id, case_id)`
   - 字段：`trace_level`、`evidence_packet_json`、`prompt_text`、`adjudication_payload_json`、`final_verdict_json`、`created_at`
3. 大文本存储策略
   - 默认写入 DB；当文本超过阈值（建议 64KB）时落盘到 `.lua_nil_guard/traces/<run_id>/<case_id>/...`，DB 仅存路径 + hash。
4. 索引
   - `idx_backend_events_run_case(run_id, case_id, attempt_no, stage)`
   - `idx_backend_events_run_status(run_id, status)`

### 四、运行时埋点改造

1. 新增 `TraceRecorder` 抽象（建议放在 `service.py` 或新建 `trace.py`）
   - `on_call_started(...)`
   - `on_call_finished(...)`
   - `on_call_failed(...)`
   - `on_case_captured(...)`
2. 在 `CliAgentBackend`（`agent_backend.py`）内接入埋点
   - 命令构建前记录 `stage=build_command`
   - 子进程执行前后记录 `stage=execute`
   - 响应解析前后记录 `stage=parse_response`
   - fallback 路径记录 `stage=fallback`
3. 在 `_run_review_from_assessments`（`service.py`）完成 case 后写入 replay capsule
   - 绑定 `run_id/case_id`
   - 关联 `adjudication_records` 与 `case_tasks` 形成完整链路

### 五、CLI 与用户呈现

1. 新增运行参数
   - `--trace-level summary|debug|forensic`（默认 `summary`）
2. 新增查询命令
   - `run-trace [--run-db PATH] <repository> [run_id]`
   - `run-trace-json [--run-db PATH] <repository> [run_id] [output]`
   - `case-replay [--run-db PATH] <repository> <run_id> <case_id>`
   - `case-replay-json [--run-db PATH] <repository> <run_id> <case_id> [output]`
3. 呈现规范
   - 文本视图按时间线展示：候选 -> LLM 调用 attempt -> 解析 -> 校验 -> 最终 verdict。
   - JSON 视图用于二次分析和可视化平台接入。

### 六、安全与合规约束

1. 新增 `config/trace_policy.json`
   - `default_trace_level`
   - `max_inline_payload_bytes`
   - `redact_patterns`（token、cookie、authorization、api key）
2. 默认开启脱敏
   - 即使 `debug/forensic`，也先做字符串脱敏再持久化。
3. 风险操作门槛
   - `forensic` 模式要求显式参数开启，避免误采集敏感信息。

### 七、分阶段执行计划

1. P0（可观测最小闭环）
   - 交付：`backend_call_events` 表、`run-trace`/`run-trace-json`、summary 级埋点
   - 验收：每个 case 至少可见 1 条 backend 调用记录，失败有 stage 和错误信息
2. P1（可重放闭环）
   - 交付：`case_replay_capsules`、`case-replay`/`case-replay-json`、debug 级 prompt/response 保存
   - 验收：可对任意 case 复盘“输入证据 -> backend 输出 -> 最终 verdict”
3. P2（审计与运维增强）
   - 交付：forensic 级原始包络、落盘分流、保留策略与清理命令
   - 验收：超大输出场景下 DB 不膨胀、查询性能稳定、敏感字段可控

### 八、测试计划

1. `tests/test_service.py`
   - 覆盖 run 期间事件写入、case 胶囊写入、失败路径写入
2. `tests/test_cli.py`
   - 覆盖 `run-trace*` / `case-replay*` 命令输出与错误分支
3. `tests/test_agent_backend.py` / `tests/test_cli_agent_backend.py`
   - 覆盖 attempt 重试、timeout、fallback、cache 命中事件
4. 回归
   - 全量 `pytest` 必须通过
   - 不得破坏既有 `run-status` / `run-export-json` 兼容输出

### 九、完成验收标准（专项）

1. 用户可按 `run_id + case_id` 查询完整 backend 交互时间线。
2. 用户可看到结构化“判定依据摘要”（证据链），并能定位到 `file:line`。
3. `summary/debug/forensic` 三个等级行为符合配置预期，默认安全。
4. 失败案例可明确定位到 `build_command/execute/parse/fallback` 具体阶段。
5. 文档与命令帮助更新完成，首次使用者可独立复盘一次 case。

### 十、专项验收结果（2026-03-07）

1. [x] `run-trace` / `run-trace-json` 已可按 `run_id + case_id` 查询 backend 全流程时间线。
2. [x] `case-replay` / `case-replay-json` 已可回放 case，并输出标准化 `decision_trace` 证据摘要。
3. [x] `summary/debug/forensic` 分级行为已生效，且 `forensic` 强制显式参数开启。
4. [x] 失败阶段可定位到 `build_command/execute/parse_response/fallback`。
5. [x] `trace_policy.json`、CLI usage、README 中英文、`docs/run-tuning.md` 已同步。
6. [x] 测试覆盖已补齐：`tests/test_cli.py`、`tests/test_run_jobs.py`、`tests/test_cli_agent_backend.py`、`tests/test_config_loader.py`。

## 0. 项目基线

LuaNilGuard 已完成 v3 主路径切换：当前运行系统为 `single_pass` 单次结构化判定，legacy 多模式路径已移除。

本计划保留为 V3 演进记录，聚焦后续能力扩展与稳定性增强。

设计文档参考：
- `internal/architecture-v3.md`：目标系统架构
- `internal/business-design-v3.md`：业务设计
- `internal/expected-design-v3.md`：详细技术预期
- `internal/test-design-v3.md`：测试设计指导

---

## Phase A：单次结构化判定 + 离线统计校准

> 最快见效，不改数据模型，token 成本立降。

### A-1. 合并裁决 Prompt

**目标**：将 Prosecutor / Defender / Judge 三段 prompt 合并为一个结构化判定 prompt。

**涉及文件**：
- `src/lua_nil_guard/prompting.py` — 当前三角色 prompt 构建逻辑
- `src/lua_nil_guard/adjudication.py` — 当前 `adjudicate_packet()` 入口
- `src/lua_nil_guard/models.py` — `AdjudicationRecord` / `RoleOpinion` 数据模型
- `skills/lua-nil-adjudicator/SKILL.md` — skill 行为规则
- `src/lua_nil_guard/lua_nil_adjudicator.SKILL.md` — skill 副本

**执行步骤**：

1. 在 `prompting.py` 中新增 `build_single_pass_prompt(packet, sink_rule)` 函数：
   - 合并 prosecutor / defender / judge 三段 prompt 为一个
   - 保留证据要求（target / context / static reasoning / summaries / knowledge facts）
   - 保留不变原则（Unknown is not risk / Absence of proof is not proof of bug）
   - 去掉角色扮演，改为"同时从攻防两面分析"
   - 要求严格 JSON schema 输出
2. 在 `models.py` 中新增 `SinglePassJudgment` 数据类：
   ```python
   @dataclass(frozen=True, slots=True)
   class SinglePassJudgment:
       verdict: Verdict
       raw_response: str
       backend_metadata: dict
   ```
3. 在 `adjudication.py` 中新增 `adjudicate_single_pass(packet, sink_rule)` 函数：
   - 调用 `build_single_pass_prompt()` 构建 prompt
   - 解析 LLM 响应为 `SinglePassJudgment`
   - 与现有 `adjudicate_packet()` 并存
4. 更新两份 SKILL.md：去掉 Prosecutor / Defender / Judge 角色描述，改为单次判定语义

**测试**：
- 新增 `tests/test_single_pass_adjudication.py`
- 对 benchmark labeled cases 运行 single-pass 并与 multi-agent 结果对比
- 所有现有测试不破坏

### A-2. 裁决模式切换机制

**目标**：统一裁决模式为 `single_pass`，保留显式配置入口但不再支持旧模式。

**涉及文件**：
- `src/lua_nil_guard/cli.py` — CLI 入口，新增 `--adjudication-mode` 参数
- `src/lua_nil_guard/service.py` — 服务层，读取 mode 并路由到对应裁决函数
- `src/lua_nil_guard/config_loader.py` — 加载 `adjudication_policy.json`
- `src/lua_nil_guard/pipeline.py` — pipeline 中的裁决调用点

**执行步骤**：

1. 在 `config_loader.py` 中新增 `load_adjudication_policy()` 函数：
   - 加载 `config/adjudication_policy.json`
   - 默认值：`{"adjudication_mode": "single_pass"}`
   - 仅支持 `single_pass`
2. 在 `cli.py` 中为 `report` / `report-file` / `run-start` 等命令新增 `--adjudication-mode` 可选参数
3. 在 `service.py` / `pipeline.py` 中根据 mode 路由：
   - `single_pass` → `adjudicate_single_pass()`（唯一路径）
4. `init-config` 命令在目标仓库写入默认 `adjudication_policy.json`

**测试**：
- 新增 `tests/test_adjudication_mode_routing.py`
- 验证旧模式会被拒绝
- 验证 CLI flag 覆盖配置文件

### A-3. 校准数据收集

**目标**：在裁决记录中收集校准所需的字段。

**涉及文件**：
- `src/lua_nil_guard/service.py` — 持久化 run 数据库操作
- `src/lua_nil_guard/models.py` — 如需扩展模型

**执行步骤**：

1. 在 run SQLite schema 中扩展 `adjudication_records` 表（如已有），或创建新表存储：
   - `predicted_status` / `predicted_confidence`：LLM 原始输出
   - `actual_outcome`：后续人工确认或 benchmark 标注的真实结果（初始为 NULL）
   - `calibration_applied`：是否已应用校准（0/1）
   - `calibrated_confidence`：校准后的置信度
2. 在裁决流程完成后，写入 `predicted_status` 和 `predicted_confidence`
3. `actual_outcome` 字段留空，待人工确认或 benchmark 比对填充

**测试**：
- 验证新字段正确写入和读取
- 验证不影响现有 run 数据库

### A-4. 校准引擎

**目标**：实现离线统计校准层。

**涉及文件**：
- 新增 `src/lua_nil_guard/calibration.py`
- `src/lua_nil_guard/verification.py` — 在 verify 阶段应用校准修正
- `src/lua_nil_guard/cli.py` — 新增 `calibration-status` 命令

**执行步骤**：

1. 新增 `calibration.py` 模块：
   - `calibration_buckets` SQLite 表：`(sink_type, unknown_reason, predicted_confidence)` → `(sample_count, correct_count, actual_precision)`
   - `recalibrate(db)` 函数：从 `adjudication_records` 重新计算各桶精度
   - `lookup_calibration(sink_type, unknown_reason, predicted_confidence)` 函数：查询校准修正
   - 冷启动保护：样本 < 30 时返回原始值不修正
2. 在 `verification.py` 的 `verify_verdict()` 中，如果校准可用，修正 LLM 输出的 confidence
3. 在 `cli.py` 中新增 `calibration-status` 命令：
   - 输出各桶的样本数、精度、修正量
   - 标识哪些桶仍在冷启动阶段

**测试**：
- 新增 `tests/test_calibration.py`
- 验证冷启动保护行为
- 验证校准修正逻辑
- 验证 `calibration-status` 命令输出

### A-5. A/B 精度对比验证

**目标**：确认 v3 单次判定在现有用例集上保持稳定性，并作为唯一实现路径。

**执行步骤**：

1. 使用现有 `benchmark` 命令，在统一 `single_pass` 模式下跑 labeled cases
2. 跟踪 `exact_matches` / `false_positive_risks` / `missed_risks` 三个指标
3. 以回归指标守护后续优化，不再引入多模式分流

**Phase A 完成标准**：
- [x] `--adjudication-mode single-pass` 可用
- [x] `calibration-status` 命令可用
- [x] 单模式稳定性验证通过（single_pass 路径）
- [x] 所有现有测试通过 + 新增测试通过
- [x] `single_pass` 已设为默认且唯一 adjudication_mode

---

## Phase B：依赖驱动的增量分析图

> 数据模型扩展，越早做越便宜。依赖 Phase A 完成（单次判定稳定后再扩展数据模型）。

### B-1. 文件指纹基础设施

**目标**：为每个分析过的文件记录指纹，支持变更检测。

**涉及文件**：
- `src/lua_nil_guard/repository.py` — 文件发现，新增指纹计算
- `src/lua_nil_guard/service.py` — run 流程中写入指纹
- `src/lua_nil_guard/models.py` — `CandidateCase` 新增 `file_fingerprint` 字段

**执行步骤**：

1. 在 `repository.py` 中新增 `compute_file_fingerprint(path) -> str`：
   - 计算文件内容 SHA-256 hash
   - 返回 hex digest
2. 新增 SQLite 表 `file_fingerprints`：
   ```sql
   CREATE TABLE file_fingerprints (
       file_path TEXT PRIMARY KEY,
       content_hash TEXT NOT NULL,
       mtime_ns INTEGER NOT NULL,
       last_analyzed_run_id INTEGER
   );
   ```
3. 在 `CandidateCase` 中新增 `file_fingerprint: str = ""` 字段
4. 在 Collector 产出 candidate 时计算并写入指纹
5. 在 run 流程的 INIT 阶段写入所有文件的指纹

**测试**：
- 验证指纹计算正确性
- 验证文件变更后指纹变化
- 验证 `file_fingerprints` 表读写

### B-2. 依赖追踪表

**目标**：记录分析产物之间的依赖关系。

**涉及文件**：
- `src/lua_nil_guard/service.py` — 依赖关系写入
- `src/lua_nil_guard/static_analysis.py` — 静态分析过程中收集依赖
- `src/lua_nil_guard/collector.py` — 候选收集过程中记录文件来源

**执行步骤**：

1. 新增 SQLite 表 `fact_dependencies`：
   ```sql
   CREATE TABLE fact_dependencies (
       fact_id TEXT NOT NULL,
       fact_type TEXT NOT NULL,
       depends_on_file TEXT NOT NULL,
       depends_on_function TEXT,
       run_id INTEGER NOT NULL,
       PRIMARY KEY (fact_id, depends_on_file)
   );
   ```
2. 在 Collector 中：每个 candidate 依赖其来源文件 → 写入 `fact_dependencies`
3. 在 Static Analysis 中：每个 `StaticResult` 依赖其使用的 `FunctionSummary` / `MacroFact` 来源文件 → 写入 `fact_dependencies`
4. 在 Adjudication 中：每个 verdict 依赖其 `EvidencePacket` 引用的文件 → 写入 `fact_dependencies`

**测试**：
- 验证依赖关系正确写入
- 验证跨文件 summary 引用被追踪

### B-3. 增量失效传播引擎

**目标**：给定变更文件列表，计算需要重算的 case 子图。

**涉及文件**：
- 新增 `src/lua_nil_guard/incremental.py`

**执行步骤**：

1. 新增 `incremental.py` 模块：
   ```python
   def compute_invalidated_facts(
       db_connection,
       changed_files: set[str],
   ) -> set[str]:
       """BFS 沿依赖边计算所有需要失效的 fact_id。"""
   ```
2. 实现 BFS 失效传播：
   - 查询 `fact_dependencies` 中所有 `depends_on_file in changed_files` 的 fact_id
   - 对每个 fact_id，查询依赖它的上层 fact
   - 迭代直到无新增
3. 新增 `should_fallback_to_full(db_connection, changed_files, total_files)` 函数：
   - 无历史 run → True
   - `file_fingerprints` 为空 → True
   - changed_files > 30% total → True
   - 依赖图完整性检查失败 → True

**测试**：
- 新增 `tests/test_incremental.py`
- 构造依赖图，验证失效传播覆盖正确
- 验证全量回退条件

### B-4. run-incremental 命令

**目标**：实现 PR 级增量分析入口。

**涉及文件**：
- `src/lua_nil_guard/cli.py` — 新增命令
- `src/lua_nil_guard/service.py` — 增量 run 逻辑
- `src/lua_nil_guard/pipeline.py` — 增量 pipeline

**执行步骤**：

1. 在 `cli.py` 中新增 `run-incremental` 命令：
   - 必填参数：`--changed-files`（逗号分隔文件列表）
   - 必填参数：目标仓库路径
   - 可选：`--base-run-id`（默认使用最近全量 run）
2. 在 `service.py` 中新增增量 run 逻辑：
   - 加载 base run 的 `file_fingerprints` 和 `fact_dependencies`
   - 调用 `compute_invalidated_facts()` 获取失效子图
   - 如果 `should_fallback_to_full()` 返回 True → 降级为全量 run 并提示
   - 只对失效 case 执行 `STATIC → QUEUE → LLM → VERIFY → FINALIZE`
   - 未失效 case 复用上一轮 verdict
   - 合并输出完整报告
3. 增量 run 记录为新的 run_id，标注 `run_type = 'incremental'`

**测试**：
- 新增 `tests/test_run_incremental.py`
- 构造小型多文件仓库 fixture
- 验证改 1 个文件只重算受影响 case
- 验证增量结果与全量结果一致
- 验证全量回退条件触发

### B-5. 增量一致性验证

**目标**：证明增量结果与全量结果一致性 > 99%。

**执行步骤**：

1. 对测试仓库运行全量 run → 记录所有 verdict
2. 修改 1~3 个文件
3. 运行 `run-incremental` → 记录所有 verdict
4. 重新全量 run → 记录所有 verdict
5. 对比步骤 3 和步骤 4 的 verdict，统计一致率

**Phase B 完成标准**：
- [x] `run-incremental` 命令可用
- [ ] 改动 1 个文件场景分析时间 < 全量 10%（需真实仓库验证）
- [ ] 增量与全量 verdict 一致性 > 99%（需真实仓库验证）
- [x] 全量回退条件正确触发
- [x] 所有现有测试通过 + 新增测试通过
- [x] 文件指纹 + 依赖追踪 schema 已实现
- [x] BFS 失效传播引擎已实现并测试

---

## Phase C：渐进式类型标注引导

> 最大的范式转变，需要 Phase A + B 稳定后推进。

### C-1. 标注语法定义

**目标**：定义基于 Lua 注释的 nil 标注语法。

**执行步骤**：

1. 确定标注前缀：`--- @nil_guard`（兼容 LuaLS / EmmyLua 注释风格）
2. 定义标注类型：
   - `--- @nil_guard: returns_non_nil` — 函数总是返回非 nil
   - `--- @nil_guard: ensures_non_nil_arg N` — 函数保证第 N 个参数非 nil（assert / error）
   - `--- @nil_guard param NAME: non_nil | may_nil` — 参数 nil 性声明
   - `--- @nil_guard return SLOT: non_nil | may_nil` — 返回值 nil 性声明
   - `--- @nil_guard returns_non_nil when argN is non_nil` — 条件性返回声明
3. 编写标注语法参考文档 `docs/annotations.md`

### C-2. 标注解析器

**目标**：从 Lua 源码中解析 nil_guard 标注。

**涉及文件**：
- 新增 `src/lua_nil_guard/annotations.py`
- `src/lua_nil_guard/models.py` — 新增 `AnnotationFact` / `AnnotationVerification`

**执行步骤**：

1. 在 `models.py` 中新增：
   ```python
   @dataclass(frozen=True, slots=True)
   class AnnotationFact:
       function_id: str
       file: str
       line: int
       annotation_type: str
       param_name: str | None
       param_index: int | None
       return_slot: int | None
       nullability: str
       condition: str | None
       raw_text: str
   ```
2. 新增 `annotations.py` 模块：
   - `parse_annotations(source: str, file_path: str) -> tuple[AnnotationFact, ...]`
   - 基于正则解析 `--- @nil_guard` 行
   - 关联到最近的下方 `function` 定义
   - 解析参数名到参数索引的映射（需要 AST 辅助或简单行扫描）
3. 兼容读取 LuaLS `@return` / EmmyLua `@type` 标注（作为弱信号，不作为强证据）

**测试**：
- 新增 `tests/test_annotations.py`
- 覆盖各种标注语法
- 覆盖异常格式的鲁棒性

### C-3. 标注-函数体一致性验证器

**目标**：验证标注声明与函数实现是否一致。

**涉及文件**：
- `src/lua_nil_guard/annotations.py` — 新增验证逻辑
- `src/lua_nil_guard/static_analysis.py` — 复用现有静态分析能力

**执行步骤**：

1. 在 `models.py` 中新增：
   ```python
   @dataclass(frozen=True, slots=True)
   class AnnotationVerification:
       annotation: AnnotationFact
       consistent: bool
       evidence: tuple[str, ...]
       conflicts: tuple[str, ...]
       confidence: str
   ```
2. 在 `annotations.py` 中实现验证函数：
   - `returns_non_nil`：检查所有 return 路径是否确实非 nil
   - `ensures_non_nil_arg N`：检查函数是否对第 N 个参数做了 assert / error / guard
   - `param X: may_nil`：检查函数体是否在使用 X 前有守卫
3. 不一致时输出警告，不自动信任标注（precision-first）

**测试**：
- 一致标注 → 验证通过
- 不一致标注 → 验证失败 + 冲突证据
- 边界情况：条件 return、多 return 路径

### C-4. 标注接入跨函数推理链路

**目标**：让已标注函数的标注作为跨函数推理的 ground truth。

**涉及文件**：
- `src/lua_nil_guard/static_analysis.py` — 跨函数证据查询
- `src/lua_nil_guard/summaries.py` — 函数摘要生成

**执行步骤**：

1. `AnnotationFact` → `StaticProof`（kind = `annotation_proof`）转换器
2. 修改跨函数调用分析的证据查询优先级：
   ```
   标注 > function_contracts > bounded recognizer > LLM
   ```
3. 已标注函数不再需要 `function_contracts.json` 对应条目（但 contract 仍作为兜底）
4. 在 `EvidencePacket` 中包含标注来源信息

**测试**：
- 跨文件调用已标注函数 → 直接使用标注证据
- 标注覆盖 contract → 标注优先
- 无标注无 contract → 回退到 bounded recognizer

### C-5. annotation-coverage 和 annotation-suggest 命令

**目标**：提供标注覆盖率报告和自动标注建议。

**涉及文件**：
- `src/lua_nil_guard/cli.py` — 新增两个命令
- `src/lua_nil_guard/service.py` — 覆盖率计算和建议生成逻辑
- `src/lua_nil_guard/reporting.py` — 报告格式化

**执行步骤**：

1. `annotation-coverage` 命令：
   - 扫描仓库所有 Lua 文件中的标注
   - 统计总函数数 / 已标注函数数
   - 按模块（目录）分组输出覆盖率
   - 输出"建议优先标注"列表：按跨文件引用次数排序
2. `annotation-suggest` 命令：
   - 对指定文件运行静态分析
   - 基于已有 `StaticProof` 生成标注建议
   - 高置信度建议：所有 return 路径已证明非 nil → 建议 `returns_non_nil`
   - 中置信度建议：存在 return nil 路径 → 建议 `return 1: may_nil`

**测试**：
- 验证覆盖率统计正确性
- 验证建议生成合理性

**Phase C 完成标准**：
- [x] 标注语法文档就绪 (`docs/annotations.md`)
- [x] 标注解析器正确解析所有标注类型 (21 测试通过)
- [x] 一致性验证器工作正确
- [x] 跨函数推理使用标注证据 (`annotation_to_proof()` 已实现)
- [x] `annotation-coverage` 命令可用
- [x] `annotation-suggest` 命令可用
- [ ] 已标注函数跨文件推理精度 > bounded recognizer（需真实仓库验证）
- [x] 未标注函数无新增 false positive
- [x] 所有现有测试通过 + 新增测试通过

---

## 跨阶段：收尾与清理

### X-1. 移除多 Agent 旧路径（Phase A 验证后）

当 A/B 测试确认 single-pass 精度 >= multi-agent 后：

1. 移除 `adjudicate_packet()` 中的 prosecutor / defender / judge 路径
2. 移除 `RoleOpinion` 模型
3. 将 `AdjudicationRecord` 简化为只包含 `SinglePassJudgment`
4. 移除 `adjudication_mode` 开关，`single_pass` 成为唯一路径
5. 更新 `docs/sink-rules.md` 中相关描述（如有）
6. 更新 README.md / README.zh-CN.md 中的 backend 说明

### X-2. 更新用户文档

在所有 Phase 完成后：

1. 更新 README.md / README.zh-CN.md：
   - 新增 `run-incremental` 使用说明
   - 新增标注系统使用说明
   - 更新 backend 策略说明
   - 移除多 Agent 相关描述
2. 新增 `docs/annotations.md`：标注语法参考
3. 更新 CONTRIBUTING.md：新增标注和增量分析的开发指引

### X-3. 更新 SKILL.md

在 Phase A 完成后：

1. 移除 Prosecutor / Defender / Judge 角色描述
2. 改为"单次结构化判定"语义
3. 保留核心不变原则
4. 同步更新两份副本

---

## 风险控制

| 风险 | 影响 | 控制措施 |
|------|------|---------|
| 单次判定精度 < 多 Agent | Phase A 失败 | A/B 对比先行；校准数据充足前不移除旧路径；特定 sink 类型可保留多轮 |
| 依赖追踪引入脏数据 | 增量结果不一致 | 增量必须与全量可对照；依赖图不完整时自动降级；保守失效优于遗漏 |
| 标注推广阻力 | Phase C 用户采纳低 | 标注可选，不标注保守处理；先支持 LuaLS/EmmyLua 已有标注；`annotation-suggest` 降低人工成本 |
| 数据模型迁移破坏现有数据 | run 数据库损坏 | 所有变更均为增量 ALTER/CREATE，不修改已有表结构 |

## 退出标准

整体重构完成的条件：

1. ~~多 Agent 对抗模型已被单次判定 + 校准替换~~ — **已完成**：`single_pass` 为默认模式，A/B 验证 verdict 一致。多 Agent 路径保留为兼容选项。
2. ~~增量分析路径可用于 PR 级场景~~ — **已完成**：`run-incremental` CLI 可用，BFS 失效传播引擎 + 全量回退机制已实现。待真实仓库验证性能和一致性。
3. ~~标注系统 MVP 可用~~ — **已完成**：标注解析器 + 验证器 + `annotation-coverage` + `annotation-suggest` CLI 均可用。
4. ~~全量测试通过~~ — **已完成**：500+ 测试通过（含 91+ 新增）。
5. ~~文档、CLI、测试行为一致~~ — **已完成**：README 中英文已更新，`docs/annotations.md` 已创建，CLI help 包含所有新命令。
