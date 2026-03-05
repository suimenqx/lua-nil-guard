# Plan 5（执行版）：V2.1 架构重构与收口

## 1. 执行目标

把 LuaNilGuard 从“单次命令工具”升级为“可恢复的全仓审查系统”，并完成从旧流程到 V2.1 的主路径切换。

本计划默认允许：

1. 大刀阔斧改造模块边界；
2. 删除历史废弃方案代码；
3. 同步删除、重写不适配的新旧测试。

基线架构文档：
[internal/architecture-v2-llm-agent-first.md](/storage/emulated/0/xin/code/github/codex/lua-nil-review-agent/internal/architecture-v2-llm-agent-first.md)

## 2. DoD（最终完成标准）

Plan 5 只在以下条件全部满足时视为完成：

1. 默认流程为 uncertain-first（仅 `unknown_static` 进 Agent）。
2. 持久化作业链路稳定（start/resume/status/report/export）。
3. 候选来源可追踪（`ast_exact/lexical_fallback`）且可统计。
4. 高置信 verdict 由结构化证据支持，冲突场景保守处理。
5. 全量测试通过，且测试语义反映新契约而非旧偶然行为。

## 3. 阶段拆解

## P5-0：冻结基线与清理原则

目标：防止“边改边漂移”。

任务：

1. 冻结 V2.1 架构边界与数据契约。
2. 明确可删列表（历史 fallback、旧路径桥接、冗余断言）。
3. 在计划内记录每次破坏性变更的测试迁移策略。

退出条件：

1. 架构和计划文档可独立指导执行。

## P5-1：作业运行时重构

目标：具备可恢复的全仓作业主干。

任务：

1. 阶段机：`INIT -> STATIC -> QUEUE -> LLM -> VERIFY -> FINALIZE`。
2. SQLite 持久化核心表：
   `runs / file_tasks / case_tasks / adjudication_records / verdict_snapshots`。
3. 断点恢复：
   - 已完成 case 不重复处理；
   - 阶段状态可观测。

退出条件：

1. 中断后 `run-resume` 可稳定继续。
2. `run-status` 可准确显示阶段和进度。

## P5-2：候选层双通道与来源追踪

目标：精准召回 + 有界兜底。

任务：

1. 主通道 `ast_exact`。
2. 兜底通道 `lexical_fallback`（仅 AST 不可用/解析失败时启用）。
3. `CandidateCase.candidate_source` 全链路透传到 `EvidencePacket`。
4. 去重键稳定化（file/line/column/sink/arg）。

退出条件：

1. 候选结果稳定、可复现、可解释来源。
2. fallback 占比可在运行统计中看到。

## P5-3：Static Evidence Kernel 收敛

目标：保留高 ROI 的静态能力，淘汰低收益复杂逻辑。

任务：

1. 强化 proof/risk 结构化产出与 provenance。
2. 强制 `unknown_reason`，禁止静默失败。
3. 对关键场景做收敛：
   - string/concat/pairs/ipairs/#/compare/arithmetic。
4. 保持 LuaJIT + `module(..., package.seeall)` 生态可用。

退出条件：

1. 静态层输出可用于直接审计与统计。
2. 关键回归用例稳定。

## P5-4：uncertain-first 裁决主路径

目标：让 LLM 只做“静态无法定论”的高价值工作。

任务：

1. 默认仅 `unknown_static` 进入 Agent。
2. `safe_static` 不再消耗 Agent，走 verify 合成。
3. 对必须验证 Agent 上下文构建的测试，显式开启非默认开关。

退出条件：

1. LLM 调用量显著下降。
2. 关键安全场景不因绕过 Agent 退化。

## P5-5：上下文预算与二跳策略

目标：避免 prompt 膨胀，提升稳定性。

任务：

1. 首轮一跳上下文。
2. 仅在 uncertain 且 backend 支持重试时扩二跳。
3. 预算参数显式化（depth/lines/summaries）。

退出条件：

1. 单 case prompt 体积可控。
2. 二跳触发有据可查。

## P5-6：Verdict 合成与验证闸门

目标：避免“弱证据高置信”。

任务：

1. 高置信 `safe/risky` 门槛统一化。
2. 分离 summary：
   - static proof preview；
   - static risk preview；
   - adjudication summary。
3. 冲突结论保守降级。

退出条件：

1. 高置信 verdict 全部可追溯。
2. 冲突场景输出稳定一致。

## P5-7：CLI 与运维可观测性

目标：形成可持续运行的操作界面。

任务：

1. 作业命令族：
   `run-start / run-resume / run-status / run-report / run-export-json`。
2. 状态指标输出：
   - candidate source 分布；
   - static safe/unknown；
   - llm enqueue/process；
   - failed cases。
3. 保留 `report/report-json` 兼容入口。

退出条件：

1. 运维不需要人工反复全量重跑。
2. 故障可定位，状态可解释。

## P5-8：测试体系迁移（强制执行）

目标：测试语义与新架构一致。

任务：

1. 删除：
   - 依赖旧路径偶然行为的断言；
   - 与 uncertain-first 默认冲突的历史断言。
2. 重写：
   - service/pipeline/cli 的阶段化行为测试；
   - run resume 幂等测试；
   - candidate_source 追踪测试。
3. 新增：
   - 持久化 run store 回放测试；
   - 宏/模块/跨文件上下文回归；
   - 二跳扩展触发策略测试。

退出条件：

1. 全量测试通过。
2. 测试命名与断言体现 V2.1 契约。

## 4. 执行顺序（严格）

1. P5-1 -> P5-2 -> P5-4（先把主路径跑通）。
2. P5-3 -> P5-5 -> P5-6（再收敛质量与稳定性）。
3. P5-7 -> P5-8（最后收口可观测性与测试体系）。

## 5. 测试迁移策略（明确授权）

1. 允许直接删除历史废弃方案测试，不做兼容保留。
2. 新测试优先验证“行为契约”，不验证内部实现偶然细节。
3. 对不再默认触发的 Agent 路径，测试需显式打开对应开关。
4. 每个破坏性改动必须伴随测试迁移提交，不允许“代码先改、测试后补”。

## 6. 风险与控制

### 风险 A：重构期间功能漂移

控制：

1. 阶段出口门禁；
2. 每阶段至少一组端到端回归；
3. 变更日志记录“行为变化”而非仅“文件变化”。

### 风险 B：误把静态保守当风险

控制：

1. unknown 与 risky 严格区分；
2. uncertain-first 下 safe_static 必须可校验落地。

### 风险 C：大仓时延不可控

控制：

1. parse-once；
2. 上下文预算；
3. 持久化 resume 避免重复计算。

## 7. 最终退出门

仅当以下条件同时成立才退出 Plan 5：

1. V2.1 作业路径成为默认路径。
2. 旧路径依赖已移除或封装为明确兼容层。
3. 文档、CLI、测试、运行指标一致。
4. 发布前全量测试通过。

## 8. 执行完成状态（2026-03-05）

### Phase 状态总览

1. P5-0：completed（基线与清理原则冻结，执行边界明确）。
2. P5-1：completed（持久化作业链路与阶段机稳定，resume 幂等通过）。
3. P5-2：completed（候选双通道和 `candidate_source` 全链路透传完成）。
4. P5-3：completed（结构化 static proof/risk 与 `unknown_reason` 收敛到主路径）。
5. P5-4：completed（uncertain-first 为默认，`safe_static` 走 verify）。
6. P5-5：completed（上下文预算参数统一，二跳触发受控且可追踪）。
7. P5-6：completed（高置信门槛收紧，冲突结论保守降级）。
8. P5-7：completed（`run-status/run-report/run-export-json` 可观测性补齐）。
9. P5-8：completed（历史断言迁移，新契约测试补齐）。

### 验证结果

1. 全量测试：`447 passed`。
2. 关键场景回归（宏字典、跨文件、`module/require`）：`15 passed`。

### 输出契约结果

1. `run-status`/`run-report`：
   - 包含阶段指标（STATIC/QUEUE/LLM/VERIFY/FINALIZE）；
   - 包含 `unknown_reason` 分布；
   - 包含二跳与 verify 计数。
2. `run-export-json`：
   - 输出结构固定为 `{"run": {...}, "findings": [...]}`；
   - `run` 包含阶段指标和 `unknown_reason_distribution`。
