# Plan 5：架构 V2 重构计划（轻量 AST + LLM Agent）

## 1. 目标

将项目从“单次命令式审查”升级为“可恢复、可追溯、可持续完成全仓任务”的审查系统。

本计划明确授权：

1. 允许大刀阔斧重构；
2. 不以“最小改动”作为约束；
3. 允许同步删除、重写不再适配的新旧测试。

架构基线文档：
[internal/architecture-v2-llm-agent-first.md](/storage/emulated/0/xin/code/github/codex/lua-nil-review-agent/internal/architecture-v2-llm-agent-first.md)

## 2. 范围

### 2.1 计划内（In Scope）

1. 作业运行时与阶段状态机重构。
2. 候选层双通道（`ast_exact` + `lexical_fallback`）。
3. 轻量 AST 证据层收敛与性能治理。
4. uncertain-first 的 Agent 裁决流程。
5. 证据校验闸门与 Verdict 合成规则重构。
6. 测试体系迁移（删除/重写/新增）。

### 2.2 计划外（Out of Scope）

1. 全局完备调用图求解。
2. 无界过程间控制流分析。
3. 自动直接写入生产 contracts。
4. 运行时对外部超大目录做全量实时扫描。

## 3. 完成标准（DoD）

Plan 5 结束必须同时满足：

1. 全仓任务支持 checkpoint/resume。
2. 静态阶段与 Agent 阶段可独立观测和统计。
3. 候选来源、证据来源、判决来源可追溯。
4. 默认仅 `unknown_static` 进入 Agent。
5. 新测试体系全量通过并反映 V2 行为契约。

## 4. 分阶段执行

## Phase P5-1：作业运行时与持久化状态机

### 目标

建立可恢复的全仓作业模型，避免“中断即重跑”。

### 必做项

1. 引入作业阶段状态机：
   `INIT -> STATIC -> QUEUE -> LLM -> VERIFY -> FINALIZE`。
2. 引入 SQLite 持久化（至少）：
   - runs
   - file_tasks
   - case_tasks
   - adjudication_records
   - verdict_snapshots
3. 实现 resume 语义：
   - 阶段幂等
   - case 级断点恢复

### 验收

1. 人为中断后可恢复且不重复处理已完成 case。
2. 阶段状态可通过 CLI 查询。

## Phase P5-2：候选层重构（双通道）

### 目标

候选发现既要精准又要有兜底，不再单一路径。

### 必做项

1. 候选增加 `candidate_source`：
   - `ast_exact`
   - `lexical_fallback`
2. AST 作为主通道提取真实语法候选。
3. lexical 仅在 AST 不可用或单文件解析失败时兜底。
4. 统一去重键（位置 + sink + 参数位）。

### 验收

1. 候选输出稳定、可复现、可标注来源。
2. fallback 占比在报告中可见。

## Phase P5-3：轻量 AST 证据层收敛与提速

### 目标

保留高价值证明能力，去掉高成本低收益路径。

### 必做项

1. 固化高价值 proof：
   - guard/assert/defaulting/loop-index/reassign invalidation
2. 固化高价值 risk signal：
   - direct sink field path
   - unguarded origin
   - bounded wrapper/call nil-return
3. 所有不可判定场景必须输出结构化 `unknown_reason`。
4. 增加 AST 预算与降级策略（文件级/阶段级）。

### 验收

1. 无静默 fallback。
2. unknown reason 可统计。
3. 大文件场景运行时间受控。

## Phase P5-4：上下文解析与预算策略

### 目标

把上下文扩展从“启发式拼接”改成“预算可控的证据构建”。

### 必做项

1. 标准化预算：
   - 调用链深度预算
   - summary 数量预算
   - context 行数预算
2. 首轮只用一跳；仅 uncertain 重试时扩到二跳。
3. 外部依赖引入“索引查询接口”，运行时按需取证，不做全目录扫描。

### 验收

1. 首轮 packet 体积稳定。
2. 二跳重试触发条件明确且可统计。
3. 外部依赖缺证时默认 `uncertain_external`，不猜测升级风险。

## Phase P5-5：Agent 裁决契约收紧

### 目标

让 Agent 成为“证据裁决器”，而非“自由推断器”。

### 必做项

1. 默认 uncertain-first 路由。
2. 维持严格 JSON schema 输出与硬解析失败策略。
3. 强化证据字段约束（risk_path/safety_evidence/provenance）。
4. 缓存身份纳入：
   - backend
   - model
   - skill 版本/签名
   - prompt hash

### 验收

1. 无自由文本裁决路径。
2. 无证据或不合规输出自动降级 `uncertain`。

## Phase P5-6：Verdict 合成与验证重构

### 目标

提升结论可信度，避免“弱证据高置信”。

### 必做项

1. 高置信 `safe/risky` 必须满足结构化证据门槛。
2. 分离三类 summary：
   - static proof preview
   - static risk preview
   - adjudication summary
3. 增加静态与 Agent 冲突策略（冲突默认保守，不自动升级）。

### 验收

1. 每个高置信 verdict 可追溯解释。
2. 冲突场景输出稳定。

## Phase P5-7：测试体系迁移（删除/重写/新增）

### 目标

让测试反映新架构契约，而不是延续旧实现细节。

### 必做项

1. 删除：
   - 依赖旧流程偶然行为的测试
   - 与 V2 契约冲突的 legacy-only 断言
2. 重写：
   - pipeline/cli/service 的阶段化行为测试
   - uncertain-first 路由测试
   - resume 幂等测试
3. 新增：
   - 作业恢复回放测试
   - 候选来源标签测试
   - 证据校验降级测试
   - 大仓性能回归测试（合成数据）

### 验收

1. 全量测试通过。
2. 删除项在迁移说明中有记录。
3. benchmark 输出分阶段质量指标。

## Phase P5-8：CLI 与运维可观测性

### 目标

提供可执行、可监控、可恢复的作业入口。

### 必做项

1. 增加作业命令：
   - run start
   - run resume
   - run status
   - run report/export
2. 保留现有 report/scan 兼容入口（必要时作为 facade）。
3. 输出核心指标：
   - 候选数（按来源）
   - 静态 safe/unknown
   - Agent 队列与处理量
   - 缓存命中率
   - unknown reason 分布

### 验收

1. 无需人工循环调用即可跑完整仓任务。
2. 故障与降级原因可见、可定位。

## 5. 迁移与兼容规则

1. 允许重划内部模块边界。
2. 对外 CLI 尽量兼容，但不牺牲架构正确性。
3. 已废弃路径必须明确移除，不保留半激活状态。
4. 任何重大行为变化必须有文档和测试对应。

## 6. 风险与控制

### 风险 A：重构期不稳定

控制：

1. 分阶段门禁；
2. 阶段级 golden tests；
3. 作业回放一致性校验。

### 风险 B：Agent 过度裁决

控制：

1. uncertain-first；
2. schema 强约束；
3. 证据闸门控制高置信输出。

### 风险 C：性能回退

控制：

1. AST/上下文预算；
2. 缓存键纪律；
3. 分阶段时延指标与阈值报警。

## 7. 退出门（Exit Gate）

仅当下列条件全部满足，Plan 5 才可宣布完成：

1. V2 作业路径成为默认路径。
2. 旧路径依赖已清理或显式兼容封装。
3. 迁移后测试全量通过。
4. 文档、CLI、运维指标与 V2 一致。

