# LuaNilGuard V3 测试设计指导

## 0. 现有测试基线

历史版本 共 31 个测试文件，447 个测试用例，全部通过。

### 0.1 现有测试分层

| 层次 | 文件 | 关注点 |
|------|------|--------|
| **单元** | `test_adjudication.py` | heuristic 裁决逻辑：prosecutor/defender/judge 各角色行为 |
| | `test_verification.py` | verify gate：升级/降级/冲突处理 |
| | `test_prompting.py` | prompt 构建：证据包→prompt 文本转换 |
| | `test_collector.py` | candidate 收集：AST 主通道 + lexical 兜底 |
| | `test_static_analysis.py` | 静态分析：guard/defaulting/loop/wrapper/binary_operand 证明 |
| | `test_pipeline.py` | evidence packet 构建、should_report 报告门槛 |
| | `test_config_loader.py` | 配置加载：sink_rules/confidence_policy/contracts/preprocessor |
| | `test_preprocessor.py` | 宏字典解析 |
| | `test_summaries.py` | 函数摘要生成 |
| | `test_repository.py` | 文件发现、UTF-8 读取 |
| | `test_reporting.py` | 报告格式化 |
| | `test_knowledge.py` | 知识库 CRUD |
| | `test_baseline.py` | 基线抑制 |
| | `test_skill_runtime.py` | skill 加载与合同验证 |
| | `test_parser_backend.py` | Tree-sitter 解析后端 |
| | `test_agent_backend.py` | LLM backend 封装 |
| | `test_agent_protocols.py` | backend 协议 |
| | `test_agent_driver_manifest.py` | 自定义 backend manifest |
| **集成** | `test_review_flow.py` | review_source 端到端：collect → static → assessment |
| | `test_service.py` | 服务层端到端：bootstrap → review → report |
| | `test_run_jobs.py` | run 作业链路：start → status → resume → export |
| | `test_repository_review.py` | 仓库级审查回归 |
| | `test_evidence_preparation.py` | 证据组装流程 |
| | `test_knowledge_refresh.py` | 知识库刷新流程 |
| **语义回归** | `test_mvp_demo.py` | 基础演示场景 |
| | `test_mvp_semantic_suite.py` | 语义判定回归 |
| | `test_mvp_agent_semantic_suite.py` | agent 语义判定回归 |
| | `test_mvp_ast_stress_suite.py` | AST 极端场景 |
| **CLI** | `test_cli.py` | CLI 命令入口：help/scan/report/run-*/macro-*/benchmark 等 |
| | `test_cli_agent_backend.py` | CLI 与 LLM backend 交互 |
| | `test_prompt_export.py` | prompt 导出格式 |

### 0.2 现有测试约定

1. **无 fixture 目录**：Lua 代码作为 Python 字符串内联构造。
2. **tmp_path**：需要仓库目录结构的测试使用 pytest `tmp_path` 临时构建。
3. **deterministic backend**：LLM 相关测试通过自定义 `CountingBackend` / `StrictEvidenceBackend` 类模拟 LLM 响应，不依赖真实 LLM 调用。
4. **数据模型直接构造**：测试通过直接构造 `EvidencePacket` / `CandidateCase` / `SinkRule` 等 frozen dataclass 实例。
5. **断言风格**：使用 `assert` 语句，不使用 unittest 风格的 `self.assert*`。
6. **文件命名**：`test_{module_name}.py` 对应 `src/lua_nil_guard/{module_name}.py`。

---

## 1. V3 测试策略总则

### 1.1 不变原则

- **所有 447 个现有测试必须始终通过**。每个 Phase 的每个步骤都不允许破坏现有测试。
- **精度回归是硬门禁**：任何导致 `test_mvp_semantic_suite.py` 或 `test_mvp_agent_semantic_suite.py` 失败的变更必须立即修复。
- **新增模块必须有对应测试文件**。`calibration.py` → `test_calibration.py`，`incremental.py` → `test_incremental.py`，`annotations.py` → `test_annotations.py`。

### 1.2 测试金字塔目标

```
        /  语义回归  \          — 少量关键场景的端到端精度验证
       / 集成 + CLI   \        — 命令入口 + 跨模块流程
      /    单元测试     \       — 每个新函数/新模块的独立行为验证
     /  deterministic mock  \  — 不依赖真实 LLM，用 mock backend 控制确定性
```

### 1.3 测试命名规范

遵循现有项目风格：

```python
def test_{被测功能}_{场景描述}() -> None:
    """可选 docstring，复杂场景加一句解释。"""
```

示例：
- `test_single_pass_prompt_includes_canonical_principles()`
- `test_calibration_cold_start_skips_correction()`
- `test_incremental_invalidation_propagates_through_summary_dependency()`

---

## 2. Phase A 测试设计

### 2.1 test_single_pass_adjudication.py（A-1 对应）

新建文件。测试单次结构化裁决的 heuristic 路径。

**测试用例清单**：

```
T-A1-01  单次判定对有 guard 的 case 返回 safe
         输入: EvidencePacket 含 observed_guards=("if username then",)
         预期: verdict.status == "safe", verdict.confidence == "high"

T-A1-02  单次判定对无 guard 无安全证据的 case 返回 risky
         输入: EvidencePacket 含 observed_guards=(), 无 knowledge_facts
         预期: verdict.status == "risky", risk_path 非空

T-A1-03  单次判定对证据不足的 case 返回 uncertain
         输入: EvidencePacket 含部分模糊证据
         预期: verdict.status == "uncertain"

T-A1-04  单次判定产出 SinglePassJudgment 包含 raw_response 和 backend_metadata
         验证数据结构完整性

T-A1-05  单次判定对带 static_proofs 的 case 利用结构化安全证据
         输入: EvidencePacket 含 StaticProof(kind="direct_guard")
         预期: verdict.status == "safe", verification 引用 proof

T-A1-06  单次判定对带 static_risk_signals 的 case 利用结构化风险信号
         输入: EvidencePacket 含 StaticRiskSignal(kind="direct_sink_field_path")
         预期: 风险信号被纳入判定

T-A1-07  单次判定的 autofix_patch 附加行为与多 Agent 路径一致
         验证 attach_autofix_patch() 在单次判定路径上正常工作

T-A1-08  回归保护：对现有 test_adjudication.py 所有 case 的输入，
         用单次判定路径运行，verdict.status 与多 Agent judge.status 一致
```

**构造方式**：复用 `test_adjudication.py` 中 `EvidencePacket` + `SinkRule` 的构造模式。

### 2.2 test_single_pass_prompting.py（A-1 对应）

新建文件。测试单次判定 prompt 的构建。

```
T-A1-P01  prompt 包含 target 元数据（file/line/sink/expression）
T-A1-P02  prompt 包含 local_context
T-A1-P03  prompt 包含 static_reasoning 各字段
T-A1-P04  prompt 包含不变原则文本："Unknown is not risk" + "Absence of proof is not proof of bug"
T-A1-P05  prompt 不包含 "prosecutor" / "defender" / "judge" 角色词汇
T-A1-P06  prompt 包含 JSON schema 输出要求
T-A1-P07  prompt 包含 function_summaries 和 knowledge_facts
T-A1-P08  prompt 包含 related_function_contexts
T-A1-P09  prompt 包含 static_proofs 和 static_risk_signals 的格式化输出
T-A1-P10  空 knowledge_facts / 空 summaries 时 prompt 段落不出现或显示"无"
```

### 2.3 test_adjudication_mode_routing.py（A-2 对应）

新建文件。测试裁决模式路由。

```
T-A2-01  mode=legacy_mode 路由到 adjudicate_packet()
T-A2-02  mode=single_pass 路由到 adjudicate_single_pass()
T-A2-03  mode=legacy_split 按 case_id hash 分流，比例约 50/50
         构造 100 个不同 case_id，验证分流比例在 [35, 65] 区间
T-A2-04  legacy_split 相同 seed + 相同 case_id 始终路由到同一路径（确定性）
T-A2-05  CLI --adjudication-mode flag 覆盖配置文件值
T-A2-06  配置文件缺失时使用默认值（legacy_mode，兼容 历史版本）
T-A2-07  配置文件中 adjudication_mode 值非法时报错
```

### 2.4 test_adjudication_policy_config.py（A-2 对应）

新建文件，或并入 `test_config_loader.py`。

```
T-A2-C01  load_adjudication_policy() 正确加载有效 JSON
T-A2-C02  文件缺失时返回默认策略
T-A2-C03  JSON 格式错误时抛出 ConfigError
T-A2-C04  init-config 命令生成默认 adjudication_policy.json
          使用 tmp_path 构建目标仓库，运行 init-config，验证文件存在且内容有效
```

### 2.5 test_calibration.py（A-3 / A-4 对应）

新建文件。测试校准引擎。

```
T-A4-01  recalibrate() 从空 adjudication_records 计算 → calibration_buckets 为空
T-A4-02  recalibrate() 从含有标注 actual_outcome 的记录计算 → 桶统计正确
         构造 50 条记录：sink_type="string.match", unknown_reason="no_bounded_ast_proof",
         predicted_confidence="high", 其中 40 条 actual_outcome="correct"
         预期: actual_precision == 0.8

T-A4-03  lookup_calibration() 桶存在且样本充足 → 返回校准后 confidence
         样本 50, precision 0.6 → "high" 降级为 "medium"
T-A4-04  lookup_calibration() 桶存在但样本 < 30 → 冷启动保护，返回原始 confidence
T-A4-05  lookup_calibration() 桶不存在 → 返回原始 confidence
T-A4-06  校准应用后 verification.verify_verdict() 修正 confidence
         构造 verdict(confidence="high") + 校准桶(precision=0.5)
         预期: 最终 confidence 被降级

T-A4-07  校准不可用时 verify_verdict() 行为与 历史版本 完全一致
         回归保护：无校准数据时，所有现有 test_verification.py 用例结果不变

T-A4-08  calibration-status 命令输出包含桶统计和冷启动标识
T-A4-09  adjudication_records 新字段（predicted_status/predicted_confidence/actual_outcome/
         calibration_applied/calibrated_confidence）正确读写
T-A4-10  现有 run 数据库（无新字段）不因 schema 迁移而损坏
```

**SQLite mock 方式**：使用 `sqlite3.connect(":memory:")` 或 `tmp_path` 下的临时 DB 文件。

### 2.6 Phase A 回归测试

不新建文件，在 CI 中确保以下全部通过：

```
pytest tests/ -q
```

特别关注：
- `test_adjudication.py` — 多 Agent 路径未被破坏
- `test_verification.py` — verify gate 未被破坏
- `test_run_jobs.py` — run 作业链路未被破坏
- `test_mvp_semantic_suite.py` / `test_mvp_agent_semantic_suite.py` — 精度未退化

---

## 3. Phase B 测试设计

### 3.1 test_file_fingerprint.py（B-1 对应）

新建文件，或并入 `test_repository.py`。

```
T-B1-01  compute_file_fingerprint() 对同一文件返回相同 hash
T-B1-02  compute_file_fingerprint() 对不同内容文件返回不同 hash
T-B1-03  修改文件内容后 fingerprint 变化
T-B1-04  文件 mtime 变化但内容不变 → hash 不变（hash 基于内容非 mtime）
T-B1-05  file_fingerprints 表正确写入和读回
         使用 tmp_path 下 SQLite DB，写入 3 个文件指纹，读回验证
T-B1-06  CandidateCase 新增 file_fingerprint 字段不影响现有序列化
         构造 CandidateCase(file_fingerprint="abc123")，验证字段存在
         构造 CandidateCase()（不传 file_fingerprint），验证默认为 ""
```

### 3.2 test_fact_dependencies.py（B-2 对应）

新建文件。

```
T-B2-01  candidate 依赖写入：collector 产出的 candidate 在 fact_dependencies 中有记录
         fact_type="candidate", depends_on_file=candidate.file

T-B2-02  static_result 依赖写入：使用了跨文件 FunctionSummary 的 StaticResult
         在 fact_dependencies 中记录 depends_on_file=summary.file

T-B2-03  verdict 依赖写入：EvidencePacket 引用了 related_functions 来源文件
         在 fact_dependencies 中记录对应文件

T-B2-04  宏事实依赖：使用了 MacroFact 的 StaticResult 记录 depends_on_file=macro.file

T-B2-05  无跨文件依赖的 case：fact_dependencies 仅包含本文件
```

**构造方式**：构造包含 2~3 个 Lua 文件的 tmp_path 仓库，运行 collector + static_analysis，查询 SQLite 验证依赖记录。

### 3.3 test_incremental.py（B-3 对应）

新建文件。核心测试文件。

```
T-B3-01  单文件变更，无跨文件依赖 → 只失效该文件的 candidate 和 verdict
         构造依赖图：A.lua → case_001 → verdict_001, B.lua → case_002 → verdict_002
         changed_files={A.lua}
         预期: invalidated = {case_001, verdict_001}

T-B3-02  helper 文件变更，跨文件依赖传播
         构造依赖图：
           A.lua → case_001 → StaticResult(case_001) → verdict_001
           helper.lua → FunctionSummary(helper.resolve)
           StaticResult(case_001) depends_on helper.lua
         changed_files={helper.lua}
         预期: invalidated 包含 StaticResult(case_001) 和 verdict_001

T-B3-03  多层传播：A depends on B depends on C，C 变更
         预期: A, B, C 相关的 facts 全部失效

T-B3-04  无关文件变更不触发传播
         changed_files={unrelated.lua}
         预期: invalidated 为空

T-B3-05  全量回退：无历史 run 数据 → should_fallback_to_full() == True
T-B3-06  全量回退：file_fingerprints 为空 → True
T-B3-07  全量回退：changed_files > 30% → True
T-B3-08  正常增量：changed_files < 30% 且有历史数据 → False
T-B3-09  BFS 终止：循环依赖不死循环（防御性测试）
         构造 A depends on B depends on A 的环，验证算法终止
```

**构造方式**：直接操作 `sqlite3.connect(":memory:")` 写入 `fact_dependencies` 和 `file_fingerprints` 表，然后调用 `compute_invalidated_facts()` 验证。

### 3.4 test_run_incremental.py（B-4 对应）

新建文件。集成测试。

```
T-B4-01  增量 run 基本流程：全量 run 后改 1 个文件 → run-incremental 只重算受影响 case
         构造 tmp_path 仓库（2 个 Lua 文件，各含 1 个 sink 调用）
         1. run-start 全量 → 记录 verdict
         2. 修改文件 A 内容
         3. run-incremental --changed-files A.lua
         4. 验证只有 A 的 case 被重算，B 的 case 复用

T-B4-02  增量 run 结果与全量一致
         步骤 3 结束后，重新 run-start 全量
         对比增量报告和全量报告的 verdict

T-B4-03  全量回退触发：首次运行（无历史数据）时 run-incremental 降级为全量
T-B4-04  全量回退触发：changed-files 比例过高
T-B4-05  run-incremental 记录 run_type="incremental"
T-B4-06  run-incremental 与 run-status / run-report / run-export-json 兼容
T-B4-07  增量 run 使用自定义 --base-run-id

T-B4-08  CLI 入口验证：run-incremental --help 输出包含 --changed-files 参数说明
T-B4-09  CLI 入口验证：--changed-files 为空时报错
T-B4-10  CLI 入口验证：--changed-files 指定不存在的文件时警告但不中断
```

**构造方式**：复用 `test_run_jobs.py` 的 `_write_review_config()` 模式构建 tmp_path 仓库。使用 `CountingBackend` 类的变体统计调用数来验证"只重算受影响 case"。

### 3.5 Phase B 性能基准测试

不作为 pytest 自动化用例，作为手工验证步骤记录：

```
PERF-B-01  10 文件仓库，改 1 文件，增量分析时间 vs 全量分析时间
           预期: 增量 < 全量 * 0.1
PERF-B-02  50 文件仓库，改 1 文件
PERF-B-03  50 文件仓库，改 5 文件
```

---

## 4. Phase C 测试设计

### 4.1 test_annotations.py（C-2 / C-3 对应）

新建文件。标注解析器和一致性验证器的单元测试。

#### 解析器测试

```
T-C2-01  解析 returns_non_nil 标注
         输入: "--- @nil_guard: returns_non_nil\nfunction get_name() ... end"
         预期: AnnotationFact(annotation_type="returns_non_nil", function_id 正确)

T-C2-02  解析 ensures_non_nil_arg 标注
         输入: "--- @nil_guard: ensures_non_nil_arg 1\nfunction assert_present(value) ... end"
         预期: AnnotationFact(annotation_type="ensures_non_nil_arg", param_index=1)

T-C2-03  解析 param nullability 标注
         输入: "--- @nil_guard param raw: may_nil\nfunction normalize(raw, fallback) ... end"
         预期: AnnotationFact(param_name="raw", nullability="may_nil")

T-C2-04  解析 return nullability 标注
         输入: "--- @nil_guard return 1: non_nil"
         预期: AnnotationFact(return_slot=1, nullability="non_nil")

T-C2-05  解析条件性标注
         输入: "--- @nil_guard returns_non_nil when arg1 is non_nil"
         预期: AnnotationFact(condition="when arg1 is non_nil")

T-C2-06  多行标注绑定到同一函数
         输入: "--- @nil_guard param raw: may_nil\n--- @nil_guard return 1: non_nil\nfunction f(raw) ... end"
         预期: 返回 2 个 AnnotationFact，function_id 相同

T-C2-07  标注与函数之间有空行 → 仍正确关联
T-C2-08  标注后面没有函数定义 → 忽略该标注（不报错）
T-C2-09  非 @nil_guard 注释 → 不解析
T-C2-10  格式错误的标注 → 忽略并记录 warning
T-C2-11  文件无标注 → 返回空 tuple
T-C2-12  local function 和 module 级 function 均可关联
```

#### 一致性验证器测试

```
T-C3-01  returns_non_nil + 函数确实所有路径返回非 nil → consistent=True
         输入: "--- @nil_guard: returns_non_nil\nfunction f()\n  return 'hello'\nend"

T-C3-02  returns_non_nil + 函数存在 return nil 路径 → consistent=False
         输入: "--- @nil_guard: returns_non_nil\nfunction f(x)\n  if x then return x end\nend"
         预期: conflicts 描述"隐式 return nil 路径"

T-C3-03  returns_non_nil + 所有路径有 or 兜底 → consistent=True
         输入: "function f(x)\n  return x or ''\nend"

T-C3-04  ensures_non_nil_arg 1 + 函数有 assert(arg1) → consistent=True
T-C3-05  ensures_non_nil_arg 1 + 函数无 assert/error/guard → consistent=False

T-C3-06  param raw: may_nil + 函数在使用 raw 前有 guard → consistent=True
T-C3-07  param raw: may_nil + 函数直接使用 raw 无 guard → consistent=False（warning 级别）

T-C3-08  不一致的标注不被自动信任 → verify_annotation().consistent == False 时
         该标注不应产生 StaticProof
```

### 4.2 test_annotation_cross_function.py（C-4 对应）

新建文件。标注接入跨函数推理的集成测试。

```
T-C4-01  跨文件调用已标注 returns_non_nil 函数 → 调用结果视为 safe
         文件 A: "--- @nil_guard: returns_non_nil\nfunction get_name() return self.name or '' end"
         文件 B: "local name = get_name()\nstring.match(name, '^a')"
         预期: B 中的 string.match case 被静态判定为 safe_static
         证据包含 StaticProof(kind="annotation_proof")

T-C4-02  标注覆盖 function_contracts → 标注优先
         function_contracts.json 中 get_name 返回 may_nil
         但 get_name 有 @nil_guard: returns_non_nil 标注
         预期: 标注优先，判定为 safe

T-C4-03  标注不一致时 → 不信任标注，回退到 contract / recognizer
T-C4-04  无标注无 contract → 保持原有 bounded recognizer 行为
T-C4-05  ensures_non_nil_arg 标注 → 被调用者的参数在调用后视为 non_nil
```

**构造方式**：使用 tmp_path 构造包含 2 个 Lua 文件的仓库，运行 `review_source` 或 `bootstrap_repository` + `run_repository_review`，验证 verdict。

### 4.3 test_annotation_coverage.py（C-5 对应）

新建文件。

```
T-C5-01  空仓库（无标注）→ 覆盖率 0%
T-C5-02  全标注仓库 → 覆盖率 100%
T-C5-03  部分标注 → 覆盖率正确计算
         3 个文件，5 个函数，2 个有标注 → 40%

T-C5-04  按模块分组统计正确
         core/ 有 2/3 标注，utils/ 有 0/2 标注

T-C5-05  建议优先标注列表按跨文件引用次数排序
T-C5-06  annotation-coverage CLI 命令输出格式正确
T-C5-07  annotation-suggest 对已有 returns_non_nil 证明的函数建议 returns_non_nil
T-C5-08  annotation-suggest 对有 return nil 路径的函数建议 return 1: may_nil
T-C5-09  annotation-suggest CLI 命令输出格式正确
```

---

## 5. 跨阶段测试设计

### 5.1 旧路径移除回归（X-1 对应）

当多 Agent 路径被移除后，需要修改的现有测试文件：

| 文件 | 修改内容 |
|------|---------|
| `test_adjudication.py` | 所有 case 改为调用 `adjudicate_single_pass()`，断言不再检查 `prosecutor` / `defender` |
| `test_run_jobs.py` | `CountingBackend.adjudicate()` 返回 `SinglePassJudgment` 而非 `AdjudicationRecord(prosecutor, defender, judge)` |
| `test_mvp_agent_semantic_suite.py` | `StrictEvidenceBackend.adjudicate()` 同上 |
| `test_cli.py` | 移除 `--adjudication-mode` 相关测试（如果 single_pass 成为唯一路径） |
| `test_prompting.py` | prompt 构建测试改为验证单次判定 prompt |

### 5.2 数据库 schema 迁移测试

```
T-X-01  历史版本 run 数据库（无新表/新字段）在 V3 代码下可正常打开和查询
T-X-02  V3 代码对 历史版本 数据库自动执行 schema 迁移（ALTER/CREATE）后数据完整
T-X-03  多次重复打开同一数据库不重复迁移
```

---

## 6. Mock 与 Fixture 设计

### 6.1 SinglePassBackend（Phase A）

```python
class SinglePassBackend:
    """确定性单次判定 mock，替代 CountingBackend。"""

    def __init__(self) -> None:
        self.calls = 0

    def adjudicate(self, packet, sink_rule):
        self.calls += 1
        observed_guards = _tuple_field(packet.static_reasoning, "observed_guards")
        if observed_guards:
            return SinglePassJudgment(
                verdict=Verdict(
                    case_id=packet.case_id,
                    status="safe",
                    confidence="high",
                    risk_path=(),
                    safety_evidence=observed_guards,
                    counterarguments_considered=(),
                    suggested_fix=None,
                    needs_human=False,
                ),
                raw_response='{"status":"safe","confidence":"high"}',
                backend_metadata={"backend": "mock", "calls": self.calls},
            )
        return SinglePassJudgment(
            verdict=Verdict(
                case_id=packet.case_id,
                status="risky",
                confidence="medium",
                risk_path=(f"potential nil reaches {sink_rule.qualified_name}",),
                safety_evidence=(),
                counterarguments_considered=(),
                suggested_fix=None,
                needs_human=False,
            ),
            raw_response='{"status":"risky","confidence":"medium"}',
            backend_metadata={"backend": "mock", "calls": self.calls},
        )
```

### 6.2 多文件仓库 Fixture（Phase B/C）

```python
def build_multi_file_repo(tmp_path: Path) -> Path:
    """构建含跨文件依赖的测试仓库。"""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "config").mkdir()
    (root / "src").mkdir()

    # 写入标准配置
    _write_sink_rules(root)
    _write_confidence_policy(root)
    _write_function_contracts(root)

    # helper.lua: 提供 normalize_name 函数
    (root / "src" / "helper.lua").write_text(
        '--- @nil_guard: returns_non_nil\n'
        'function normalize_name(raw)\n'
        '  return raw or ""\n'
        'end\n',
        encoding="utf-8",
    )

    # main.lua: 调用 normalize_name 并使用 string.match
    (root / "src" / "main.lua").write_text(
        'local helper = require("helper")\n'
        'local name = helper.normalize_name(raw_input)\n'
        'return string.match(name, "^a")\n',
        encoding="utf-8",
    )

    return root
```

### 6.3 校准数据 Fixture（Phase A）

```python
def build_calibration_db(tmp_path: Path, records: list[dict]) -> Path:
    """构建含校准数据的测试 SQLite 数据库。"""
    db_path = tmp_path / "calibration.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE calibration_buckets (
            sink_type TEXT NOT NULL,
            unknown_reason TEXT NOT NULL,
            predicted_confidence TEXT NOT NULL,
            sample_count INTEGER NOT NULL DEFAULT 0,
            correct_count INTEGER NOT NULL DEFAULT 0,
            actual_precision REAL,
            last_updated TEXT NOT NULL,
            PRIMARY KEY (sink_type, unknown_reason, predicted_confidence)
        )
    """)
    for r in records:
        conn.execute(
            "INSERT INTO calibration_buckets VALUES (?,?,?,?,?,?,?)",
            (r["sink_type"], r["unknown_reason"], r["predicted_confidence"],
             r["sample_count"], r["correct_count"], r["actual_precision"],
             r["last_updated"]),
        )
    conn.commit()
    conn.close()
    return db_path
```

---

## 7. 测试执行策略

### 7.1 日常开发

```sh
# 运行特定 Phase 的新增测试
pytest tests/test_single_pass_adjudication.py tests/test_calibration.py -v

# 运行全量回归
pytest tests/ -q
```

### 7.2 Phase 完成验收

每个 Phase 完成时，必须执行完整验收：

```sh
# 1. 全量测试通过
pytest tests/ -q

# 2. 精度回归无退化
pytest tests/test_mvp_semantic_suite.py tests/test_mvp_agent_semantic_suite.py -v

# 3. run 作业链路完整性
pytest tests/test_run_jobs.py tests/test_run_incremental.py -v

# 4. CLI 入口完整性
pytest tests/test_cli.py -v
```

### 7.3 A/B 对比测试（Phase A 专属）

非自动化，手工执行并记录结果：

```sh
# 对同一组 labeled cases 分别用两种模式运行
lua-nil-guard benchmark --adjudication-mode multi-agent --backend heuristic /path/to/repo
lua-nil-guard benchmark --adjudication-mode single-pass --backend heuristic /path/to/repo

# 对比 exact_matches / false_positive_risks / missed_risks
```

结果记录格式：

```
日期: YYYY-MM-DD
labeled cases: N
multi-agent: exact_matches=X, fp_risks=Y, missed=Z
single-pass:  exact_matches=X, fp_risks=Y, missed=Z
结论: [single-pass >= multi-agent] / [需保留部分 sink 类型的多轮]
```

---

## 8. 测试文件清单总览

| 新文件 | Phase | 对应计划步骤 | 预估用例数 |
|--------|-------|-------------|-----------|
| `test_single_pass_adjudication.py` | A | A-1 | 8 |
| `test_single_pass_prompting.py` | A | A-1 | 10 |
| `test_adjudication_mode_routing.py` | A | A-2 | 7 |
| `test_calibration.py` | A | A-3, A-4 | 10 |
| `test_file_fingerprint.py` | B | B-1 | 6 |
| `test_fact_dependencies.py` | B | B-2 | 5 |
| `test_incremental.py` | B | B-3 | 9 |
| `test_run_incremental.py` | B | B-4 | 10 |
| `test_annotations.py` | C | C-2, C-3 | 20 |
| `test_annotation_cross_function.py` | C | C-4 | 5 |
| `test_annotation_coverage.py` | C | C-5 | 9 |
| **合计** | | | **~99** |

加上现有 447 测试，V3 完成后预计总测试用例 **~546**。
