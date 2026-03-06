# LuaNilGuard V3 预期设计

本文档记录 Plan 6 三个方向的详细技术预期，按执行顺序排列。

---

## 1. 方向三：单次结构化判定 + 离线统计校准

### 1.1 单次判定 Prompt Schema

替换 Prosecutor / Defender / Judge 三段 prompt 为一个结构化判定 prompt。

输入模板：

```
你是一个 Lua nil 风险审查员。根据以下证据包判断 nil 是否能到达指定 sink。

## 目标
- 文件: {file}
- 行号: {line}
- Sink: {sink_name}
- 参数: {expression}

## 代码上下文
{local_context}

## 静态分析结果
- 状态: {static_state}
- 已观测守卫: {observed_guards}
- 值来源: {origin_candidates}
- 结构化安全证据: {static_proofs}
- 结构化风险信号: {static_risk_signals}

## 函数摘要
{function_summaries}

## 相关函数上下文
{related_function_contexts}

## 仓库知识事实
{knowledge_facts}

## 不变原则
- Unknown is not risk.
- Absence of proof is not proof of bug.
- 只从提供的代码和声明的事实推理。
- 不做投机性 bug 声称。
- 先检查安全证据，再追踪风险路径。

## 要求
同时从攻防两面分析，输出严格 JSON：
```

输出 Schema：

```json
{
  "status": "safe | risky | uncertain",
  "confidence": "low | medium | high",
  "risk_path": ["步骤 1", "步骤 2"],
  "safety_evidence": ["证据 1", "证据 2"],
  "missing_evidence": ["缺失 1"],
  "recommended_next_action": "suppress | expand_context | report | autofix",
  "suggested_fix": "修复建议（可选）"
}
```

### 1.2 数据模型变更

`AdjudicationRecord` 简化：

```python
@dataclass(frozen=True, slots=True)
class AdjudicationRecord:
    """单次结构化判定结果。"""
    judgment: Verdict  # 直接输出 verdict
    raw_response: str  # 原始 LLM 响应，用于审计
    backend_metadata: dict  # backend/model/latency 等元数据
```

旧 `RoleOpinion` 模型在迁移期保留，通过 `adjudication_mode` flag 区分新旧路径。

### 1.3 校准数据表

新增 SQLite 表：

```sql
CREATE TABLE calibration_buckets (
    sink_type TEXT NOT NULL,
    unknown_reason TEXT NOT NULL,
    predicted_confidence TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    correct_count INTEGER NOT NULL DEFAULT 0,
    actual_precision REAL,
    last_updated TEXT NOT NULL,
    PRIMARY KEY (sink_type, unknown_reason, predicted_confidence)
);
```

扩展 `adjudication_records` 表：

```sql
ALTER TABLE adjudication_records ADD COLUMN predicted_status TEXT;
ALTER TABLE adjudication_records ADD COLUMN predicted_confidence TEXT;
ALTER TABLE adjudication_records ADD COLUMN actual_outcome TEXT;
ALTER TABLE adjudication_records ADD COLUMN calibration_applied INTEGER DEFAULT 0;
ALTER TABLE adjudication_records ADD COLUMN calibrated_confidence TEXT;
```

### 1.4 A/B 切换机制

`config/adjudication_policy.json`：

```json
{
  "adjudication_mode": "single_pass",
  "ab_test": {
    "enabled": false,
    "split_ratio": 0.5,
    "seed": 42
  },
  "calibration": {
    "cold_start_threshold": 30,
    "recalibrate_interval_runs": 5
  }
}
```

CLI flag：

```sh
lua-nil-guard report --adjudication-mode single-pass /path/to/repo
lua-nil-guard report --adjudication-mode multi-agent /path/to/repo  # 旧路径
lua-nil-guard report --adjudication-mode ab-test /path/to/repo
```

### 1.5 精度对比方法

1. 使用现有 `benchmark` 命令，对同一组 labeled case 分别用 `single-pass` 和 `multi-agent` 模式运行。
2. 比较 `exact_matches`、`false_positive_risks`、`missed_risks` 三个关键指标。
3. 如果 `single-pass` 在某些 sink 类型上确实较差，可只对这些类型保留多轮。
4. 在校准数据充足前不移除旧路径。

### 1.6 成功标准

1. 单次判定精度 >= 多 Agent 对抗。
2. 单 case LLM 调用次数从 3 次降至 1 次。
3. 校准层运行后，高置信 verdict 的实际精度可度量且持续改善。

---

## 2. 方向二：依赖驱动的增量分析图

### 2.1 依赖图数据模型

新增 SQLite 表：

```sql
CREATE TABLE file_fingerprints (
    file_path TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    mtime_ns INTEGER NOT NULL,
    last_analyzed_run_id INTEGER
);

CREATE TABLE fact_dependencies (
    fact_id TEXT NOT NULL,
    fact_type TEXT NOT NULL,  -- 'candidate' | 'static_result' | 'function_summary' | 'verdict'
    depends_on_file TEXT NOT NULL,
    depends_on_function TEXT,
    depends_on_annotation TEXT,
    run_id INTEGER NOT NULL,
    PRIMARY KEY (fact_id, depends_on_file)
);

CREATE INDEX idx_fact_deps_file ON fact_dependencies(depends_on_file);
CREATE INDEX idx_fact_deps_run ON fact_dependencies(run_id);
```

### 2.2 Candidate 层改造

按文件粒度产出 candidate：

```python
# 每个 CandidateCase 新增字段
file_fingerprint: str  # content_hash at discovery time
```

Collector 在产出 candidate 时，同时写入 `file_fingerprints` 表和 `fact_dependencies` 表。

### 2.3 Static Evidence 层改造

每个 `StaticResult` 记录其依赖的 `FunctionSummary` / `MacroFact` ID：

```python
# StaticAnalysisResult 隐含依赖
# 在分析过程中收集，写入 fact_dependencies 表
dependencies: list[tuple[str, str]]  # [(depends_on_file, depends_on_function), ...]
```

### 2.4 增量失效传播算法

```
输入: changed_files: set[str]
输出: invalidated_facts: set[str]

1. 对每个 changed_file:
   a. 更新 file_fingerprints 表
   b. 查询 fact_dependencies 中所有 depends_on_file = changed_file 的 fact_id
   c. 将这些 fact_id 加入 invalidated_facts

2. 传播（BFS）:
   while invalidated_facts 有新增:
     对每个新 fact_id:
       查询所有依赖该 fact_id 的上层 fact
       加入 invalidated_facts

3. 输出 invalidated_facts 作为需要重算的子图
```

### 2.5 run-incremental 入口

```sh
lua-nil-guard run-incremental --changed-files src/a.lua,src/helper.lua /path/to/repo
```

内部流程：

1. 加载最近一次全量 run 的 `file_fingerprints` 和 `fact_dependencies`。
2. 对 `--changed-files` 运行失效传播。
3. 只对 invalidated 子图执行 `STATIC → QUEUE → LLM → VERIFY → FINALIZE`。
4. 未失效的 case 直接复用上一轮 verdict。
5. 合并输出完整报告。

### 2.6 全量回退条件

以下任一条件触发自动降级为全量：

1. 无历史 run 数据（首次运行）。
2. `file_fingerprints` 表为空或严重过期。
3. `--changed-files` 涉及 > 30% 的仓库文件。
4. 依赖图完整性检查失败。

### 2.7 成功标准

1. 改动 1 个文件的 PR 场景，分析时间 < 全量的 10%。
2. 增量结果与全量结果一致性 > 99%。
3. `run-incremental` 可在 CI 中直接使用。

---

## 3. 方向一：渐进式类型标注引导

### 3.1 标注语法设计

兼容 LuaLS / EmmyLua 风格，基于 Lua 注释：

```lua
--- @nil_guard returns_non_nil when arg1 is non-nil
--- @nil_guard param raw: may_nil
--- @nil_guard param fallback: non_nil
--- @nil_guard return 1: non_nil
function normalize_name(raw, fallback)
    return raw or fallback or ""
end
```

简化语法（常见场景）：

```lua
--- @nil_guard: returns_non_nil
function get_name()
    return self.name or "unknown"
end

--- @nil_guard: ensures_non_nil_arg 1
function assert_present(value)
    assert(value ~= nil, "expected non-nil")
    return value
end
```

### 3.2 标注解析器接口

```python
@dataclass(frozen=True, slots=True)
class AnnotationFact:
    """从 Lua 注释中解析的 nil 标注。"""
    function_id: str        # file::function_name:line
    file: str
    line: int
    annotation_type: str    # 'returns_non_nil' | 'param_nullability' | 'ensures_non_nil_arg'
    param_name: str | None
    param_index: int | None
    return_slot: int | None
    nullability: str        # 'non_nil' | 'may_nil'
    condition: str | None   # 条件性标注的条件表达式
    raw_text: str           # 原始注释文本


def parse_annotations(source: str, file_path: str) -> tuple[AnnotationFact, ...]:
    """解析 Lua 源码中的 nil_guard 标注。"""
    ...
```

### 3.3 一致性验证器

验证标注与函数体是否一致：

```python
@dataclass(frozen=True, slots=True)
class AnnotationVerification:
    """标注与函数体的一致性验证结果。"""
    annotation: AnnotationFact
    consistent: bool
    evidence: tuple[str, ...]     # 支持一致性的证据
    conflicts: tuple[str, ...]    # 不一致的证据
    confidence: str               # 验证置信度


def verify_annotation(
    annotation: AnnotationFact,
    function_body: str,
    static_proofs: tuple[StaticProof, ...],
) -> AnnotationVerification:
    """验证一个标注是否与函数体实现一致。"""
    ...
```

验证规则：

1. `returns_non_nil`：检查所有 return 路径是否确实返回非 nil。
2. `ensures_non_nil_arg N`：检查函数是否对第 N 个参数执行了非 nil 保证（assert / error / return）。
3. `param X: may_nil`：检查函数体是否在使用 X 前有守卫。
4. 不一致时发出警告，不自动信任标注。

### 3.4 标注接入跨函数推理

替代当前 `function_contracts.json` + `bounded recognizer` 双轨制：

```
优先级: 标注 > function_contracts > bounded recognizer > LLM 判定
```

接入方式：

1. `AnnotationFact` 直接转换为等效的 `StaticProof`（kind = `annotation_proof`）。
2. 跨函数调用时，先查调用目标的标注；无标注则查 contract；无 contract 则走 bounded recognizer。
3. 标注覆盖的函数不再需要 `function_contracts.json` 中的对应条目。

### 3.5 annotation-coverage 命令

```sh
lua-nil-guard annotation-coverage /path/to/repo
```

输出：

```
标注覆盖率报告
===============
总函数数: 1,234
已标注函数: 156 (12.6%)
未标注函数: 1,078

按模块分布:
  core/       42/120  (35.0%)
  utils/      68/200  (34.0%)
  handlers/   46/914  (5.0%)

建议优先标注:
  1. core/validator.lua::validate_input (被 23 个 case 跨文件引用)
  2. utils/helper.lua::normalize_name (被 18 个 case 引用)
  3. core/parser.lua::parse_header (被 15 个 case 引用)
```

### 3.6 annotation-suggest 命令

```sh
lua-nil-guard annotation-suggest /path/to/repo/src/core.lua
```

基于现有分析结果，自动建议标注：

```
建议标注:
  L42: function normalize_name(raw, fallback)
       → --- @nil_guard: returns_non_nil
       置信度: high (静态分析已证明所有 return 路径非 nil)

  L88: function get_user(req)
       → --- @nil_guard param req: non_nil
       → --- @nil_guard return 1: may_nil
       置信度: medium (return nil 路径存在)
```

### 3.7 兼容策略

1. `function_contracts.json` 保留为"无标注仓库"的兼容路径。
2. 先支持读取 LuaLS / EmmyLua 已有标注（`@type`、`@return`），降低客户额外工作量。
3. 标注是可选的，不标注的函数保守处理。

### 3.8 成功标准

1. 标注覆盖率可度量。
2. 已标注函数的跨文件推理精度 > 当前 bounded recognizer。
3. 未标注函数不产生新的 false positive。
