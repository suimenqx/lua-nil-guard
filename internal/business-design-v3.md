# LuaNilGuard V3 业务设计

## 1. 产品定位

LuaNilGuard 是面向 Lua 开发者的 nil 风险筛查 CLI 工具。

核心价值主张：**用最少的人工注意力，发现最可信的 nil 崩溃风险**。

设计哲学：

- 精度优先：报出来的就是真的，没报的可能存在但当前无法确认。
- 渐进增长：从单文件到全仓，从零标注到高覆盖，开发者按自己的节奏采纳。
- 机器推理替代人工审查：静态分析兜底，LLM 处理不确定部分，统计校准修正偏差。

## 2. 目标用户场景

### 场景 A：全仓离线审计（历史版本 已支持）

- 典型用户：项目负责人、QA 团队。
- 工作流：`init-config → scan → report → run-start`。
- 价值：一次性发现仓库中潜在的 nil 崩溃热点。
- 输出：结构化报告（Markdown / JSON），含证据链。

### 场景 B：PR 级增量审查（V3 Phase B 目标）

- 典型用户：CI/CD 流水线、代码审查者。
- 工作流：`run-incremental --changed-files a.lua,b.lua`。
- 价值：每个 PR 在分钟级出结果，只报告本次变更引入或影响的风险。
- 约束：改动 1 个文件的场景，分析时间 < 全量的 10%。

### 场景 C：标注驱动的渐进式覆盖（V3 Phase C 目标）

- 典型用户：核心模块维护者。
- 工作流：在关键函数上添加 nil 标注 → 工具验证标注与函数体一致性 → 标注覆盖率报告驱动逐步覆盖。
- 价值：开发者主动声明意图，工具验证而非推断，跨函数推理精度显著提升。

### 场景 D：单文件快速审查（历史版本 已支持）

- 典型用户：开发者本地调试。
- 工作流：`report-file /path/to/file.lua`。
- 价值：即时反馈，无需等待全仓分析。

## 3. CLI 命令体系

### 3.1 现有命令（保持）

| 命令 | 用途 |
|------|------|
| `init-config` | 初始化目标仓库配置 |
| `doctor` | 检查 Tree-sitter 解析环境 |
| `scan` / `scan-file` | 静态扫描 |
| `report` / `report-file` / `report-file-json` | 完整报告 |
| `run-start` / `run-status` / `run-report` / `run-resume` / `run-export-json` | 持久化作业 |
| `macro-audit` / `macro-build-cache` / `macro-cache-status` | 预处理宏管理 |
| `encoding-audit` / `normalize-encoding` | 编码检查与转码 |
| `proposal-analytics` | 提案分析 |
| `benchmark` | 精度基准测试 |
| `generate-backend-manifest` | 自定义 backend 模板 |

### 3.2 Plan 6 新增命令

| 命令 | 阶段 | 用途 |
|------|------|------|
| `run-incremental` | Phase B | 增量分析，接受 `--changed-files` 参数 |
| `annotation-coverage` | Phase C | 标注覆盖率报告 |
| `annotation-suggest` | Phase C | 基于现有分析结果自动建议标注 |
| `calibration-status` | Phase A | 校准数据统计与精度报告 |

### 3.3 命令交互示例

```sh
# Phase A：单次判定上线后
lua-nil-guard report --adjudication-mode single-pass /path/to/repo
lua-nil-guard calibration-status /path/to/repo

# Phase B：PR 级增量
lua-nil-guard run-incremental --changed-files src/a.lua,src/b.lua /path/to/repo

# Phase C：标注引导
lua-nil-guard annotation-coverage /path/to/repo
lua-nil-guard annotation-suggest /path/to/repo/src/core.lua
```

## 4. 用户交互流程

### 4.1 当前流程（保持）

```
开发者 → init-config → doctor → [macro-audit] → scan/report → 阅读报告 → 补充 contracts → 重新 report
```

### 4.2 V3 目标流程

```
开发者 → init-config → doctor → scan/report
  │
  ├─ 发现 uncertain 多 → annotation-suggest → 添加标注 → report（精度提升）
  │
  ├─ CI 集成 → run-incremental --changed-files（PR 级反馈）
  │
  └─ 持续改善 → calibration-status → 观察校准修正趋势 → annotation-coverage → 推进覆盖
```

## 5. 配置体系

### 5.1 现有配置（保持）

| 文件 | 用途 |
|------|------|
| `config/sink_rules.json` | nil 敏感 sink 目录 |
| `config/confidence_policy.json` | 置信度门槛与报告策略 |
| `config/function_contracts.json` | 函数语义契约（手工配置） |
| `config/preprocessor_files.json` | 预处理宏字典文件配置 |

### 5.2 V3 新增配置

| 文件 | 阶段 | 用途 |
|------|------|------|
| `config/adjudication_policy.json` | Phase A | 裁决模式（`single_pass` / `legacy_mode` / `legacy_split`），校准冷启动阈值 |
| 标注语法（内嵌 Lua 注释） | Phase C | `--- @nil_guard: ...` 风格的 nil 标注 |

### 5.3 配置优先级

标注 > function_contracts > 静态推断 > LLM 判定 > 保守默认（uncertain）

## 6. Backend 策略

### 6.1 当前 Backend（保持）

- `heuristic`（默认，纯静态）
- `gemini` / `claude` / `codex`（LLM 裁决）
- 自定义 manifest

### 6.2 V3 Token 经济性

单次判定后：

| 维度 | 历史版本（多 Agent） | V3（单次判定） |
|------|------------------|----------------|
| 每 case LLM 调用次数 | 3 | 1 |
| 单 case token 成本 | ~3x | ~1.5x（更好的上下文） |
| 省下的预算用途 | — | 扩大首轮上下文窗口、EvidencePacket 中包含更多相关函数片段 |

## 7. 交付里程碑

### Phase A：单次判定 + 校准（最快见效）

- 不改数据模型。
- Token 成本立降。
- 交付物：`--adjudication-mode single-pass` flag，`calibration-status` 命令。
- 用户可感知：同等精度下 LLM 调用成本降至 1/3。

### Phase B：增量分析图（数据模型扩展）

- SQLite schema 扩展。
- 交付物：`run-incremental` 命令。
- 用户可感知：PR 级审查从"分钟级全量"降至"秒级增量"。

### Phase C：标注引导（最大范式转变）

- 需要前两个方向稳定后推进。
- 交付物：标注解析器、`annotation-coverage` 命令、`annotation-suggest` 命令。
- 用户可感知：标注覆盖的函数跨文件推理精度显著提升，`uncertain` 比例下降。

## 8. 报告体系

### 8.1 现有报告输出（保持）

- `risky` / `risky_verified` + `high` confidence → 人类可见报告
- `safe` / `safe_verified` → 内部状态，默认不展示
- `uncertain` → 内部状态，默认不展示

### 8.2 V3 新增报告维度

- **校准修正审计**：原始 confidence + 校准后 confidence + 校准桶统计
- **标注覆盖率**：已标注函数 / 总函数，按模块分布
- **增量分析命中率**：增量重算子图 / 全量 case 比例
