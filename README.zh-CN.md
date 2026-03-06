# LuaNilGuard（中文说明）

`lua-nil-guard` 是一个面向开发者的 CLI 工具，用于审查 Lua 代码中潜在的 nil 相关运行时风险。

当前推荐的使用方式是：保留本仓库的源码目录结构，在此仓库中运行，并将它指向你希望审查的 Lua 项目。

对应英文文档可见：[README.md](./README.md)

## 环境要求

- Python 3.12+
- 本项目源码仓库
- 在本仓库内执行 `pip install -e .`

## 快速开始

1. 创建并激活虚拟环境。
2. 以 editable 模式安装：

```sh
pip install -e .
```

通常每个 Python 环境只需要执行一次。只有在你切换了环境，或项目的依赖、CLI 入口等安装元数据发生变化时，才需要重新执行。

3. 先确认 Tree-sitter 解析环境可用：

```sh
lua-nil-guard doctor
```

4. 初始化目标仓库配置：

```sh
lua-nil-guard init-config /path/to/target-repo
```

5. 默认情况下，LuaNilGuard 已经会把 `id.lua` 和 `*_id.lua` 视为预处理宏字典候选。如果你的仓库里存在超大的“编译前宏字典”文件，请先检查或扩展 `config/preprocessor_files.json`，再查看工具能从这些文件中提取哪些事实：

```sh
lua-nil-guard macro-audit /path/to/target-repo
lua-nil-guard macro-build-cache /path/to/target-repo
lua-nil-guard macro-cache-status /path/to/target-repo
```

这类文件只会被当作预处理输入：它们提供编译期非 nil 事实，但不会被当作普通业务 Lua 文件参与候选扫描。
LuaNilGuard 还会为它们编译并复用本地宏缓存，这样重复执行时不需要每次重新解析未变更的超大宏字典文件。

6. 如果仓库里可能有历史编码的 Lua 文件，先做编码审计和转码：

```sh
lua-nil-guard encoding-audit /path/to/target-repo
lua-nil-guard normalize-encoding --write /path/to/target-repo
```

7. 运行静态扫描：

```sh
lua-nil-guard scan /path/to/target-repo
```

8. 运行完整报告：

```sh
lua-nil-guard report /path/to/target-repo
```

## 持久化 Run 工作流

如果你希望使用“可恢复”的全仓作业链路（start/status/report/export/resume），请使用：

```sh
lua-nil-guard run-start /path/to/target-repo
lua-nil-guard run-status /path/to/target-repo [run_id]
lua-nil-guard run-report /path/to/target-repo [run_id]
lua-nil-guard run-export-json /path/to/target-repo [run_id] [output]
lua-nil-guard run-resume /path/to/target-repo <run_id>
```

`run-status` 与 `run-report` 现在会输出阶段指标和 `unknown_reason` 分布，包含：

- 候选来源计数（`ast_exact`、`lexical_fallback`）
- 静态层计数（`safe_static`、`unknown_static`）
- LLM 层计数（`llm_enqueued`、`llm_processed`、`llm_second_hop`）
- verify 层计数（`safe_verified`、`risky_verified`）
- `unknown_static` case 的 `unknown_reason` 分布

`run-export-json` 现在导出对象结构（不再是纯 findings 数组）：

```json
{
  "run": {
    "run_id": 12,
    "stage_metrics": {
      "static": {"total_cases": 120, "safe_static_cases": 80, "unknown_static_cases": 40},
      "queue": {"llm_enqueued_cases": 40},
      "llm": {"llm_processed_cases": 40, "llm_second_hop_cases": 7},
      "verify": {"safe_verified_cases": 86, "risky_verified_cases": 21},
      "finalize": {"completed_cases": 120, "failed_cases": 0}
    },
    "unknown_reason_distribution": [
      {"reason": "no_bounded_ast_proof", "count": 31}
    ]
  },
  "findings": [
    {
      "case_id": "...",
      "status": "risky_verified",
      "confidence": "high"
    }
  ]
}
```

如果你希望先做一轮更快的“字符串风险专项排查”（仅关注字符串库首参与字符串拼接），可用：

```sh
lua-nil-guard scan --focus string /path/to/target-repo
lua-nil-guard report --focus string /path/to/target-repo
```

## 单文件审查

如果你只想审查某一个 Lua 文件，可以使用单文件入口。该文件仍然必须位于一个已经执行过 `init-config` 的目标仓库中。

```sh
lua-nil-guard scan-file /path/to/target-repo/src/demo.lua
lua-nil-guard report-file /path/to/target-repo/src/demo.lua
lua-nil-guard report-file-json /path/to/target-repo/src/demo.lua
```

如需单文件“字符串风险专项排查”，可用：

```sh
lua-nil-guard scan-file --focus string /path/to/target-repo/src/demo.lua
lua-nil-guard report-file --focus string /path/to/target-repo/src/demo.lua
```

单文件审查会保留仓库上下文，因此在条件允许时，仍然会使用跨文件函数摘要和相关函数源码片段辅助裁决。

## 默认高危覆盖面

LuaNilGuard 开箱即用时，优先覆盖那些最常见、最容易直接引发运行时错误的 nil 高危点：

- `string.find`、`string.match`、`string.gsub`、`string.sub`、`string.len`、`string.byte`、`string.lower`、`string.upper` 等字符串库首参
- 字符串拼接 `..`（左右两侧操作数都会分别检查）
- `pairs(...)` / `ipairs(...)` 表迭代
- `#value` 长度操作
- 可能为 nil 的 receiver 成员访问（如 `value.name`、`value[key]`）
- 数字顺序比较：`<`、`<=`、`>`、`>=`（`==` 和 `~=` 不属于这一类高危点）
- 数值计算：`+`、`-`、`*`、`/`、`%`、`^`（左右两侧操作数都会分别检查）

这些模式已经包含在默认生成的 `sink_rules.json` 中，也是本工具在首次试用时最希望让客户直接感知到的核心价值。

## 首次试用建议

第一次试用时，不建议直接对整个仓库运行完整审查。更稳妥的做法是：先选一个具有代表性的真实 Lua 文件，跑通单文件流程，再逐步扩大范围。

1. 先初始化目标仓库：

```sh
lua-nil-guard init-config /path/to/target-repo
```

2. 先确认解析环境可用：

```sh
lua-nil-guard doctor
```

3. 如果目标仓库可能由旧版 Windows 工具维护过，先做编码检查：

```sh
lua-nil-guard encoding-audit /path/to/target-repo
lua-nil-guard normalize-encoding --write /path/to/target-repo
```

4. 选一个存在 nil 敏感调用的真实文件，先跑：

```sh
lua-nil-guard report-file /path/to/target-repo/src/demo.lua
```

5. 如果结果已经比较明确（例如 `risky` 或 `safe`），先继续在少量文件上验证，再考虑扩大到模块级或仓库级。

6. 如果结果里大量出现 `uncertain`，优先检查该文件是否依赖了当前仓库中不存在的 helper 函数。如果是，先为这些 helper 在 `config/function_contracts.json` 中补最小契约，而不是立刻扩大扫描范围。

常见契约示例：

- 声明某个 guard helper 会保证参数非 nil：

```json
[
  {
    "qualified_name": "assert_present",
    "ensures_non_nil_args": [1]
  }
]
```

- 声明某个 normalizer 只有在传入已知 fallback 时才可视为返回非 nil：

```json
[
  {
    "qualified_name": "normalize_name",
    "returns_non_nil": true,
    "applies_with_arg_count": 2,
    "required_literal_args": {
      "2": "''"
    },
    "applies_to_call_roles": ["assignment_origin", "sink_expression"]
  }
]
```

7. 修改契约后，先重新运行同一个文件，确认效果稳定，再扩大到：

```sh
lua-nil-guard report /path/to/target-repo
```

8. 如果你想看工具当前还无法证明的模式，可以查看 proposal backlog：

```sh
lua-nil-guard proposal-analytics /path/to/target-repo
```

这个输出更适合在你已经跑过几个真实文件之后再看。它能帮助你区分：

- 真正尚未支持的代码模式
- 需要补充 helper 契约的场景

如果你的仓库里有超大的“宏定义/默认值”文件（例如每行都是 `NAME = ""` 或 `Defaults.Name = 0`，并在编译阶段做替换），注意 `id.lua` 和 `*_id.lua` 默认已经会按预处理文件处理。其他文件请继续加入 `config/preprocessor_files.json`，然后运行：

```sh
lua-nil-guard macro-audit /path/to/target-repo
lua-nil-guard macro-build-cache /path/to/target-repo
lua-nil-guard macro-cache-status /path/to/target-repo
```

`macro-audit` 会告诉你：

- 哪些宏文件被加载了
- 哪些宏行被识别成可用的编译期事实
- 哪些行因为超出当前有界语法而被保守地标记为 unresolved

`macro-build-cache` 会预构建编译后的宏缓存，`macro-cache-status` 会显示缓存是否新鲜、是否需要重建。正常的扫描命令在缓存新鲜时也会自动复用它。当命中的预处理文件发生变化、有效的预处理文件配置发生变化，或缓存 schema 版本变化时，缓存会自动重建。

## Backend

默认 backend 是 `heuristic`。如果需要 LLM 裁决，可以通过 `--backend` 使用本地 CLI 集成：

- `gemini`
- `claude`
- `codex`

示例：

```sh
lua-nil-guard report --backend gemini /path/to/target-repo
lua-nil-guard report-file --backend gemini /path/to/target-repo/src/demo.lua
```

这些 backend 依赖对应的本地 CLI 工具、账号凭据以及网络环境都已经在你的机器上正常工作。

如果要使用自定义 provider，可以先生成一份 manifest 模板：

```sh
lua-nil-guard generate-backend-manifest my-provider stdout_envelope_cli
```

## 目标仓库结构

目标仓库需要包含以下配置文件：

- `config/sink_rules.json`
- `config/confidence_policy.json`
- `config/function_contracts.json`
- `config/preprocessor_files.json`

`init-config` 会自动写入这四份默认文件。

其中 `function_contracts.json` 用于声明高置信度 helper 的语义，例如：

- `returns_non_nil`
- `ensures_non_nil_args`
- `returns_non_nil_from_args`
- `returns_non_nil_from_args_by_return_slot`
- `requires_guarded_args_by_return_slot`

同时也支持大量“收紧范围”的字段，用于避免把契约配得过宽，例如：

- `applies_in_modules`
- `applies_in_function_scopes`
- `applies_to_scope_kinds`
- `applies_to_top_level_phases`
- `applies_to_sinks`
- `applies_to_call_roles`
- `applies_to_usage_modes`
- `applies_to_return_slots`
- `applies_with_arg_count`
- `required_literal_args`
- `required_arg_shapes`
- `required_arg_roots`
- `required_arg_prefixes`
- `required_arg_access_paths`

例如：

- 你可以只让某个 helper 在 `assignment_origin` 或 `sink_expression` 场景生效
- 你可以只让它在 `req.params.user` 这类精确访问路径上生效
- 带引号的表键如 `req.params["user"]` 会规范化成与 `req.params.user` 相同的路径
- 动态索引如 `req.params[token]` 不会被视为精确路径匹配

这套机制的目标是：在不依赖 prompt 猜测的前提下，尽量降低误报。

`preprocessor_files.json` 用于声明那类“编译阶段宏字典”文件。默认模板已经内置了 `id.lua` 和 `*_id.lua` 这两个匹配规则。被匹配到的文件不是普通业务 Lua 文件，因此不会参与常规候选扫描；LuaNilGuard 只会从中提取有界、确定的编译期事实，例如：

- `NAME = ""`
- `COUNT = 0`
- `AAA = 0x100`（会规范化为十进制数值语义）
- `Defaults.Name = ""`
- `cmd_id.dis = {0x14, "display"}`（会识别为非 nil 的表字面量）
- `ALIAS = NAME`

对于点号路径赋值（例如 `a.b = 1`），LuaNilGuard 还会推导父级表存在性（`a`）并作为非 nil 表事实。然后在正式扫描原始源码时，把这些事实作为额外的非 nil 证据来减少误报，同时保持报告仍然指向开发者真正维护的原始源码。

## 裁决模式

LuaNilGuard v3 固定使用单次结构化裁决。
CLI 已移除 `--adjudication-mode` 参数。
`config/adjudication_policy.json` 也仅支持 `single_pass`。

## 校准

运行审查后，使用 `calibration-status` 查看离线校准数据：

```sh
lua-nil-guard calibration-status /path/to/target-repo
```

## 增量分析

对于 PR 级工作流，使用 `run-incremental` 只重新分析受变更影响的文件：

```sh
lua-nil-guard run-incremental --changed-files src/a.lua,src/b.lua /path/to/target-repo
```

需要先通过 `run-start` 完成一次全量运行。如果增量分析不可用，会提示回退到全量运行。

## Nil Guard 标注

开发者可以在函数上方添加 `--- @nil_guard` 注释来声明 nil 契约：

```lua
--- @nil_guard: returns_non_nil
function normalize_name(raw)
    return raw or ""
end
```

LuaNilGuard 将标注作为高优先级证据用于跨函数推理。完整语法参见 `docs/annotations.md`。

相关命令：

```sh
lua-nil-guard annotation-coverage /path/to/target-repo
lua-nil-guard annotation-suggest /path/to/target-repo/src/demo.lua
```

## 已知边界

- 当前版本面向开发者试用，推荐先从少量真实文件或一个小模块开始。
- 正式分析命令（如 `scan`、`report`、`report-file`、`benchmark`、`proposal-*`）要求 Tree-sitter 可用。如果 `doctor` 显示不可用，请先修复解析环境，而不是继续依赖降级模式。
- LuaNilGuard 只使用仓库内自带的 Lua grammar，并通过本地 `cc`、`gcc` 或 `clang` 编译生成解析库；不会再回退到外部安装的 `tree_sitter_lua` Python 包，这样不同机器上的解析行为更一致、更可复现。
- 当前要求 Lua 源文件使用 UTF-8。你可以先用 `encoding-audit` 找出非 UTF-8 的 `.lua` 文件，再用 `normalize-encoding --write` 将受支持的历史编码文件（`utf-8-sig`、`gb18030`）统一转为 UTF-8。
- 单文件审查在“重要 helper 源码位于同一仓库”或“这些 helper 已通过 `function_contracts.json` 声明契约”时效果最好。
- 缺少 helper 定义不会阻止审查，但会削弱跨文件证明能力，并增加 `uncertain` 的概率。
- 对于裸全局 `require("module.name")`，工具会把对应模块符号视为已加载非 nil，因此不会在成员访问场景里反复把这些模块 receiver 当作 nil 风险上报。
- 当前实现是“精度优先”而不是“覆盖优先”。当工具无法做出有界证明时，会保守回退，而不是强行给出确定结论。
- 面向超大仓库的性能优化（如全局 AST 缓存、增量分析、并发执行）不在本次发布范围内。本次更适合文件级或模块级试用。

## 说明

- 当前官方支持的运行方式是“源码目录使用”或 editable install。默认 adjudicator skill 已作为包内资源分发，但 vendored Lua grammar 的本地编译仍依赖本仓库目录结构。
- `docs/` 目录下还有更详细的提示词结构与 sink rule 说明，可按需查看。
