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

3. 初始化目标仓库配置：

```sh
lua-nil-guard init-config /path/to/target-repo
```

4. 运行静态扫描：

```sh
lua-nil-guard scan /path/to/target-repo
```

5. 运行完整报告：

```sh
lua-nil-guard report /path/to/target-repo
```

## 单文件审查

如果你只想审查某一个 Lua 文件，可以使用单文件入口。该文件仍然必须位于一个已经执行过 `init-config` 的目标仓库中。

```sh
lua-nil-guard scan-file /path/to/target-repo/src/demo.lua
lua-nil-guard report-file /path/to/target-repo/src/demo.lua
lua-nil-guard report-file-json /path/to/target-repo/src/demo.lua
```

单文件审查会保留仓库上下文，因此在条件允许时，仍然会使用跨文件函数摘要和相关函数源码片段辅助裁决。

## 首次试用建议

第一次试用时，不建议直接对整个仓库运行完整审查。更稳妥的做法是：先选一个具有代表性的真实 Lua 文件，跑通单文件流程，再逐步扩大范围。

1. 先初始化目标仓库：

```sh
lua-nil-guard init-config /path/to/target-repo
```

2. 选一个存在 nil 敏感调用的真实文件，先跑：

```sh
lua-nil-guard report-file /path/to/target-repo/src/demo.lua
```

3. 如果结果已经比较明确（例如 `risky` 或 `safe`），先继续在少量文件上验证，再考虑扩大到模块级或仓库级。

4. 如果结果里大量出现 `uncertain`，优先检查该文件是否依赖了当前仓库中不存在的 helper 函数。如果是，先为这些 helper 在 `config/function_contracts.json` 中补最小契约，而不是立刻扩大扫描范围。

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

5. 修改契约后，先重新运行同一个文件，确认效果稳定，再扩大到：

```sh
lua-nil-guard report /path/to/target-repo
```

6. 如果你想看工具当前还无法证明的模式，可以查看 proposal backlog：

```sh
lua-nil-guard proposal-analytics /path/to/target-repo
```

这个输出更适合在你已经跑过几个真实文件之后再看。它能帮助你区分：

- 真正尚未支持的代码模式
- 需要补充 helper 契约的场景

## Backend

默认 backend 是 `heuristic`。如果需要 LLM 裁决，可以通过 `--backend` 使用本地 CLI 集成：

- `gemini`
- `codeagent`
- `claude`
- `codex`

示例：

```sh
lua-nil-guard report --backend gemini /path/to/target-repo
lua-nil-guard report-file --backend codeagent /path/to/target-repo/src/demo.lua
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

`init-config` 会自动写入这三份默认文件。

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

## 已知边界

- 当前版本面向开发者试用，推荐先从少量真实文件或一个小模块开始。
- 单文件审查在“重要 helper 源码位于同一仓库”或“这些 helper 已通过 `function_contracts.json` 声明契约”时效果最好。
- 缺少 helper 定义不会阻止审查，但会削弱跨文件证明能力，并增加 `uncertain` 的概率。
- 当前实现是“精度优先”而不是“覆盖优先”。当工具无法做出有界证明时，会保守回退，而不是强行给出确定结论。
- 面向超大仓库的性能优化（如全局 AST 缓存、增量分析、并发执行）不在本次发布范围内。本次更适合文件级或模块级试用。

## 说明

- 当前官方支持的运行方式是“源码目录使用”或 editable install。默认技能文件依赖本仓库目录结构。
- `docs/` 目录下还有更详细的提示词结构与 sink rule 说明，可按需查看。
