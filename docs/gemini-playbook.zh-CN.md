# Gemini Backend 实战手册

这是一份可直接跟跑的 Gemini 审核手册，用于 Lua nil 风险审查。

同时包含“如何配置新的自定义 backend”和“如何指定模型”。

## 1. 快速上手（Gemini）

1. 先检查本地 CLI 与解析环境：

```sh
gemini --version
lua-nil-guard doctor
```

2. 先用单文件验证：

```sh
lua-nil-guard report-file \
  --backend gemini \
  --backend-timeout 90 \
  --backend-attempts 1 \
  /path/to/target-repo/src/demo.lua
```

3. 再扩大到全仓审核：

```sh
lua-nil-guard report \
  --backend gemini \
  --backend-timeout 90 \
  --backend-attempts 1 \
  /path/to/target-repo
```

4. 建议用 `benchmark-json` 做调优与排障：

```sh
lua-nil-guard benchmark-json \
  --backend gemini \
  --backend-timeout 90 \
  --backend-attempts 1 \
  /path/to/labeled-repo \
  build/benchmark_gemini.json
```

标签文件名必须符合：`provable_risky_*`、`provable_safe_*`、`provable_uncertain_*`。

## 2. Backend 与模型指定

`lua-nil-guard` 的核心参数：

- `--backend <name>`：选择裁决 backend（如 `gemini`、`codex`、`claude`）。
- `--model <model_id>`：在 backend 支持模型覆盖时指定模型。
- `--backend-executable <path>`：本次运行覆盖 backend CLI 可执行文件路径。
- `--backend-timeout <seconds>`：单次后端请求超时。
- `--backend-attempts <n>`：单次后端请求重试次数。
- `--backend-config KEY=VALUE`：后端配置覆盖（仅 provider 支持时可用）。

示例：

```sh
lua-nil-guard report --backend gemini --model gemini-3.1-pro-preview /path/to/target-repo
lua-nil-guard report --backend codex --model gpt-5.1-codex-mini /path/to/target-repo
lua-nil-guard report --backend claude --model claude-sonnet-4-5 /path/to/target-repo
```

说明：

- `gemini` 未显式传 `--model` 时，当前默认模型是 `gemini-3.1-pro-preview`。
- 若 provider 不支持模型覆盖却传了 `--model`，命令会报错 `does not support model overrides`。

## 3. 配置新的 Backend（自定义 Provider）

### 3.1 先选协议

当前支持的 manifest 协议：

- `schema_file_cli`：CLI 通过 schema/output 文件交互。
- `stdout_structured_cli`：CLI 以结构化 JSON envelope 输出到 stdout。
- `stdout_envelope_cli`：CLI 以 JSON envelope 输出到 stdout（prompt 参数输入）。

### 3.2 生成 manifest 模板

```sh
lua-nil-guard generate-backend-manifest myagent stdout_envelope_cli build/myagent.manifest.json
```

### 3.3 编辑 manifest

最小示例：

```json
{
  "name": "myagent",
  "protocol": "stdout_envelope_cli",
  "default_executable": "myagent-cli",
  "default_timeout_seconds": 90.0,
  "default_max_attempts": 2,
  "default_fallback_to_uncertain_on_error": true,
  "default_expanded_evidence_retry_mode": "auto",
  "capabilities": {
    "supports_model_override": true,
    "supports_config_overrides": false,
    "supports_backend_cache": true,
    "supports_output_schema": false,
    "supports_output_file": false,
    "supports_stdout_json": true,
    "supports_tool_free_prompting": true
  }
}
```

### 3.4 校验 manifest

```sh
lua-nil-guard validate-backend-manifest build/myagent.manifest.json
```

### 3.5 在审查命令中使用

单次加载（命令内直接带 manifest）：

```sh
lua-nil-guard report \
  --backend myagent \
  --backend-manifest build/myagent.manifest.json \
  --model myagent-pro \
  /path/to/target-repo
```

持久注册（后续命令直接用 backend 名）：

```sh
lua-nil-guard register-backend-manifest --replace build/myagent.manifest.json
lua-nil-guard report --backend myagent --model myagent-pro /path/to/target-repo
```

关键约束：

- `--backend` 必须与 manifest 的 `name` 一致。
- `supports_model_override=false` 时，不要传 `--model`。
- `supports_config_overrides=false` 时，不要传 `--backend-config`。

## 4. Gemini 调优建议

建议先用这组基线参数：

- `--backend-timeout 90`
- `--backend-attempts 1`

出现 fallback/异常时按顺序排查：

1. 看 benchmark JSON 的 `cases[*].backend_failure_reason`。
2. 如果出现 `ERR_STREAM_PREMATURE_CLOSE` 这类传输错误，把 `--backend-attempts` 提高到 `2` 或 `3`。
3. 如果超时比例高，把 `--backend-timeout` 提高到 `120`。

本地实测（`examples/mvp_cases/agent_semantic_suite`，2026-03-07）：

- `--backend-timeout 25 --backend-attempts 1`：fallback 明显偏高，准确率显著下降。
- `--backend-timeout 90 --backend-attempts 1`：`17/18` 命中（`94.4%`），仅有 1 次瞬时后端失败。
