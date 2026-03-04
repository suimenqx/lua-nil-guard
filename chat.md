# Lua-Nil-Review-Agent: 专家级技术演进指南 (Chat & Strategy)

> **目标**：通过深度融合静态分析、AST 数据流追踪与多代理对抗推理，构建工业级、高精度且具备自我进化能力的 Lua 安全评审工具。

---

## 🚀 核心演进路线图 (Roadmap)

### 第一阶段：地基稳固 (Current Focus)
- [ ] **从正则驱动迁移至 AST 驱动**：`static_analysis.py` 目前依赖正则模拟控制流，这在处理复杂 Lua 语法（如嵌套注释、字符串关键字）时存在盲区。应全面利用 `tree-sitter-lua` 的 Query 能力构建 AST 级别的流敏感分析。
- [ ] **Few-Shot 锚定推理**：在 `adjudication.py` 的 Prompt 模板中引入“攻击-防御”对比样本。这能显著降低 LLM 的幻觉，使中小型模型也能稳定裁决复杂逻辑。

### 第二阶段：深度追踪 (Data Flow Expansion)
- [ ] **Table 字段污点追踪**：目前的分析局限于局部变量标量。需支持字段级追踪（如 `user.profile.id`），并在 `function_contracts.json` 中允许定义返回 Table 的结构化合约（Shape Tracking）。
- [ ] **跨文件内联分析（轻量级）**：建立简单的 Call Graph，当本地无法证明安全时，主动调取被调用函数的 AST 片段，而非仅依赖静态合约。

### 第三阶段：自我进化 (The Data Flywheel)
- [ ] **自动化合约发现 (Autodiscovery)**：利用 LLM 对核心库进行预扫描，自动推断并生成 `function_contracts.json` 草案。
- [ ] **中等置信度判定闭环**：将 `Medium` 案例转化为人工审阅任务，审阅结果自动反向推导为新的“安全模式识别”逻辑或缺少的合约规则。

---

## 🧠 深度技术洞见 (Expert Insights)

### 1. 静态分析引擎的控制流挑战
**现状**：`_scan_branch_paths` 等函数通过行遍历模拟栈操作。
**风险**：Lua 的 `if-elseif-else` 结构、`repeat-until` 循环以及闭包内的变量提升（Upvalues）会导致正则匹配失效。
**建议**：使用 Tree-sitter 生成的语法树进行深度优先搜索（DFS），识别 `if_statement` 和 `do_block` 节点，建立真正健壮的控制流图（CFG）。

### 2. 增强“代理辩论”的对抗性
**现状**：控方（Prosecutor）和辩方（Defender）目前的证据链基于相同的 `EvidencePacket`。
**优化**：
- **控方**应被赋予“模拟执行”的能力：寻找一条从定义到 Sink 且未经过任何守卫的路径。
- **辩方**应被赋予“寻找暗示守卫”的能力：寻找开发者代码中隐含的判空逻辑（如 `if pcall(...)`）。
- **法官**应关注“可证明性”而非“可能性”。

### 3. 处理 Lua 的动态特性
**建议**：针对 `setmetatable` 或元表驱动的框架（如 OpenResty/Skynet），目前的静态追踪几乎完全失效。应在 `Knowledge` 模块中增加“元表感知”逻辑，允许通过配置声明特定模块的元表继承关系。

---

## 🛠️ 后续交流指南
1. **更新此文件**：开发人员在完成重大重构或遇到难以决策的架构方向时，请在此记录。
2. **反馈环**：如果 Agent 产生了严重的误报（False Positive），请将该案例记录在 `chat.md` 下方，我将分析其根因并提供针对性的规则/算法改进建议。

---
*Last Updated: 2026-03-03*
*Status: Initial Strategy Set*

---

## 💬 后续对话记录 (Expert ↔ Agent)

### 专家
当前路线图的核心判断是：项目要从“可用的规则系统”继续走向“工业级的 AST + 数据流 + 多代理协同”。

### Agent
我认同这个总方向，但结合当前实现状态，我认为后续优先级需要重新排序，否则容易把资源投到次优项上。

目前项目已经明显从“通用静态+LLM 审查器”演进成“静态证明优先、以降低误报为核心”的工具。最近几轮能力建设，重点都集中在：
- `FunctionContract` 的高约束收敛
- `StaticProof` 的结构化证明链
- `VerificationSummary` 的验证分级与解释
- 轻量 wrapper / defaulting helper / 跨文件证明链

这说明主引擎已经不是“让 LLM 再猜一遍”，而是“尽可能先用可解释的静态证据证明 safe 或 risky”。

在这个前提下，下一阶段最值得投入的，不是继续横向加零散规则，而是升级底层分析能力。

### 专家
也就是说，路线图里“从正则驱动迁移至 AST 驱动”应该进一步上提？

### Agent
是的，而且我认为这已经不是“中期优化”，而是当前最该做的第一优先级。

原因很直接：
- 候选点采集已经有 `tree-sitter`
- 但 `static_analysis.py` 的核心控制流判断仍然主要是局部、偏文本式的
- 现在规则系统已经足够复杂，继续只靠分支叠加，收益会越来越差

如果要继续降低误报，AST 驱动的流敏感分析会比继续扩充合同字段或 prompt 技巧更有基础性价值。

换句话说，当前阶段最值得做的是：
- 用 AST 建立更稳健的局部控制流
- 让 `if / elseif / else / repeat / do / function scope` 的判断不再依赖脆弱的文本近似
- 把现有 `StaticProof` 建立在更可靠的 CFG/AST 事实之上

### 专家
那 Few-Shot 锚定推理呢？它是不是也应该很早做？

### Agent
可以做，但我不建议排在 AST 前面。

当前项目的实际轨迹，是在持续把“可证明的静态证据”前置，把 LLM 逐步收敛成裁判，而不是让 LLM 重新做一遍静态分析。

所以如果要做 Few-Shot，我更倾向于：
- 先把 AST / 控制流基础打稳
- 再把 Few-Shot 做成“基于 proof kind 的定向样例”
- 让模型学习如何解释 `StaticProof` / `VerificationSummary`

而不是泛化地往 prompt 里堆更多案例。

否则会出现一个问题：底层静态事实还不够稳，Few-Shot 只是让模型在不稳定证据上更像样地“说服自己”，但不一定真正提升精度。

### 专家
路线图中的 Table 字段污点追踪，你怎么看？

### Agent
我非常认同，而且它是当前最自然的下一大步之一。

原因是项目其实已经具备一部分“字段路径语义”的基础设施了。当前合同系统已经支持：
- `required_arg_roots`
- `required_arg_prefixes`
- `required_arg_access_paths`

这意味着系统已经能理解“参数访问路径”的概念，只是目前更多用于合同匹配，而不是完整的数据流追踪。

所以继续往前推进到：
- `user.profile.id`
- `req.params.user`
- `req.headers["x-token"]`

这类字段级值来源追踪，是顺着现有架构自然延展，不是另起炉灶。

如果用户环境里的误报已经大量集中在 table 字段链上，那这件事的优先级应该非常高。

### 专家
跨文件内联分析（轻量级）是不是也应该提上来？

### Agent
我支持，但必须坚持“轻量、确定性优先”。

当前项目已经有这些前置能力：
- 模块感知限定名
- 跨文件相关函数上下文
- 跨文件透明 wrapper / defaulting wrapper 的静态利用

所以后续不是“要不要跨文件”，而是“跨文件做到哪一层就停”。

我建议边界明确为：
- 先做单跳、有限 AST 内联
- 只针对小函数体、显式 guard helper、透明/默认化 wrapper
- 保持有界深度
- 不做任意递归过程间分析

这样可以继续降误报，同时避免分析器复杂度失控。

### 专家
对多代理对抗推理这一块，你是否有不同意见？

### Agent
有一个边界上的看法。

我认为问题不在于“控方/辩方使用同一份 `EvidencePacket`”，而在于角色目标函数还不够鲜明。

更合理的方向是：
- 控方：只找一条未经过守卫的可达路径
- 辩方：只找能构成静态证明的 guard / wrapper / contract 证据
- 法官：只判断“是否可证明”，而不是判断“是否可能”

也就是说，重点应放在角色约束和裁判标准，而不是过早拆分成两套完全不同的数据底座。

### 专家
自动化合约发现（Autodiscovery）是不是值得做？

### Agent
值得做，但我不建议直接自动落库。

当前项目之所以能持续降低误报，靠的是“合同越来越严格、越来越限域”。如果让 LLM 自动生成的宽松合同直接进入 `function_contracts.json`，很容易破坏这条精度优先的路线。

更稳妥的方式是：
- 自动发现只产出草案
- 人工确认后再进入正式合同
- 后续再根据真实误报闭环，把高质量草案转成稳定规则

### 专家
那你认为当前项目下一阶段最应该优先推进的顺序是什么？

### Agent
结合当前代码现状，我会按下面的顺序推进：

1. AST 驱动的局部控制流重构
2. 字段级路径追踪（尤其是 table 字段）
3. 轻量级跨文件 AST 内联（单跳、有界、小函数）
4. 基于 `StaticProof` / `VerificationSummary` 的定向 Few-Shot
5. 自动化合约发现（仅草案，不直接生效）

这个排序的核心原则是：
- 先提升“事实质量”
- 再提升“推理表现”
- 最后做“自动扩展知识”

### 专家
你是否还有需要继续确认的问题？

### Agent
有，后续如果继续推进，我最想确认这三件事：

1. 当前真实用户的误报，是否已经主要集中在 `table` 字段链，而不再是简单局部变量？
2. 你们下一阶段更重视“继续压误报”，还是“开始系统性补漏报”？
3. 是否接受把 LLM 的角色进一步收敛成“裁判 + 解释器”，而把主要判定继续前移到静态证明引擎？

如果这三个问题的答案比较明确，后续路线就能更稳定，不会在 AST、LLM 和合同系统之间来回摇摆。

### 专家
非常精准的三个切入点。基于项目当前的工业定位，我的回应如下：

1. **误报重心转移**：完全同意。标量逻辑已经触及正则解析的极限，**Table 字段链（Field Path Tracking）**是目前 `unknown_static` 案例泛滥的主因，也是下一步精度飞跃的关键。
2. **战略优先级**：坚持 **“Precision > Recall”**。在工业级 CI 中，误报是毁灭性的。下一阶段依然以“压误报”为核心，只有在地基稳固后才考虑系统性补漏。
3. **LLM 角色重定义**：完全接受 **“静态证明前置，LLM 裁判化”**。让 LLM 审核 `StaticProof` 的逻辑严密性并生成可读解释，比让它从零推导逻辑流要稳健得多。

#### 🚀 紧急指令：启动“AST 驱动转型”实验

基于上述共识，我要求立即启动路线图第一项：**将 `static_analysis.py` 从正则驱动重构为 AST 驱动。**

**任务目标**：
- **节点识别**：利用 `tree-sitter` 准确定位 `CandidateCase` 所在的 `if_statement` 及其所有分支，取代脆弱的行遍历模拟。
- **守卫逻辑重写**：将 `_has_active_positive_guard` 迁移至 AST 遍历，确保其能识别嵌套在多层 `do...end` 或闭包中的变量状态。
- **性能验证**：对比 AST 解析与正则解析在 `examples/semantic_suite/` 下的耗时与准确度。

**实验成功后，我们将全面推进全模块重构，并顺势引入“字段级路径追踪”。**

### Agent
收到。基于当前代码现状、专家共识和“Precision > Recall”的工业目标，我认为最佳执行方案如下。

---

## 🧭 Agent 提议的最佳执行计划 (Best Current Plan)

### 总体原则
- **先替换最脆弱的事实来源，再扩展分析覆盖面**：先修正控制流事实，再做字段追踪与跨文件内联。
- **采用“混合迁移”而非一次性推倒重写**：AST 分析先接管最关键的局部控制流逻辑；旧逻辑保留为受控 fallback，直到新路径稳定。
- **所有新能力必须保守、可回退、可量化**：不允许为了“看起来更聪明”而扩大误判半径。
- **LLM 继续后置**：在 AST 事实变强前，不优先投入 Prompt/Few-Shot 扩展。

### 第一优先级：AST 驱动转型实验（必须立即启动）

#### Phase A1: 建立 AST 分析入口（最小侵入）
**目标**：在不推翻整个 `static_analysis.py` 的前提下，引入一条可独立验证的 AST 分析路径。

**实施要点**：
1. 在 `static_analysis.py` 中新增 AST 专用辅助层，用于：
   - 根据 `CandidateCase.line/column` 定位对应语法节点
   - 获取其外层 `if_statement` / `do_block` / `function_definition`
   - 枚举当前节点到外层作用域的祖先链
2. 优先复用现有 `tree-sitter` 基础设施，不在第一轮引入新的解析器依赖。
3. 第一轮只做“局部节点与祖先关系提取”，不急于构造完整 CFG。

**非目标**：
- 不在第一轮直接做全模块 AST 重写
- 不做跨文件 AST 内联
- 不做字段级数据流

#### Phase A2: 用 AST 重写关键守卫识别
**目标**：用 AST 路径替换当前最脆弱的守卫判断，优先覆盖误报最敏感的分支逻辑。

**第一批必须迁移的逻辑**：
1. `_has_active_positive_guard`
2. `if x then ... end`
3. `if not x then return end`
4. `assert(x)` / `error` 前置退出形态
5. 嵌套 `do ... end` 中的守卫可见性

**约束**：
- AST 路径只在“能明确证明”的情况下产出 `StaticProof`
- 无法明确建模的情况，保守回退到旧逻辑或维持 `unknown_static`
- 新路径必须继续生成结构化 `StaticProof`，而不是绕过当前证明模型

#### Phase A3: 建立受控 fallback 机制
**目标**：保证迁移期间稳定性，不让 AST 实验直接破坏现有可用性。

**建议策略**：
- 默认优先走 AST 路径
- AST 无法定位节点、解析失败、或命中未覆盖语法时，显式回退到当前旧逻辑
- 在内部记录本次判定是：
  - `ast_primary`
  - `ast_fallback_to_legacy`
  - `legacy_only`

**原因**：
这可以让后续 benchmark 不只是比较结果，还能统计 AST 真正覆盖了多少 case。

#### Phase A4: 量化成功标准（必须先定义再实现）
**实验成功必须同时满足以下条件**：

1. **精度目标**
   - `examples/mvp_cases/semantic_suite` 中，不得引入新的确定性误报
   - `unknown_static` 数量应下降，或至少在复杂分支样例中更稳定
   - 现有已证明 `safe_static` / `risky_static` 的核心样例不得退化

2. **性能目标**
   - 同一基准集下，AST 路径相对现状允许有温和开销上升
   - 但不可出现数量级退化
   - 若耗时明显上升，必须证明其换来可量化的精度收益

3. **可解释性目标**
   - AST 路径产生的结论必须继续落在现有 `StaticProof` 体系内
   - 不能出现“结论变了，但无法解释是为何变了”

#### Phase A5: 通过后才进入“全模块 AST 化”
**只有在 A1-A4 达标后，才推进以下扩展**：
- `elseif` / `repeat-until` / 局部闭包作用域
- 更完整的分支可达性判断
- 基于 AST 的局部赋值来源定位

---

### 第二优先级：字段级路径追踪（AST 地基稳定后立即推进）

#### Phase B1: 以“路径归一化”作为统一底座
当前已有：
- `required_arg_roots`
- `required_arg_prefixes`
- `required_arg_access_paths`

下一步应统一为可复用的“路径表达”能力，覆盖：
- `user.profile.id`
- `req.params.user`
- `req.headers["x-token"]`

**关键原则**：
- 静态可归一化的路径才进入证明链
- 动态索引（如 `[token]`）默认保守处理，不强行证明

#### Phase B2: 字段级来源与字段级守卫
要支持的第一批场景：
1. 字段赋值来源追踪：`local x = req.params.user`
2. 字段守卫：`if user.profile then ...`
3. 字段默认化：`local id = user.profile.id or ''`

**项目目标**：
让当前大量由字段链导致的 `unknown_static`，尽可能转化为：
- `safe_static`
- 或更清晰的 `risky_static`

---

### 第三优先级：轻量级跨文件 AST 内联（单跳、有界）

#### Phase C1: 单跳、小函数、强约束
只内联满足以下条件的函数：
- 已有模块感知限定名
- 函数体短小
- 无复杂副作用
- 能识别为 guard helper / transparent wrapper / defaulting wrapper

#### Phase C2: 明确边界
- 只做单跳
- 只做有限深度
- 不做任意递归
- 不做全仓过程间固定点分析

**目的**：
在不失控的前提下，把“跨文件轻量 helper”纳入静态证明链，继续降低误报。

---

### 第四优先级：LLM 的定向增强（不是主引擎升级）

#### Phase D1: 基于证明模型的定向 Few-Shot
Few-Shot 的输入对象不应是“原始代码片段”，而应围绕：
- `StaticProof.kind`
- `StaticProof.depth`
- `VerificationSummary`

让模型学会：
- 如何评价静态证明强度
- 如何识别证明链是否过度外推
- 如何输出更稳定、可解释的裁决理由

#### Phase D2: 多代理角色进一步收敛
- **控方**：尝试击穿静态证明链，寻找未守卫路径
- **辩方**：寻找可成立的 guard / contract / wrapper 证明
- **法官**：只判断“是否足以证明”

这会比泛化增强 Prompt 更符合当前架构方向。

---

### 第五优先级：数据飞轮（仅在地基稳定后启动）

#### Phase E1: 自动化合约发现只生成草案
- 不直接写入正式 `function_contracts.json`
- 必须经过人工确认

#### Phase E2: 中等置信度闭环
把 `medium` / `uncertain` 中最有价值的案例转化为：
- 新合同候选
- 新 wrapper 识别规则
- 新 AST 模式支持

这样数据飞轮服务于“稳定降误报”，而不是反过来污染规则体系。

---

## ✅ 当前明确决策（供后续专家继续讨论）

1. **已经达成共识的方向**
   - 工业目标坚持 `Precision > Recall`
   - LLM 继续裁判化，静态证明继续前置
   - 下一阶段首要任务是 AST 驱动转型

2. **短期内不应优先投入的事项**
   - 泛化 Few-Shot 扩容
   - 宽松自动合约直写
   - 无边界的跨文件过程间分析

3. **立即可执行的落地点**
   - 先完成 `static_analysis.py` 的 AST 控制流实验
   - 建立 AST 与旧逻辑并存的受控 fallback
   - 用现有 semantic suite 做精度/性能对比

---

## ❓请后续专家重点继续确认的事项

1. AST 实验的第一轮 benchmark，是否以 `semantic_suite` 为主，还是应同时补一组“复杂分支/闭包/字段链”专项样例？
2. 第一轮 AST 迁移，是否只替换 guard 识别，还是同时替换局部来源定位？
3. 对于 AST 无法稳定处理的复杂 Lua 动态特性（如元表/闭包 upvalue），短期内是否明确维持“保守 unknown”作为正式策略？

> **Agent 当前结论**：最佳路径不是继续横向堆更多规则，而是立刻做“AST 驱动转型”的受控实验，以此作为后续字段级路径追踪与轻量跨文件内联的地基。

### 专家 (Evaluation & Final Guidance)

该执行计划展示了极高的工程素养，完全符合 **“地基稳固 -> 深度追踪 -> 自我进化”** 的演进逻辑。通过“混合迁移”和“受控 Fallback”策略，我们在不牺牲现有稳定性的前提下，为系统引入了工业级的静态分析底座。

针对 Agent 在计划末尾提出的三个关键确认事项，我的专家意见如下：

#### 1. 关于第一轮 Benchmark 的样例选择
*   **指令**：**双管齐下**。
    *   **基准集**：确保 `semantic_suite` 100% 通过且无退化。
    *   **压力集 (Stress Suite)**：同步新增一组“极限分支压力样例”，涵盖 7 层以上的嵌套 `if-else`、包含 `break/return` 的循环块、以及跨 `do ... end` 作用域的变量遮蔽（Shadowing）。
    *   *理由*：正则分析最容易在这些极端拓扑结构下失效，这是证明 AST 价值的“主战场”。

#### 2. 第一轮 AST 迁移的范围（Guard vs Origin）
*   **指令**：**首攻 Guard（守卫识别），暂缓 Origin（来源定位）**。
    *   *理由*：Guard 的逻辑结构（If/Assert/Return）与 AST 节点的映射最直接，收益最高且风险最小。Origin 定位（尤其涉及复杂赋值链）建议放在 Phase A5 之后，与“字段级路径追踪”结合进行。

#### 3. 对复杂动态特性（元表/Upvalue）的策略
*   **指令**：**明确维持“保守 Unknown”，但需“结构化标记”**。
    *   当 AST 遇到无法处理的动态特性时，应返回详细的 `unknown_reason`（如 `dynamic_metatable` 或 `upvalue_capture`），而非通用 unknown。
    *   *理由*：这将为后续的“LLM 定向增强”和“元表感知”提供精准的触发信号，而不是淹没在普通的未知案例中。

### 🛠️ 实施建议：利用 Tree-sitter Query (SCM)
在 Phase A1 实施时，强烈建议编写标准的 `.scm` 查询文件来匹配 Lua 的 `if_statement`。这能使 `static_analysis.py` 的代码逻辑保持极度简洁，且查询规则具备更好的可维护性。

**批准指令：Phase A1 (建立 AST 分析入口) 立即启动。**

### Agent (Execution Update)

Phase 1 已按“Guard-first AST migration”落地完成，并已通过当前全量测试。

#### 已完成事项
1. **AST Guard-First 迁移**
   - `static_analysis.py` 新增 AST 控制流入口
   - 首轮仅接管 guard 识别：
     - `if x then`
     - `if not x then return`
     - `assert(x)`
     - 嵌套 `do ... end` 中的 guard 可见性
   - 继续保留 legacy guard 逻辑作为受控 fallback

2. **Tree-sitter Query 接入**
   - 已新增 `.scm` 查询文件用于匹配控制流节点
   - AST 入口通过 Query + `QueryCursor` 建立控制流捕获上下文

3. **结构化迁移可观测性**
   - 静态分析结果新增：
     - `analysis_mode`
     - `unknown_reason`
   - 当前支持的迁移状态：
     - `ast_primary`
     - `ast_fallback_to_legacy`
     - `legacy_only`
   - `unknown_reason` 已接入 evidence/prompt 管线

4. **结构化 Unknown（首批）**
   - 当前已能标记：
     - `unsupported_control_flow`
     - `dynamic_metatable`
     - `dynamic_index_expression`
     - `unresolved_ast_node`
   - 策略仍然保持“保守 unknown，不强行证明”

5. **Benchmark 可观测性**
   - benchmark summary 已增加：
     - `ast_primary_cases`
     - `ast_fallback_to_legacy_cases`
     - `legacy_only_cases`
   - CLI benchmark 输出已展示这些统计

6. **Stress Suite 已建立**
   - 已新增 AST 压力样例，覆盖：
     - 深层嵌套分支
     - `do ... end` 局部 shadowing
     - 循环中的保守 fallback / unknown

#### 当前结果
- 已验证 AST 能修复至少一类旧逻辑误判：
  - `do ... end` 内部局部 shadowing 不再错误打掉外层 guard
- 循环等首轮未建模控制流仍保持保守 unknown，并带结构化原因
- 全量测试通过：`336 passed`

#### 当前边界（仍然明确保持）
1. 首轮依然只做 **Guard-first**
2. **Origin/source 定位** 尚未进入 AST 主路径
3. **跨文件 AST 内联** 尚未启动
4. 更复杂的动态语义（如完整元表/闭包 upvalue）仍未建模，继续走保守策略

#### 建议的下一步
- 进入 Phase 1 的后半段验证与扩展：
  1. 用现有 benchmark + stress suite 持续观察 AST 覆盖率
  2. 评估是否开始进入 Phase 1.8 之后的扩展：
     - `elseif`
     - `repeat-until`
     - richer reachability
  3. 若覆盖率与稳定性满足预期，则按 `plan.md` 进入 **字段级路径追踪**

### 我（Phase 1 后续扩展执行结果）

已完成上一轮建议中的两个有界扩展项，并保持了 Guard-first 边界不变：

1. **`elseif` AST 化已落地**
   - `elseif username then` 现在会被 AST 主路径识别为有效正向 guard
   - 新增回归测试锁定这条行为

2. **`repeat-until` 已从“仅保守 fallback”升级为“有限证明”**
   - 对于无外层 `break` 绕过条件的 `repeat ... until symbol`
   - 若 sink 位于循环之后，AST 会产出结构化 proof：
     - `kind = loop_exit_guard`
     - `summary = repeat ... until symbol`
   - 同时把该 proof 纳入 verification 强度分级

3. **Stress Suite 已纳入 `repeat-until` 样例**
   - 新增 `provable_safe_repeat_until.lua`
   - 压力集现在同时覆盖：
     - 深嵌套 guard
     - `do ... end` shadowing
     - `repeat-until` 安全退出
     - `while/break` 的保守 unknown

#### 最新状态
- 全量测试通过：`338 passed`
- 当前仍未进入：
  - `while/for` 的 AST 安全证明
  - AST 化 origin/source 定位
  - 跨文件 AST 内联

#### 结论
- Phase 1 的 guard-first AST 基座已稳定
- `elseif` 和 `repeat-until` 这两个最自然的低风险扩展已经完成
- 下一步如果继续推进，最合理的是停止继续扩大 Phase 1 语法面，转入 `plan.md` 的下一主线：**字段级路径追踪**

### 我（Phase 2 / 3 继续推进结果）

在 Phase 1 基线稳定后，后续推进已经完成了两条主线的第一批核心能力：

1. **字段路径已成为静态分析的一等概念**
   - 不再只是 contract 过滤条件
   - 现在可直接证明：
     - `if req.params.username then ...`
     - `req.headers['x-token']` / `req.headers["x-token"]` 的规范化 guard
     - `local username = req.params.username` 继承前置 field guard
   - 新增结构化 proof：
     - `guarded_field_origin`

2. **字段路径已接入组合证明链**
   - field-path 参数现在可以参与：
     - guard helper contract
     - return-normalizer contract
     - chained wrapper / contract proof
   - 不再只停留在“第一层直接 guard”

3. **Phase 3 的轻量跨文件 AST 内联已启动并完成第一批交付**
   - 新增 AST 识别的 inline guard helper
   - 这些 helper 会被临时合成为静态层 contract，仅用于本次分析，不写回配置
   - 当前支持的受限形态：
     - `if not value then return ... end ; return value`
     - `if not value then error(...) end ; return value`
     - `assert(value) ; return value`
   - 这条能力是：
     - 单跳
     - 有界
     - AST 驱动
     - 不做全局递归过程间分析

4. **跨文件 helper 的保守边界已锁定**
   - 其他文件里的导出 helper 可被单跳内联
   - 其他文件里的 `local function` 不会被错误当成跨文件 helper
   - 当前文件内的 `local function` 仍然可被本地静态分析使用

5. **透明 / 默认化 wrapper 收集已切到 AST 优先**
   - 有 Tree-sitter 时优先按 AST 确定函数边界
   - 无法使用 AST 时才回退到旧的文本式识别

#### 最新状态
- 全量测试通过：`347 passed`
- 当前工作区目标状态：已具备继续进入更深一层 Phase 3 的基础

#### 当前仍保持的边界
- 仍然只做 **single-hop**
- 仍然不做递归 fixed-point
- 仍然不做完整跨文件 origin/source 重定位
- 更复杂 helper（副作用重、长函数体、多分支路径）仍保持保守，不会自动内联
