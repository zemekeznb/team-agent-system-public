# Team Agent System

> **Move coding agents owned by different people, built by different vendors, and running in different environments from isolated sessions toward trusted collaboration.**

Team Agent System (TAS) is middleware for agent collaboration and trustworthy team memory.

It does not replace Codex, Claude Code, Cursor, or other agents, and it does not require them to share one runtime. TAS provides the missing boundaries between them: identity, tasks, authorization, evidence, and memory.

> **Requests may cross Owner boundaries. Execution authority, factual judgment, and responsibility must not travel with them.**

**Current status: F2 / M6 technical validation. TAS is not an MVP or a production-ready service, and it has not yet completed end-to-end validation with two real independent Owners.**

## How one collaboration should work

```text
Owner A's Agent
Codex / MCP / Environment A
        │
        │ sends a request with identity, code version, and impact scope
        ▼
┌────────────────────────────────────┐
│         Team Agent System          │
│                                    │
│  verifies identity and relations   │
│  delivers the task reliably        │
│  applies the receiver's Policy     │
│  asks Owner B when approval is due │
│  records Actions and Evidence      │
│  separates claims from observations │
└────────────────┬───────────────────┘
                 │
                 ▼
Owner B's Agent
Another Agent product / Environment B
        │
        │ performs the task and returns results
        ▼
Work Records with provenance, evidence, and version scope
        │
        ▼
Validated results can become reusable team memory
```

This is the complete experience TAS is working toward. Only part of its engineering foundation has been validated so far.

## What problems does TAS address?

### 1. Work impact should reach the relevant Agent

A frontend Agent should not need to wait for a broken build to learn that a backend API changed. TAS aims to route structured impact events bound to a Commit and Evidence. Events must still come from an Agent, Adapter, or integration—TAS cannot know that code changed on its own.

### 2. Authorization must not propagate across Owners

Agent A may ask Agent B to act, but it cannot approve on behalf of Owner B. Communication permission is not execution permission. An Approval is bound to a precise Action, Scope, Policy Version, and expiry, and its Grant can be consumed only once. TAS does not replace the host Agent's own permission prompt.

### 3. An Agent claim is not an engineering fact

“Tests passed” and an observed result such as “exit code 0, 12 passed” are separate records. Conflicts are not silently merged, and confidence alone cannot turn a claim into a validated conclusion.

### 4. Team knowledge needs version and applicability boundaries

Whether an old conclusion remains useful depends on the Commit, paths, and environment in which it was validated. After relevant code changes, it should be marked `possibly_stale` instead of being injected as current fact.

## Current validation progress

| Capability | Status | Current evidence scope |
|---|---|---|
| MCP and A2A connectivity | Validated in F2 | Real local Codex process, official A2A SDK, test identity |
| Task delivery and recovery | Validated in F2 | Inbox, Lease, Retry, ACK, process restart |
| Policy, Approval, and Audit | Validated in F2 | Automated permission matrix and local fixtures |
| Single-use authorization and execution reconciliation | Validated in F2 | Approval Grant, Action Receipt, execution-time checks |
| Git and test Evidence | Validated in F2 | Controlled local Worktree and subprocess |
| Claim / observed-fact separation | Validated in F2 | Append-only Work Records and Evidence snapshots |
| Epistemic Status | Validated in F2 | Append-only history and one controlled adversarial test-result rule |
| Team Memory and applicability-aware retrieval | Validated in F2 | Validated Work Record promotion, scoped retrieval, Git staleness, explicit supersession |
| Two-real-Owner collaboration | Not run | Required in F3 |
| Production deployment | Not implemented | No production-readiness claim |

“Validated in F2” only means that specific assertions have engineering evidence in a controlled local environment. It does not validate user value, real Owner intent, or production readiness.

## What comes next

- **Build M6:** connect the validated components in a repeatable FastAPI + TypeScript technical integration scenario, including failure recovery.
- **Enter F3:** run end-to-end collaboration with two real independent Owners, credentials, and Agent environments.
- **Continue evolving:** build a controlled Agent directory, impact routing, approval experience, Evidence review, and applicability-aware Team Memory.

Multiple sessions, Agents, Worktrees, or test fixtures belonging to one Owner are not substitutes for real multi-Owner validation.

## Follow and participate

TAS is still early. We are publishing not only what works, but also unvalidated assumptions, failed experiments, and explicit boundaries.

If you are exploring heterogeneous-agent collaboration, cross-Owner authorization, MCP, A2A, engineering Evidence, or trustworthy team memory, you are welcome to Watch, Star, or join the discussion.

⭐ **Follow TAS as it moves from technical validation toward real multi-Owner Agent collaboration.**

For use cases, product feedback, technical discussion, early collaboration, or related research:

**[zhangkk303@163.com](mailto:zhangkk303@163.com)**

## License

No open-source license is granted at this stage. This repository is publicly visible for technical preview and project tracking. A license may be added later.

---

# Team Agent System

> **让不同 Owner、不同产品和不同运行环境中的 Coding Agents，从彼此隔离的会话走向可信协作。**

Team Agent System（TAS）是一个协作与可信记忆中间件。

它不替代 Codex、Claude Code、Cursor 或其他 Agent，也不要求它们共享同一种运行时。TAS 补上的是这些 Agent 之间缺失的身份、任务、授权、证据和记忆边界。

> **请求可以跨越 Owner 边界，但执行权、事实判断和责任不能随请求一起传播。**

**当前状态：F2 / M6 技术验证阶段。不是 MVP，不是生产可用服务，尚未由两位真实独立 Owner 完成端到端验证。**

## 一次协作如何发生

```text
Owner A 的 Agent
Codex / MCP / Environment A
        │
        │ 发布带身份、代码版本和影响范围的协作请求
        ▼
┌────────────────────────────────────┐
│         Team Agent System          │
│                                    │
│  验证身份与协作关系                │
│  可靠投递任务                      │
│  执行接收方 Policy                 │
│  必要时请求接收方 Owner 批准       │
│  记录 Action、Artifact 与 Evidence │
│  区分 Agent 声明和观察事实         │
└────────────────┬───────────────────┘
                 │
                 ▼
Owner B 的 Agent
另一种 Agent 产品 / Environment B
        │
        │ 执行任务并返回结果
        ▼
带来源、证据和版本边界的 Work Record
        │
        ▼
经过验证后，成为可复用的团队记忆
```

这是 TAS 正在构建的完整目标体验。当前已完成其中部分工程基线。

## TAS 解决什么问题

### 1. 工作影响到达相关 Agent

后端修改了 API，前端不该等到构建失败才知道。TAS 希望用绑定 Commit 和 Evidence 的结构化事件，将影响投递给相关 Agent。事件必须由 Agent、Adapter 或集成入口产生，TAS 不会凭空知道代码发生了变化。

### 2. 跨 Owner 授权不能传播

Agent A 可以请求 Agent B 做事，但不能替 Owner B 批准。通信权限不等于执行权限；Approval 绑定具体 Action、Scope、Policy Version 和有效期，只能消费一次。TAS 不替代宿主 Agent 自己的权限提示。

### 3. Agent 声明不等于工程事实

Agent 说“测试通过”，与 TAS 采集到“退出码 0、12 passed”是两条记录。两者冲突时不会被静默合并，也不会因为 Agent 表达得很有信心就自动成为 validated。

### 4. 团队经验需要版本边界

一条经验在哪个 Commit、哪个文件范围和什么环境中得到验证，决定了它现在是否仍然适用。代码变化后，旧结论应提示 `possibly_stale`，而不是继续作为当前事实注入。

## 当前验证进展

| 能力 | 状态 | 当前证据范围 |
|---|---|---|
| MCP 与 A2A 接入 | F2 已验证 | 真实 Codex、官方 A2A SDK、本机测试身份 |
| Task 投递与恢复 | F2 已验证 | Inbox、Lease、Retry、ACK、进程重启 |
| Policy、Approval 与 Audit | F2 已验证 | 自动化权限矩阵和本地 Fixture |
| 单次授权与执行对账 | F2 已验证 | Approval Grant、Action Receipt、执行前复核 |
| Git/Test Evidence | F2 已验证 | 本机受控 Worktree 与 subprocess |
| Claim 与 observed fact 分离 | F2 已验证 | append-only Work Record 与 Evidence snapshot |
| Epistemic Status | F2 已验证 | append-only 历史与一条受控测试结果对抗规则 |
| Team Memory 与适用性检索 | F2 已验证 | validated Work Record 提升、范围检索、Git 过期检测与显式替代 |
| 两个真实 Owner 协作 | 尚未运行 | F3 强制验证项 |
| 生产部署 | 尚未完成 | 不声称生产可用 |

“F2 已验证”只表示相关断言在本机受控环境中形成了工程证据，不代表真实用户价值、真实 Owner 授权意图或生产能力已经得到验证。

## 接下来会发生什么

- **推进 M6：** 在可重复的 FastAPI + TypeScript 技术集成场景中连接已验证组件，并覆盖失败恢复。
- **进入 F3：** 由两位真实独立 Owner，使用独立身份、凭据和 Agent 环境完成端到端协作。
- **继续演进：** 推进受控 Agent 目录、影响路由、审批体验、Evidence 审查和带适用范围的 Team Memory。

同一 Owner 的多个会话、Agent、Worktree 或测试 Fixture，都不能替代真实多 Owner 验证。

## 关注与参与

TAS 仍处于早期阶段。我们公开的不只是已经完成的能力，也包括尚未验证的假设、失败实验和明确边界。

如果你也在关注异构 Agent 协作、跨 Owner 授权、MCP、A2A、工程 Evidence 或可信团队记忆，欢迎 Watch、Star 或参与讨论。

⭐ **和我们一起见证 TAS 从技术验证走向真实的多 Owner Agent 协作。**

关于使用场景、产品建议、技术讨论、早期合作或相似项目研究，可以通过邮件联系我们：

**[zhangkk303@163.com](mailto:zhangkk303@163.com)**

## License

当前暂未授予开源许可证。仓库现阶段公开用于技术预览和项目进展展示，后续可能加入正式许可证。
