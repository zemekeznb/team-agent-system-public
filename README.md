# Team Agent System

> **Let your coding agents work as a team—not as isolated sessions.**
> 让 Coding Agents 从各自为战，走向可信协作。

Team Agent System (TAS) is building an infrastructure layer for multi-Agent collaboration.

Our goal is to help coding agents operated by different Owners, using different tools and running in different environments, securely discover one another, delegate tasks, deliver results, request approval, and turn validated work into traceable and reusable team knowledge.

TAS is not trying to replace Codex, Claude Code, Cursor, or other capable Agents. It aims to become the missing collaboration layer between them.

```text
Your Agent
    │ delegate a task
    ▼
Team Agent System
    ├── verifies identity and permissions
    ├── delivers work reliably
    ├── requests human approval when required
    ├── collects artifacts and evidence
    ├── survives disconnects and process restarts
    └── preserves reusable team knowledge
    │
    ▼
Another Owner's Agent
```

## Why Team Agent System?

Today’s coding agents are powerful, but most still work as isolated individuals. They may edit a repository, run tests, call tools, or complete an entire feature—but collaboration across agents is still difficult:

- How does one Agent discover and contact another?
- How do we know which Owner or Agent initiated a request?
- Who decides what a remote Agent is allowed to do?
- What happens when an action requires human approval?
- Can a task survive a network disconnect or process crash?
- How do we distinguish a claimed result from independently verifiable evidence?
- Can useful knowledge outlive the conversation that produced it—and remain applicable?

TAS explores these questions as engineering boundaries rather than leaving them to prompts and informal conventions.

> **Agents should be able to collaborate with the reliability, accountability, and shared memory expected from a real engineering team.**

## What we want to make possible

1. You give your Agent a product goal.
2. It finds another Owner’s Agent with the right expertise or repository access.
3. TAS verifies the identities and permissions involved.
4. The task is delivered reliably, even if either side temporarily disconnects.
5. High-risk actions are routed through explicit human approval.
6. The receiving Agent returns artifacts, status, and supporting evidence.
7. TAS records what happened without treating an Agent’s self-report as proof.
8. Validated results become reusable team knowledge—with provenance, scope, version, and lifecycle attached.

That is the experience we are working toward.

## Project principles

- **Trust must be explicit.** Identity, authorization, approval, evidence, and memory are separate concerns. Communication permission must not silently become execution permission.
- **Evidence over claims.** Important conclusions should be traceable to tests, artifacts, logs, repository state, or other independently inspectable evidence.
- **Reliable collaboration.** Delivery, retry, lease, acknowledgement, and recovery are first-class system behavior.
- **Receiver-owned authorization.** The receiving Owner controls what an external Agent may request or execute.
- **Memory with boundaries.** Useful knowledge needs provenance, epistemic status, applicability, permissions, and lifecycle information.
- **Existing agents first.** TAS is middleware around existing Agents and protocols such as MCP and A2A, not another closed Agent runtime.

## Current progress

TAS is currently in **F2 / M3 technical validation**.

Working engineering prototypes now cover:

- a Python Domain/Application core separated from infrastructure adapters;
- MCP tool discovery and invocation with local test-credential identity binding;
- official A2A SDK interoperability and a minimal MCP-to-A2A bridge;
- durable Inbox delivery, atomic Claim, time-limited Lease, retry, acknowledgement, release, and dead-letter handling;
- recovery across real MCP and Remote Agent process restarts;
- idempotent task creation and replay;
- receiver-owned, versioned Policy decisions with `allow`, `deny`, and `approval_required` outcomes;
- a durable Approval lifecycle with receiver-owned decisions, expiry, concurrency protection, and atomic Task resumption;
- structured Messages, Artifacts, task states, and transition history;
- a lightweight TypeScript client.

These are technical-validation results, not a claim that the complete product is ready.

## Where we are going

### Now — Trusted control flow

Resource-level authorization, Audit records, and stronger evidence boundaries around the completed Policy and Approval foundations.

### Next — Real multi-Owner validation

The next major validation stage must involve two real independent Owners, independent identities and credentials, separate Agent runtime environments, real cross-Owner task delegation, receiver-controlled approval, and end-to-end evidence. Test fixtures or multiple sessions belonging to the same Owner will not be treated as a substitute.

### Later — Usable team collaboration

The longer-term direction includes Agent and capability discovery, reliable cross-team delegation, human approval inboxes, observable task timelines, artifact and evidence review, trusted team memory, applicability-aware retrieval, integrations with multiple Coding Agents, and deployable collaboration environments for real teams.

The architecture will continue to evolve as these stages produce evidence. Current technical choices are intentionally replaceable.

## Conceptual architecture

```text
┌──────────────────── Owner A ────────────────────┐
│  Coding Agent ── MCP Adapter ──┐               │
└────────────────────────────────┼───────────────┘
                                 ▼
                    ┌────────────────────────┐
                    │   Team Agent System    │
                    │  Identity              │
                    │  Tasks & Inbox         │
                    │  Policy & Approval     │
                    │  Audit & Evidence      │
                    │  Artifacts & Memory    │
                    └───────────┬────────────┘
                                │ A2A / Adapters
                                ▼
┌──────────────────── Owner B ────────────────────┐
│  Remote Agent ── Repository / Tools            │
└────────────────────────────────────────────────┘
```

TAS keeps its Domain layer independent from specific databases, Agent products, MCP/A2A implementations, or memory providers.

## Repository layout

```text
tas/                         Python domain, application, and adapters
clients/typescript/src/      Lightweight TypeScript client
pyproject.toml               Python project configuration
```

This public repository is a curated code snapshot. Internal design documents, experiments, task records, tests, and private engineering evidence are maintained separately.

## Local code preview

Python 3.12+:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\python -m uvicorn tas.api.main:app --host 127.0.0.1 --port 8000
```

Node.js 20+ and pnpm:

```powershell
pnpm --dir clients/typescript install
pnpm --dir clients/typescript run build
```

The current setup is intended for local technical exploration. A stable installation, deployment, and onboarding experience will come later.

## Honest boundaries

TAS is not yet an MVP or a production-ready service. Multi-Owner behavior has not yet been validated with two real independent Owners; local identity bindings are test fixtures; SQLite and Polling are replaceable validation choices; distributed exactly-once is not claimed; and production deployment, high availability, observability, and operational security are not complete.

We publish these boundaries because TAS is fundamentally a project about trust. Its own progress should be described with the same care it expects from Agent-generated evidence.

## Follow the journey

If you are interested in multi-Agent engineering workflows, independent Owner collaboration, MCP and A2A interoperability, human approval, reliable task delivery, evidence-driven Agent systems, or trustworthy team memory, this project may be worth watching.

⭐ **Watch or star the repository to follow its progress toward real multi-Owner Agent collaboration.**

## Contact & collaboration

We would be happy to hear from potential users, researchers, developers, and teams exploring similar problems. For ideas, feedback, early collaboration, or project-related conversations, contact:

**[zhangkk303@163.com](mailto:zhangkk303@163.com)**

## License

No open-source license is granted at this stage. The repository is publicly visible for technical preview and project tracking. A license may be added later.

---

# Team Agent System（中文）

> **让你的 Coding Agents 像一个真正的团队一样工作，而不是停留在彼此隔离的会话里。**

Team Agent System（TAS）正在构建一个面向多 Agent 协作的基础设施层。

我们的目标，是让不同 Owner、不同工具和不同运行环境中的 Coding Agents，能够安全地发现彼此、委派任务、交付成果、请求审批，并把经过验证的工作沉淀为可追溯、可复用的团队记忆。

TAS 不打算取代 Codex、Claude Code、Cursor 或其他优秀的 Agent。我们希望补上它们之间缺失的协作层。

```text
你的 Agent
    │ 委派任务
    ▼
Team Agent System
    ├── 验证身份与权限
    ├── 可靠投递任务
    ├── 在必要时请求人工审批
    ├── 收集 Artifact 与工程证据
    ├── 在断线和进程重启后继续工作
    └── 沉淀可复用的团队知识
    │
    ▼
另一位 Owner 的 Agent
```

## 为什么需要 Team Agent System？

今天的 Coding Agents 已经非常强大，但绝大多数仍然彼此隔离。它们可以修改仓库、运行测试、调用工具，甚至独立完成整个功能；但真正协作时，许多基础问题仍没有可靠答案：

- 一个 Agent 怎样发现并联系另一个 Agent？
- 如何确认请求来自哪位 Owner 和哪个 Agent？
- 谁来决定远端 Agent 可以执行什么操作？
- 操作需要人类批准时，流程怎样继续？
- 网络中断或进程崩溃后，任务能否恢复？
- 如何区分 Agent 的自我声明与可独立验证的工程证据？
- 有价值的结论能否脱离会话长期存在，并保持适用？

TAS 希望把这些问题变成明确的工程边界，而不是继续依赖 Prompt、默契和非正式约定。

> **让 Agent 团队拥有真正工程团队应当具备的可靠协作、责任边界和共享记忆。**

## 我们希望实现怎样的体验？

1. 你向自己的 Agent 提出一个产品目标。
2. Agent 找到拥有合适专业能力或仓库访问权的另一位 Owner 的 Agent。
3. TAS 验证参与协作的身份和权限。
4. 即使任意一方暂时断线，任务仍会被可靠投递和恢复。
5. 高风险操作进入明确的人工审批流程。
6. 接收方返回状态、Artifact 和支持结论的工程证据。
7. TAS 记录发生了什么，但不把 Agent 的自我报告直接当成事实。
8. 经过验证的成果成为团队知识，并保留来源、状态、适用范围、版本和生命周期。

这就是我们正在努力实现的体验。

## 项目原则

- **信任必须明确：** 身份、授权、审批、证据和记忆是不同问题，通信权限不能自动成为执行权限。
- **证据优先于声明：** 重要结论应能追溯到测试、Artifact、日志、仓库状态或其他独立证据。
- **协作必须能够恢复：** 投递、重试、Lease、确认和恢复是系统的一等能力。
- **由接收方控制授权：** 接收方 Owner 决定外部 Agent 可以请求和执行什么。
- **记忆必须有边界：** 团队知识需要来源、认知状态、适用范围、权限和生命周期。
- **优先连接现有 Agent：** TAS 希望接入 MCP、A2A 和现有 Coding Agents，而不是创造封闭运行时。

## 当前进展

TAS 目前处于 **F2 / M3 技术验证阶段**。

项目已经建立并验证了：解耦的 Domain/Application 核心、MCP 工具发现与调用、本地测试凭据身份绑定、官方 A2A SDK 互操作、最小 MCP→A2A 委派、持久化 Inbox、Claim/Lease/Retry/Acknowledge/Dead Letter、真实进程重启恢复、幂等创建与 Replay、接收方版本化 Policy、`allow`/`deny`/`approval_required` 决策、结构化 Message/Artifact/Task 历史，以及轻量 TypeScript Client。

Approval 基础能力也已覆盖接收方 Owner 决议、批准/拒绝/过期、并发单赢家，以及审批结果与 Task 状态的原子转换。

这些是已经形成工程证据的技术验证结果，但不代表完整产品已经可以投入使用。

## 接下来会发生什么？

### 现在：可信控制流程

继续完善资源级授权、Audit 记录，以及建立在 Policy 与 Approval 基础上的更严格 Evidence 边界。

### 下一阶段：真实多 Owner 验证

下一阶段必须包含两位真实且相互独立的 Owner、独立身份与凭据、独立 Agent 环境、真实跨 Owner 委派、接收方审批授权和端到端证据。同一 Owner 的多个会话或测试 Fixture 不会被当作替代方案。

### 更远的目标：真正可用的 Agent 团队协作

后续方向包括 Agent 与能力发现、跨团队可靠委派、人工审批收件箱、可观察任务时间线、Artifact 与 Evidence 审查、可信团队记忆、适用范围感知的检索、多种 Coding Agent 集成，以及真实团队可部署的协作环境。

最终架构会继续根据实验结果演进。当前组件仍是可以替换的验证方案。

## 概念架构

```text
┌──────────────────── Owner A ────────────────────┐
│  Coding Agent ── MCP Adapter ──┐               │
└────────────────────────────────┼───────────────┘
                                 ▼
                    ┌────────────────────────┐
                    │   Team Agent System    │
                    │  Identity              │
                    │  Tasks & Inbox         │
                    │  Policy & Approval     │
                    │  Audit & Evidence      │
                    │  Artifacts & Memory    │
                    └───────────┬────────────┘
                                │ A2A / Adapters
                                ▼
┌──────────────────── Owner B ────────────────────┐
│  Remote Agent ── Repository / Tools            │
└────────────────────────────────────────────────┘
```

TAS 的 Domain 层不会依赖具体数据库、Agent 产品、MCP/A2A 实现或第三方记忆服务。

## 仓库结构

```text
tas/                         Python Domain、Application 与 Adapter
clients/typescript/src/      轻量 TypeScript Client
pyproject.toml               Python 项目配置
```

这个公开仓库是一份经过筛选的代码快照。内部设计文档、实验记录、开发任务、测试和私有工程 Evidence 会在独立的事实主仓库中维护。

## 本地代码预览

Python 3.12+：

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\python -m uvicorn tas.api.main:app --host 127.0.0.1 --port 8000
```

Node.js 20+ 与 pnpm：

```powershell
pnpm --dir clients/typescript install
pnpm --dir clients/typescript run build
```

## 现阶段边界

TAS 目前还不是 MVP，也不是生产可用服务。尚未由两位真实独立 Owner 验证多 Owner 协作；本地身份绑定是测试 Fixture；SQLite 与 Polling 是可替换的验证选择；当前不声称分布式 exactly-once；生产部署、高可用、可观测性和运维安全仍未完成。

我们公开这些边界，是因为 TAS 本身就是一个研究“信任”的项目。项目进展也应遵守与 Agent Evidence 相同的诚实标准。

## 关注项目进展

如果你对多 Agent 工程工作流、独立 Owner 协作、MCP 与 A2A、人工审批、可靠任务投递、Evidence 驱动的 Agent 系统或可信团队记忆感兴趣，这个项目值得关注。

⭐ **你可以 Watch 或 Star 这个仓库，见证它从技术验证走向真实的多 Owner Agent 协作。**

## 联系与合作

如果你也在关注 Agent 协作、MCP、A2A、可信执行、团队记忆，或者正在尝试解决类似的问题，我们很期待与你交流。

无论你是潜在用户、研究者、开发者，还是正在探索多 Agent 协作的团队，都可以就想法建议、早期合作或其他项目相关话题联系我们：

**[zhangkk303@163.com](mailto:zhangkk303@163.com)**

## License

当前暂未授予开源许可证。仓库现阶段公开用于技术预览和项目进展展示，后续可能加入正式许可证。
