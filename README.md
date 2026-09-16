# Team Agent System

> Public code preview · Technical validation in progress

Team Agent System (TAS) is an evidence-driven collaboration and trusted team-memory middleware concept for independently operated coding agents. It explores how existing agents can communicate through MCP and A2A while keeping identity, authorization, durable delivery, evidence, and memory as explicit system boundaries.

## Current status

The project is currently in **F2 / M3 technical validation**.

What this public snapshot currently demonstrates:

- a Python domain and application core separated from MCP, A2A, and SQLite adapters;
- an MCP server that binds the caller identity from local test credentials;
- official A2A SDK interoperability and a minimal MCP-to-A2A bridge;
- durable Inbox polling, Lease, retry, acknowledgement, and crash recovery primitives;
- receiver-owned, versioned Policy decisions with `allow`, `deny`, and `approval_required` outcomes;
- a small TypeScript client for health and local test-session calls.

What it does **not** claim:

- multi-Owner behavior has not yet been validated with two real independent Owners;
- this is not an MVP or a production-ready service;
- local SQLite, polling, static test credentials, and the current adapters are replaceable validation choices, not final architecture commitments;
- the current code does not guarantee distributed exactly-once execution or production-grade authentication and authorization.

Internal design documents, experiment records, evidence, development tasks, and tests are intentionally not included in this public repository. This repository is a curated code snapshot rather than the system of record.

## Repository layout

```text
tas/                         Python domain, application, and adapters
clients/typescript/src/      TypeScript client source
pyproject.toml               Python package metadata
```

## Local code preview

Python 3.12+:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\python -m uvicorn tas.api.main:app --host 127.0.0.1 --port 8000
```

TypeScript client (Node.js 20+ and pnpm):

```powershell
pnpm --dir clients/typescript install
pnpm --dir clients/typescript run build
```

No open-source license is granted at this stage. A license may be added later.

---

# Team Agent System（中文）

> 公开代码预览 · 正在进行技术验证

Team Agent System（TAS）是一个面向独立 Coding Agent 的、以工程证据驱动协作并构建可信团队记忆的中间件概念。项目探索如何复用 MCP 与 A2A，让现有 Agent 在身份、授权、可靠投递、证据和记忆边界明确的前提下进行协作。

## 当前阶段

项目目前处于 **F2 / M3 技术验证阶段**。

当前公开代码已经展示：

- 与 MCP、A2A、SQLite Adapter 解耦的 Python Domain/Application 核心；
- 从本地测试凭据绑定调用者身份的 MCP Server；
- 官方 A2A SDK 互操作与最小 MCP→A2A Bridge；
- Durable Inbox、Poll、Lease、Retry、Acknowledge 和进程崩溃恢复基础能力；
- 由接收方 Owner Policy 决定的版本化 `allow`、`deny`、`approval_required`；
- 用于健康检查和本地测试 Session 的轻量 TypeScript Client。

当前明确**不能**声称：

- 尚未由两个真实、独立 Owner 完成多 Owner 验证；
- 尚未完成 MVP，也不是生产可用服务；
- SQLite、Polling、静态测试凭据和现有 Adapter 都只是可替换的验证选择，不是最终架构承诺；
- 尚不保证分布式 exactly-once，也未实现生产级认证与授权。

内部设计文档、实验记录、Evidence、开发任务和测试不会进入公开仓库。该仓库只是经过筛选的公开代码快照，不是项目的事实主仓库。

## 目录

```text
tas/                         Python Domain、Application 与 Adapter
clients/typescript/src/      TypeScript Client 源码
pyproject.toml               Python 包配置
```

## 本地预览

Python 3.12+：

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\python -m uvicorn tas.api.main:app --host 127.0.0.1 --port 8000
```

TypeScript Client（Node.js 20+ 与 pnpm）：

```powershell
pnpm --dir clients/typescript install
pnpm --dir clients/typescript run build
```

当前暂未授予开源许可证，后续可能补充。
