"""Infrastructure-independent Owner policy evaluation primitives."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum

from tas.domain.collaboration import TaskId
from tas.domain.idempotency import IdempotencyKey, RequestFingerprint
from tas.domain.identity import AgentId, OwnerId, ProjectId, TeamId


class Action(str, Enum):
    COMMUNICATE = "communicate"
    READ_METADATA = "read_metadata"
    READ_CONTENT = "read_content"
    ANALYZE = "analyze"
    MODIFY_WORKSPACE = "modify_workspace"
    COMMIT = "commit"
    PUSH = "push"
    MERGE = "merge"
    DEPLOY = "deploy"


class Risk(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class PolicyOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


class PolicyReason(str, Enum):
    RULE_ALLOWED = "rule_allowed"
    RULE_DENIED = "rule_denied"
    RULE_REQUIRES_APPROVAL = "rule_requires_approval"
    RISK_EXCEEDS_AUTO_ALLOW = "risk_exceeds_auto_allow"
    ACTION_NOT_CONFIGURED = "action_not_configured"
    POLICY_OWNER_MISMATCH = "policy_owner_mismatch"


def _require_text(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 255:
        raise ValueError(f"{field} must be 1..255 non-whitespace characters")


@dataclass(frozen=True, slots=True)
class ActionIntent:
    requester_agent_id: AgentId
    requester_owner_id: OwnerId
    receiving_agent_id: AgentId
    receiving_owner_id: OwnerId
    team_id: TeamId
    project_id: ProjectId
    repository: str
    action: Action
    scope: str
    risk: Risk
    task_id: TaskId | None = None

    def __post_init__(self) -> None:
        for value, expected, field in (
            (self.requester_agent_id, AgentId, "requester_agent_id"),
            (self.requester_owner_id, OwnerId, "requester_owner_id"),
            (self.receiving_agent_id, AgentId, "receiving_agent_id"),
            (self.receiving_owner_id, OwnerId, "receiving_owner_id"),
            (self.team_id, TeamId, "team_id"),
            (self.project_id, ProjectId, "project_id"),
        ):
            if not isinstance(value, expected):
                raise TypeError(f"{field} must be {expected.__name__}")
        if not isinstance(self.action, Action):
            raise TypeError("action must be Action")
        if not isinstance(self.risk, Risk):
            raise TypeError("risk must be Risk")
        if self.task_id is not None and not isinstance(self.task_id, TaskId):
            raise TypeError("task_id must be TaskId or None")
        _require_text(self.repository, "repository")
        _require_text(self.scope, "scope")


@dataclass(frozen=True, slots=True)
class PolicyRule:
    action: Action
    outcome: PolicyOutcome
    max_auto_risk: Risk = Risk.LOW

    def __post_init__(self) -> None:
        if not isinstance(self.action, Action):
            raise TypeError("action must be Action")
        if not isinstance(self.outcome, PolicyOutcome):
            raise TypeError("outcome must be PolicyOutcome")
        if not isinstance(self.max_auto_risk, Risk):
            raise TypeError("max_auto_risk must be Risk")


@dataclass(frozen=True, slots=True)
class OwnerPolicy:
    owner_id: OwnerId
    version: str
    rules: tuple[PolicyRule, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.owner_id, OwnerId):
            raise TypeError("owner_id must be OwnerId")
        _require_text(self.version, "version")
        if not isinstance(self.rules, tuple) or not all(
            isinstance(rule, PolicyRule) for rule in self.rules
        ):
            raise TypeError("rules must be a tuple of PolicyRule")
        actions = [rule.action for rule in self.rules]
        if len(actions) != len(set(actions)):
            raise ValueError("policy cannot contain duplicate Action rules")


@dataclass(frozen=True, slots=True)
class PolicyMutationContext:
    owner_id: OwnerId
    operation: str
    key: IdempotencyKey
    fingerprint: RequestFingerprint

    def __post_init__(self) -> None:
        if not isinstance(self.owner_id, OwnerId):
            raise TypeError("owner_id must be OwnerId")
        _require_text(self.operation, "operation")
        if not isinstance(self.key, IdempotencyKey):
            raise TypeError("key must be IdempotencyKey")
        if not isinstance(self.fingerprint, RequestFingerprint):
            raise TypeError("fingerprint must be RequestFingerprint")


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    outcome: PolicyOutcome
    reason: PolicyReason
    policy_owner_id: OwnerId
    policy_version: str
    intent: ActionIntent


class PolicyEngine:
    def authorize(
        self, intent: ActionIntent, policy: OwnerPolicy
    ) -> AuthorizationDecision:
        if not isinstance(intent, ActionIntent):
            raise TypeError("intent must be ActionIntent")
        if not isinstance(policy, OwnerPolicy):
            raise TypeError("policy must be OwnerPolicy")
        if policy.owner_id != intent.receiving_owner_id:
            return self._decision(
                intent, policy, PolicyOutcome.DENY, PolicyReason.POLICY_OWNER_MISMATCH
            )
        rule = next((rule for rule in policy.rules if rule.action is intent.action), None)
        if rule is None:
            return self._decision(
                intent, policy, PolicyOutcome.DENY, PolicyReason.ACTION_NOT_CONFIGURED
            )
        if rule.outcome is PolicyOutcome.DENY:
            reason = PolicyReason.RULE_DENIED
        elif rule.outcome is PolicyOutcome.APPROVAL_REQUIRED:
            reason = PolicyReason.RULE_REQUIRES_APPROVAL
        elif intent.risk > rule.max_auto_risk:
            return self._decision(
                intent,
                policy,
                PolicyOutcome.APPROVAL_REQUIRED,
                PolicyReason.RISK_EXCEEDS_AUTO_ALLOW,
            )
        else:
            reason = PolicyReason.RULE_ALLOWED
        return self._decision(intent, policy, rule.outcome, reason)

    @staticmethod
    def _decision(
        intent: ActionIntent,
        policy: OwnerPolicy,
        outcome: PolicyOutcome,
        reason: PolicyReason,
    ) -> AuthorizationDecision:
        return AuthorizationDecision(
            outcome=outcome,
            reason=reason,
            policy_owner_id=policy.owner_id,
            policy_version=policy.version,
            intent=intent,
        )
