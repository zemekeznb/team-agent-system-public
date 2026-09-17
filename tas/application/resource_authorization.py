"""Server-side resource relationship checks before Owner policy evaluation."""

from dataclasses import dataclass
from enum import StrEnum

from tas.domain.policy import (
    ActionIntent,
    AuthorizationDecision,
    OwnerPolicy,
    PolicyEngine,
    PolicyOutcome,
)
from tas.domain.ports import IdentityRepository, ResourceRepository


class ResourceAuthorizationReason(StrEnum):
    POLICY_EVALUATED = "policy_evaluated"
    REQUESTER_IDENTITY_MISMATCH = "requester_identity_mismatch"
    RECEIVER_IDENTITY_MISMATCH = "receiver_identity_mismatch"
    PROJECT_NOT_FOUND = "project_not_found"
    TEAM_MISMATCH = "team_mismatch"
    REQUESTER_NOT_TEAM_MEMBER = "requester_not_team_member"
    RECEIVER_NOT_TEAM_MEMBER = "receiver_not_team_member"
    REPOSITORY_NOT_FOUND = "repository_not_found"
    REPOSITORY_PROJECT_MISMATCH = "repository_project_mismatch"
    REPOSITORY_OWNER_MISMATCH = "repository_owner_mismatch"


@dataclass(frozen=True, slots=True)
class ResourceAuthorizationResult:
    outcome: PolicyOutcome
    reason: ResourceAuthorizationReason
    intent: ActionIntent
    policy_decision: AuthorizationDecision | None = None


class ResourceAuthorizationService:
    def __init__(self, identities: IdentityRepository, resources: ResourceRepository) -> None:
        self.identities = identities
        self.resources = resources

    def authorize(
        self, intent: ActionIntent, policy: OwnerPolicy
    ) -> ResourceAuthorizationResult:
        requester = self.identities.get_agent(intent.requester_agent_id)
        if requester is None or requester.owner_id != intent.requester_owner_id:
            return self._deny(
                intent, ResourceAuthorizationReason.REQUESTER_IDENTITY_MISMATCH
            )
        receiver = self.identities.get_agent(intent.receiving_agent_id)
        if receiver is None or receiver.owner_id != intent.receiving_owner_id:
            return self._deny(intent, ResourceAuthorizationReason.RECEIVER_IDENTITY_MISMATCH)
        project = self.identities.get_project(intent.project_id)
        if project is None:
            return self._deny(intent, ResourceAuthorizationReason.PROJECT_NOT_FOUND)
        if project.team_id != intent.team_id:
            return self._deny(intent, ResourceAuthorizationReason.TEAM_MISMATCH)
        if self.identities.get_membership(project.team_id, requester.owner_id) is None:
            return self._deny(intent, ResourceAuthorizationReason.REQUESTER_NOT_TEAM_MEMBER)
        if self.identities.get_membership(project.team_id, receiver.owner_id) is None:
            return self._deny(intent, ResourceAuthorizationReason.RECEIVER_NOT_TEAM_MEMBER)
        binding = self.resources.get_repository(intent.repository)
        if binding is None:
            return self._deny(intent, ResourceAuthorizationReason.REPOSITORY_NOT_FOUND)
        if binding.project_id != project.id:
            return self._deny(intent, ResourceAuthorizationReason.REPOSITORY_PROJECT_MISMATCH)
        if binding.controlling_owner_id != receiver.owner_id:
            return self._deny(intent, ResourceAuthorizationReason.REPOSITORY_OWNER_MISMATCH)
        decision = PolicyEngine().authorize(intent, policy)
        return ResourceAuthorizationResult(
            decision.outcome,
            ResourceAuthorizationReason.POLICY_EVALUATED,
            intent,
            decision,
        )

    @staticmethod
    def _deny(
        intent: ActionIntent, reason: ResourceAuthorizationReason
    ) -> ResourceAuthorizationResult:
        return ResourceAuthorizationResult(PolicyOutcome.DENY, reason, intent)
