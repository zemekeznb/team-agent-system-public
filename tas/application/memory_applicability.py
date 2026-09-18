"""Build code applicability scope only from canonical Git Evidence."""
import json
from tas.domain.identity import DomainValidationError
from tas.domain.memory import MemoryCodeScope, TeamMemory
from tas.domain.work_record import ObservedEvidenceKind, WorkRecord

def code_scope_from_git_evidence(memory: TeamMemory, record: WorkRecord, *, evidence_id) -> MemoryCodeScope:
    if memory.source_work_record_id != record.id or evidence_id not in memory.evidence_ids:
        raise DomainValidationError("Git Evidence must be cited by the promoted validation")
    evidence = next((item for item in record.observed if item.id == evidence_id), None)
    if evidence is None or evidence.kind is not ObservedEvidenceKind.GIT:
        raise DomainValidationError("code scope requires cited Git Evidence")
    payload = json.loads(evidence.payload_json)
    try:
        repository, ref, commit, files = payload["repository"], payload["branch"], payload["head_commit"], payload["files"]
        paths = tuple(sorted(item["path"] for item in files))
    except (KeyError, TypeError) as error:
        raise DomainValidationError("Git Evidence cannot form code scope") from error
    if ref is None:
        raise DomainValidationError("detached Git Evidence requires an explicit ref before scoping")
    return MemoryCodeScope(memory.id, evidence.id, repository, ref, commit, paths)
