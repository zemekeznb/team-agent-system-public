"""Read-only, maintenance-window inventory of SQLite Artifact metadata and Body files.

This is a backup/recovery candidate check, not an automatic repair or a live
cross-filesystem transaction. No unknown file is moved or removed here.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from dataclasses import asdict, dataclass
from pathlib import Path

from tas.application.artifact_uploads import MAX_ARTIFACT_BYTES


class ArtifactReconciliationError(RuntimeError):
    """The inventory is unsafe, incomplete, or cannot verify a manifest."""


@dataclass(frozen=True, slots=True)
class ArtifactReconciliationIssue:
    code: str
    reference: str  # Artifact ID or SHA-256 of an unexpected relative filename.


@dataclass(frozen=True, slots=True)
class ArtifactManifestEntry:
    artifact_id: str
    metadata_sha256: str
    body_location: str | None
    body_present: bool
    body_sha256: str | None


@dataclass(frozen=True, slots=True)
class ArtifactManifest:
    version: int
    entries: tuple[ArtifactManifestEntry, ...]
    digest: str

    def to_json(self) -> str:
        return json.dumps(
            {"version": self.version, "entries": [asdict(item) for item in self.entries],
             "digest": self.digest},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        )

    @classmethod
    def from_json(cls, raw: str) -> ArtifactManifest:
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 64 * 1024 * 1024:
            raise ArtifactReconciliationError("Artifact manifest is too large")
        try:
            value = json.loads(raw)
            if (not isinstance(value, dict)
                    or set(value) != {"version", "entries", "digest"}
                    or type(value["version"]) is not int or value["version"] != 1
                    or not isinstance(value["entries"], list)
                    or len(value["entries"]) > 100_000):
                raise ValueError
            entries: list[ArtifactManifestEntry] = []
            for item in value["entries"]:
                if (not isinstance(item, dict)
                        or set(item) != {"artifact_id", "metadata_sha256",
                                         "body_location", "body_present", "body_sha256"}
                        or not isinstance(item["artifact_id"], str)
                        or not SQLiteArtifactReconciliationService._safe_identifier(
                            item["artifact_id"]
                        )
                        or not _digest_is_valid(item["metadata_sha256"])
                        or item["body_location"] not in (None, "available", "quarantine")
                        or type(item["body_present"]) is not bool
                        or (item["body_sha256"] is not None
                            and not _digest_is_valid(item["body_sha256"]))):
                    raise ValueError
                entries.append(ArtifactManifestEntry(**item))
            if not _digest_is_valid(value["digest"]):
                raise ValueError
            manifest = cls(1, tuple(entries), value["digest"])
            if SQLiteArtifactReconciliationService._manifest_digest(manifest.entries) != manifest.digest:
                raise ValueError
            return manifest
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
            raise ArtifactReconciliationError("Artifact manifest is invalid") from error


def _digest_is_valid(value: object) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


@dataclass(frozen=True, slots=True)
class ArtifactReconciliationReport:
    issues: tuple[ArtifactReconciliationIssue, ...]
    manifest: ArtifactManifest | None


class SQLiteArtifactReconciliationService:
    """System-only scanner; callers must stop writes for an authoritative manifest."""

    def __init__(
        self,
        database: str | Path,
        artifact_root: str | Path,
        *,
        max_artifacts: int = 100_000,
        max_files: int = 200_000,
    ) -> None:
        if (type(max_artifacts) is not int or not 1 <= max_artifacts <= 200_000
                or type(max_files) is not int or not 1 <= max_files <= 400_000):
            raise ArtifactReconciliationError("Artifact inventory limit is invalid")
        self.database = Path(database)
        requested_root = Path(artifact_root)
        if requested_root.is_symlink():
            raise ArtifactReconciliationError("Artifact storage root is unsafe")
        self.root = requested_root.resolve(strict=False)
        self.max_artifacts = max_artifacts
        self.max_files = max_files

    def inspect(self) -> ArtifactReconciliationReport:
        roots = self._roots()
        issues: list[ArtifactReconciliationIssue] = []
        entries: list[ArtifactManifestEntry] = []
        expected_files: set[tuple[str, str]] = set()
        try:
            uri = self.database.resolve(strict=True).as_uri() + "?mode=ro"
            with sqlite3.connect(uri, uri=True, isolation_level=None) as connection:
                connection.execute("PRAGMA query_only=ON")
                connection.execute("BEGIN")
                if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    issues.append(ArtifactReconciliationIssue("database_integrity", "database"))
                if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                    issues.append(ArtifactReconciliationIssue("database_foreign_key", "database"))
                rows = connection.execute(
                    "SELECT upload.id,upload.task_id,upload.producer_agent_id,"
                    "upload.media_type,upload.purpose,upload.declared_size,"
                    "upload.declared_sha256,upload.status,upload.actual_size,"
                    "upload.actual_sha256,upload.created_at,upload.uploaded_at,"
                    "upload.finalized_at,security.scan_status,"
                    "security.availability_status,security.scanner_version,"
                    "security.scanned_at,security.redaction_count,"
                    "life.owner_id,life.retention_class,life.expires_at,"
                    "life.cleanup_status,life.charged_bytes,life.cleanup_requested_at,"
                    "life.purged_at,source.source_artifact_id,"
                    "derived.derived_artifact_id,producer.owner_id "
                    "FROM tas_artifact_uploads upload "
                    "LEFT JOIN tas_agents producer ON producer.id=upload.producer_agent_id "
                    "LEFT JOIN tas_artifact_security security ON security.artifact_id=upload.id "
                    "LEFT JOIN tas_artifact_lifecycle life ON life.artifact_id=upload.id "
                    "LEFT JOIN tas_artifact_derivations source ON source.derived_artifact_id=upload.id "
                    "LEFT JOIN tas_artifact_derivations derived ON derived.source_artifact_id=upload.id "
                    "ORDER BY upload.id LIMIT ?",
                    (self.max_artifacts + 1,),
                ).fetchall()
                link_rows = connection.execute(
                    "SELECT artifact_id,evidence_id,sequence "
                    "FROM tas_evidence_submission_artifacts "
                    "ORDER BY artifact_id,evidence_id,sequence LIMIT ?",
                    (self.max_files + 1,),
                ).fetchall()
                connection.execute("COMMIT")
        except (OSError, sqlite3.Error) as error:
            raise ArtifactReconciliationError("Artifact metadata cannot be inventoried") from error
        if len(rows) > self.max_artifacts:
            raise ArtifactReconciliationError("Artifact inventory limit exceeded")
        if len(link_rows) > self.max_files:
            raise ArtifactReconciliationError("Artifact reference inventory limit exceeded")
        links: dict[str, list[tuple[str, int]]] = {}
        for artifact_id, evidence_id, sequence in link_rows:
            links.setdefault(str(artifact_id), []).append((str(evidence_id), int(sequence)))

        for row in rows:
            artifact_id = str(row[0])
            if not self._safe_identifier(artifact_id):
                issues.append(ArtifactReconciliationIssue(
                    "unsafe_artifact_id", hashlib.sha256(artifact_id.encode()).hexdigest(),
                ))
                continue
            if row[13] is None or row[18] is None:
                issues.append(ArtifactReconciliationIssue("metadata_incomplete", artifact_id))
                continue
            if row[18] != row[27]:
                issues.append(ArtifactReconciliationIssue("owner_binding_mismatch", artifact_id))
            metadata_digest = hashlib.sha256(self._canonical({
                "row": list(row), "evidence_links": links.get(artifact_id, []),
            })).hexdigest()
            status, availability, cleanup = str(row[7]), str(row[14]), str(row[21])
            security, retention = str(row[13]), str(row[19])
            if (status == "reserved" and (
                    row[8] is not None or security != "pending" or retention != "pending")
                    or status == "uploaded" and (
                        row[8] is None or security != "pending" or retention != "pending")
                    or status == "finalized" and (
                        row[8] is None or security == "pending"
                        or retention != ("available" if availability == "available"
                                         else "quarantine"))
                    or availability == "available" and security not in ("clean", "redacted")
                    or availability == "quarantined" and security in ("clean", "redacted")):
                issues.append(ArtifactReconciliationIssue("metadata_inconsistent", artifact_id))
            body_location: str | None = None
            body_present = False
            body_digest: str | None = None
            if status != "reserved" and cleanup != "purged":
                body_location = "available" if availability == "available" else "quarantine"
                filename = f"{artifact_id}.bin"
                path = roots[body_location] / filename
                if path.is_symlink():
                    issues.append(ArtifactReconciliationIssue("unsafe_body", artifact_id))
                elif path.exists():
                    expected_files.add((body_location, filename))
                    body_present = True
                    body_digest = self._hash_body(path, artifact_id, row, issues)
                elif cleanup != "pending":
                    issues.append(ArtifactReconciliationIssue("body_missing", artifact_id))
            entries.append(ArtifactManifestEntry(
                artifact_id, metadata_digest, body_location, body_present, body_digest,
            ))

        file_count = 0
        try:
            root_entries = tuple(self.root.iterdir())
        except OSError as error:
            raise ArtifactReconciliationError("Artifact root cannot be inventoried") from error
        for path in root_entries:
            if path.name in roots:
                continue
            file_count += 1
            reference = hashlib.sha256(path.name.encode("utf-8", errors="replace")).hexdigest()
            issues.append(ArtifactReconciliationIssue("unregistered_root_entry", reference))
        for location, directory in roots.items():
            try:
                children = tuple(directory.iterdir())
            except OSError as error:
                raise ArtifactReconciliationError("Artifact directory cannot be inventoried") from error
            file_count += len(children)
            if file_count > self.max_files:
                raise ArtifactReconciliationError("Artifact file inventory limit exceeded")
            for path in children:
                if (location, path.name) in expected_files:
                    continue
                reference = hashlib.sha256(
                    f"{location}/{path.name}".encode("utf-8", errors="replace")
                ).hexdigest()
                code = (
                    "unsafe_entry" if path.is_symlink() or not path.is_file()
                    else "staging_remnant" if location == ".staging"
                    else "unregistered_body"
                )
                issues.append(ArtifactReconciliationIssue(code, reference))
        ordered_issues = tuple(sorted(issues, key=lambda item: (item.code, item.reference)))
        if ordered_issues:
            return ArtifactReconciliationReport(ordered_issues, None)
        ordered_entries = tuple(entries)
        return ArtifactReconciliationReport((), ArtifactManifest(
            1, ordered_entries, self._manifest_digest(ordered_entries),
        ))

    def verify_manifest(self, expected: ArtifactManifest) -> bool:
        if (not isinstance(expected, ArtifactManifest)
                or type(expected.version) is not int or expected.version != 1):
            raise ArtifactReconciliationError("Artifact manifest version is invalid")
        if self._manifest_digest(expected.entries) != expected.digest:
            raise ArtifactReconciliationError("Artifact manifest digest is invalid")
        report = self.inspect()
        if report.issues or report.manifest is None:
            raise ArtifactReconciliationError("Artifact inventory has unresolved issues")
        return report.manifest == expected

    def _roots(self) -> dict[str, Path]:
        if self.root.is_symlink() or not self.root.is_dir():
            raise ArtifactReconciliationError("Artifact storage root is unsafe")
        roots: dict[str, Path] = {}
        for name in (".staging", "quarantine", "available"):
            directory = self.root / name
            if directory.is_symlink() or not directory.is_dir():
                raise ArtifactReconciliationError("Artifact directory is unsafe")
            if directory.resolve(strict=True).parent != self.root:
                raise ArtifactReconciliationError("Artifact directory is unsafe")
            roots[name] = directory
        return roots

    @staticmethod
    def _safe_identifier(value: str) -> bool:
        if not isinstance(value, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", value
        ) or value.endswith("."):
            return False
        stem = value.split(".", 1)[0].lower()
        return stem not in {"con", "prn", "aux", "nul"} and not re.fullmatch(
            r"(?:com|lpt)[1-9]", stem
        )

    @staticmethod
    def _hash_body(path: Path, artifact_id: str, row, issues) -> str | None:
        try:
            with path.open("rb") as stream:
                file_stat = os.fstat(stream.fileno())
                if not stat.S_ISREG(file_stat.st_mode):
                    issues.append(ArtifactReconciliationIssue("unsafe_body", artifact_id))
                    return None
                if file_stat.st_size > MAX_ARTIFACT_BYTES or file_stat.st_size != row[8]:
                    issues.append(ArtifactReconciliationIssue("body_size_mismatch", artifact_id))
                    return None
                digest = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
        except OSError:
            issues.append(ArtifactReconciliationIssue("body_unreadable", artifact_id))
            return None
        calculated = digest.hexdigest()
        if calculated != row[9]:
            issues.append(ArtifactReconciliationIssue("body_digest_mismatch", artifact_id))
        return calculated

    @staticmethod
    def _canonical(value: object) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")

    @classmethod
    def _manifest_digest(cls, entries: tuple[ArtifactManifestEntry, ...]) -> str:
        payload = {"version": 1, "entries": [asdict(entry) for entry in entries]}
        return hashlib.sha256(cls._canonical(payload)).hexdigest()
