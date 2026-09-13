#!/usr/bin/env python3
"""Independent Flight Recorder verifier (not the Go binary).

Recomputes event digests and the integrity root, then checks the Ed25519
signature over the same field order encoding/json uses. Classifies the
receipt as complete, coverage-unevaluated, incomplete, stale, invalid, or
untrusted-key.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RESULT_COMPLETE = "complete"
RESULT_UNEVALUATED = "coverage-unevaluated"
RESULT_INCOMPLETE = "incomplete"
RESULT_STALE = "stale"
RESULT_INVALID = "invalid"
RESULT_UNTRUSTED = "untrusted-key"


class Classify(Exception):
    def __init__(self, result: str, message: str) -> None:
        super().__init__(message)
        self.result = result
        self.message = message


def go_json(value: Any) -> bytes:
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return raw.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e").encode("utf-8")


def omit(obj: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in obj.items() if v is not None and v != ""}


def event_canonical(digest: dict[str, Any]) -> dict[str, Any]:
    return omit(
        {
            "id": digest.get("id"),
            "source": digest.get("source"),
            "occurred_at": digest.get("occurred_at"),
            "actor": digest.get("actor"),
            "event_type": digest.get("event_type"),
            "tool_name": digest.get("tool_name"),
            "tool_call_id": digest.get("tool_call_id"),
            "collected_at": digest.get("collected_at"),
            **({"source_time_unavailable": True} if digest.get("source_time_unavailable") else {}),
        }
    )


def digest_sha(digest: dict[str, Any]) -> str:
    return hashlib.sha256(go_json(event_canonical(digest))).hexdigest()


def commit_coverage_canonical(coverage: dict[str, Any] | None) -> dict[str, Any] | None:
    if coverage is None:
        return None
    out: dict[str, Any] = {
        "list_complete": bool(coverage.get("list_complete")),
        "commits": [{"sha": item.get("sha", ""), "state": item.get("state", "")} for item in coverage.get("commits") or []],
    }
    # source/reported_count/listed_count mirror CommitCoverage's own
    # omitempty: falsy (empty string, zero) is dropped, matching Go's
    # zero-value-means-absent convention, not Python's usual `is not None`.
    if coverage.get("source"):
        out["source"] = coverage["source"]
    if coverage.get("reported_count"):
        out["reported_count"] = coverage["reported_count"]
    if coverage.get("listed_count"):
        out["listed_count"] = coverage["listed_count"]
    return out


def change_canonical(change: dict[str, Any] | None) -> dict[str, Any] | None:
    if not change:
        return None
    out: dict[str, Any] = {}
    coverage = commit_coverage_canonical(change.get("commit_coverage"))
    if coverage is not None:
        out["commit_coverage"] = coverage
    out["repository_id"] = change.get("repository_id", "")
    out["commit_sha"] = change.get("commit_sha", "")
    out["pull_request_number"] = change.get("pull_request_number", 0)
    if change.get("merge_sha"):
        out["merge_sha"] = change["merge_sha"]
    if change.get("sha_provenance"):
        out["sha_provenance"] = change["sha_provenance"]
    return out


def authorization_canonical(auth: dict[str, Any] | None) -> dict[str, Any] | None:
    if not auth:
        return None
    return {
        "scope_id": auth.get("scope_id", ""),
        "scope_digest": auth.get("scope_digest", ""),
        "granted_at": auth.get("granted_at", ""),
        "enforcement_state": auth.get("enforcement_state", ""),
        "decisions": auth.get("decisions") or [],
    }


def boundary_component_canonical(component: dict[str, Any]) -> dict[str, Any]:
    return omit(
        {
            "name": component.get("name"),
            "id": component.get("id"),
            "digest": component.get("digest"),
            "provenance": component.get("provenance"),
        }
    )


def boundary_canonical(boundary: dict[str, Any] | None) -> dict[str, Any] | None:
    if not boundary:
        return None
    out: dict[str, Any] = {"observed_at": boundary.get("observed_at", "")}
    start = [boundary_component_canonical(item) for item in boundary.get("start") or []]
    if start:
        out["start"] = start
    out["components"] = [boundary_component_canonical(item) for item in boundary.get("components") or []]
    return out


def event_digest_canonical(digest: dict[str, Any]) -> dict[str, Any]:
    out = event_canonical(digest)
    out["sha256"] = digest.get("sha256", "")
    return out


def root_canonical(packet: dict[str, Any]) -> dict[str, Any]:
    body = omit(
        {
            "policy_outcome": packet.get("policy_outcome"),
            "protection_mode": packet.get("protection_mode"),
        }
    )
    body.update(
        {
            "version": packet.get("version", ""),
            "tenant_id": packet.get("tenant_id", ""),
            "session_id": packet.get("session_id", ""),
        }
    )
    change = change_canonical(packet.get("change"))
    if change is not None:
        body["change"] = change
    if packet.get("resource") is not None:
        resource = packet["resource"]
        body["resource"] = omit({key: resource.get(key) for key in ("system", "resource_type", "resource_id", "digest")})
    auth = authorization_canonical(packet.get("authorization"))
    if auth is not None:
        body["authorization"] = auth
    boundary = boundary_canonical(packet.get("boundary"))
    if boundary is not None:
        body["boundary"] = boundary
    body.update(omit({"agent_id": packet.get("agent_id"), "agent_type": packet.get("agent_type"), "provider": packet.get("provider")}))
    body.update(
        {
            "started_at": packet.get("started_at", ""),
            "last_activity": packet.get("last_activity", ""),
            "coverage_state": packet.get("coverage_state", ""),
            "coverage_gaps": packet.get("coverage_gaps") or [],

        }
    )
    if packet.get("outcomes"):
        body["outcomes"] = [omit({k: claim.get(k) for k in ("tool_call_id", "source", "state", "event_id")}) for claim in packet["outcomes"]]
    if packet.get("redactions"):
        body["redactions"] = [omit({k: item.get(k) for k in ("field", "tool_call_id", "reason")}) for item in packet["redactions"]]
    if packet.get("packet_revision"):
        body["packet_revision"] = packet["packet_revision"]
    if packet.get("supersedes_integrity_root"):
        body["supersedes_integrity_root"] = packet["supersedes_integrity_root"]
    body["event_digests"] = [event_digest_canonical(d) for d in packet.get("event_digests") or []]
    return body


def signing_bytes(packet: dict[str, Any]) -> bytes:
    body = root_canonical(packet)
    body["integrity_root"] = packet.get("integrity_root", "")
    body["signer_key_id"] = packet.get("signer_key_id", "")
    return go_json(body)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_public_key(text: str) -> bytes:
    raw = base64.b64decode(text.strip(), validate=True)
    if len(raw) != 32:
        raise Classify(RESULT_UNTRUSTED, "public key must be 32 Ed25519 bytes")
    return raw


def verify_ed25519(public: bytes, message: bytes, signature_b64: str) -> None:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError) as err:
        raise Classify(RESULT_INVALID, f"signature mismatch: {err}") from err


def parse_rfc3339(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def key_canonical(key: dict[str, Any]) -> dict[str, Any]:
    return {
        "key_id": key.get("key_id", ""),
        "public_key": key.get("public_key", ""),
        "valid_from": key.get("valid_from", ""),
        "valid_until": key.get("valid_until", ""),
        "status": key.get("status", ""),
    }


def verify_trust_root(path: str, fingerprint: str, signer_id: str, at: str) -> bytes:
    try:
        directory = json.loads(open(path, encoding="utf-8").read())
    except (OSError, json.JSONDecodeError) as err:
        raise Classify(RESULT_INVALID, f"trust root: {err}") from err
    if directory.get("version") != "chokepoint.keys/v1":
        raise Classify(RESULT_UNTRUSTED, "unsupported trust-root version")
    root_b64 = directory.get("root_public_key", "")
    try:
        root_pub = parse_public_key(root_b64)
    except Classify:
        raise Classify(RESULT_UNTRUSTED, "trust root public key is unusable")
    want = fingerprint.strip().lower()
    got = "sha256:" + hashlib.sha256(root_pub).hexdigest()
    if want != got:
        raise Classify(RESULT_UNTRUSTED, "root fingerprint mismatch")
    keys = [key_canonical(key) for key in directory.get("keys") or []]
    keys.sort(key=lambda item: item["key_id"])
    unsigned_bytes = go_json(
        {
            "version": directory.get("version", ""),
            "issued_at": directory.get("issued_at", ""),
            "root_public_key": directory.get("root_public_key", ""),
            "keys": keys,
            "root_signature": "",
        }
    )
    try:
        verify_ed25519(root_pub, unsigned_bytes, directory.get("root_signature", ""))
    except Classify as err:
        raise Classify(RESULT_UNTRUSTED, f"trust root signature: {err.message}") from err
    try:
        when = parse_rfc3339(at)
    except ValueError as err:
        raise Classify(RESULT_UNTRUSTED, f"packet timestamp: {err}") from err
    for key in keys:
        if key["key_id"] != signer_id:
            continue
        if key["status"] != "active":
            raise Classify(RESULT_UNTRUSTED, f"signer {signer_id} is not active")
        try:
            valid_from = parse_rfc3339(key["valid_from"])
            valid_until = parse_rfc3339(key["valid_until"])
        except ValueError as err:
            raise Classify(RESULT_UNTRUSTED, f"signer validity: {err}") from err
        if when < valid_from or when > valid_until:
            raise Classify(RESULT_UNTRUSTED, f"signer {signer_id} is outside its validity window")
        return parse_public_key(key["public_key"])
    raise Classify(RESULT_UNTRUSTED, f"signer {signer_id} is not in the directory")


def validate_evidence(packet: dict[str, Any]) -> None:
    def invalid(message: str) -> None:
        raise Classify(RESULT_INVALID, message)

    digests = packet.get("event_digests") or []
    calls = {d.get("tool_call_id") for d in digests if d.get("tool_call_id")}
    for d in digests:
        if type(d.get("source_time_unavailable", False)) is not bool:
            invalid("invalid source-time availability flag")
        if d.get("source_time_unavailable") and (not d.get("collected_at") or d.get("occurred_at") != d.get("collected_at")):
            invalid("missing source time requires a collection-time fallback")
        if d.get("source_time_unavailable") and (packet.get("coverage_state") != "evidence_incomplete" or "source_time_unavailable" not in (packet.get("coverage_gaps") or [])):
            invalid("missing source-time gap")
        if d.get("collected_at"):
            parse_rfc3339(d["collected_at"])
    resource = packet.get("resource")
    if resource is not None:
        if packet.get("change") is not None:
            invalid("packet cannot bind both change and resource")
        for key, maximum in (("system", 256), ("resource_type", 256), ("resource_id", 512)):
            value = resource.get(key)
            if not isinstance(value, str) or not value or len(value.encode()) > maximum or any(ord(c) <= 32 or ord(c) == 127 for c in value):
                invalid("invalid resource " + key)
        if resource.get("digest") and not re.fullmatch(r"[0-9a-f]{64}", resource["digest"]):
            invalid("invalid resource digest")
    revision = packet.get("packet_revision", 0)
    prior = packet.get("supersedes_integrity_root", "")
    if type(revision) is not int or revision < 0:
        invalid("invalid packet revision")
    if revision >= 2:
        if not re.fullmatch(r"[0-9a-f]{64}", prior):
            invalid("revision requires predecessor root")
    elif prior:
        invalid("first issuance cannot supersede a packet")
    seen = set()
    for claim in packet.get("outcomes") or []:
        key = (claim.get("tool_call_id"), claim.get("source"))
        if key[0] not in calls or key[1] not in ("agent_reported", "tool_response", "target_confirmed") or claim.get("state") not in ("attempted", "completed", "failed", "not_executed", "unknown") or key in seen:
            invalid("invalid or duplicate outcome claim")
        if claim.get("event_id") and not any(d.get("id") == claim["event_id"] and d.get("tool_call_id") == key[0] for d in digests):
            invalid("outcome evidence does not match tool call")
        seen.add(key)
    if seen and [(c["tool_call_id"], c["source"]) for c in packet["outcomes"]] != sorted(seen):
        invalid("outcomes are not canonical")
    seen = set()
    for item in packet.get("redactions") or []:
        field = item.get("field", "")
        call = item.get("tool_call_id", "")
        if not field or len(field.encode()) > 256 or any(ord(c) <= 32 or ord(c) == 127 for c in field) or (call and call not in calls) or item.get("reason") not in ("privacy_minimization", "not_authorized_for_recipient", "policy") or (field, call) in seen:
            invalid("invalid or duplicate redaction")
        seen.add((field, call))
    if seen and [(r["field"], r.get("tool_call_id", "")) for r in packet["redactions"]] != sorted(seen):
        invalid("redactions are not canonical")
    for decision in (packet.get("authorization") or {}).get("decisions") or []:
        if decision.get("tool_call_id") not in calls:
            invalid("authorization decision has no matching event")


def classify_packet(packet: dict[str, Any], public: bytes) -> str:
    for required in ("version", "tenant_id", "session_id", "started_at", "last_activity", "coverage_state", "integrity_root"):
        if not packet.get(required):
            raise Classify(RESULT_INVALID, f"missing {required}")
    if packet.get("version") != "chokepoint.flight-recorder/v1":
        raise Classify(RESULT_INVALID, "unsupported packet version")
    coverage = packet.get("coverage_state")
    gaps = packet.get("coverage_gaps") or []
    if coverage == "complete" and gaps:
        raise Classify(RESULT_INVALID, "complete coverage cannot include gaps")
    if coverage == "evidence_incomplete" and not gaps:
        raise Classify(RESULT_INVALID, "incomplete coverage requires a gap")
    if coverage not in ("complete", "evidence_incomplete"):
        raise Classify(RESULT_INVALID, "unsupported coverage_state")

    validate_evidence(packet)
    for digest in packet.get("event_digests") or []:
        if digest_sha(digest) != digest.get("sha256"):
            raise Classify(RESULT_INVALID, f"event digest mismatch for {digest.get('id')}")
    if sha256_hex(go_json(root_canonical(packet))) != packet.get("integrity_root"):
        raise Classify(RESULT_INVALID, "integrity root mismatch")
    if not packet.get("signature") or not packet.get("signer_key_id"):
        raise Classify(RESULT_INVALID, "signature and signer_key_id are required")
    verify_ed25519(public, signing_bytes(packet), packet["signature"])

    if "stale" in gaps:
        return RESULT_STALE
    if coverage == "complete":
        change = packet.get("change")
        if change and change.get("commit_coverage") is None:
            # The packet is genuine and its own claim is complete; what is
            # unknown is whether that claim covers the whole change. Never
            # substitute this for RESULT_INVALID/STALE/UNTRUSTED above.
            return RESULT_UNEVALUATED
        return RESULT_COMPLETE
    return RESULT_INCOMPLETE


def write_output(name: str, value: str) -> None:
    path = __import__("os").environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def resolve_public_key(packet: dict[str, Any], args: argparse.Namespace) -> bytes:
    if args.trust_root:
        if not args.root_fingerprint:
            raise Classify(RESULT_UNTRUSTED, "--trust-root requires --root-fingerprint")
        public = verify_trust_root(args.trust_root, args.root_fingerprint, packet.get("signer_key_id", ""), packet.get("last_activity", ""))
    elif args.public_key:
        public = parse_public_key(args.public_key)
    else:
        raise Classify(RESULT_INVALID, "provide --trust-root or --public-key")
    return public


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Verify a Chokepoint receipt without the Go binary")
    parser.add_argument("--packet", required=True)
    parser.add_argument("--previous-packet")
    parser.add_argument("--trust-root")
    parser.add_argument("--root-fingerprint")
    parser.add_argument("--public-key")
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument("--allow-unevaluated", action="store_true")
    args = parser.parse_args(argv)

    try:
        raw = open(args.packet, encoding="utf-8").read()
        packet = json.loads(raw)
        if not isinstance(packet, dict):
            raise Classify(RESULT_INVALID, "packet must be a JSON object")
        public = resolve_public_key(packet, args)
        result = classify_packet(packet, public)
        revision_link = "unevaluated" if packet.get("packet_revision", 0) >= 2 else "not-applicable"
        if args.previous_packet:
            prior = json.loads(open(args.previous_packet, encoding="utf-8").read())
            classify_packet(prior, resolve_public_key(prior, args))
            same_resource = all((packet.get("resource") or {}).get(k) == (prior.get("resource") or {}).get(k) for k in ("system", "resource_type", "resource_id"))
            same_change = all((packet.get("change") or {}).get(k) == (prior.get("change") or {}).get(k) for k in ("repository_id", "commit_sha", "pull_request_number"))
            if any(packet.get(k) != prior.get(k) for k in ("tenant_id", "session_id")) or not same_change or not same_resource or packet.get("packet_revision") != max(prior.get("packet_revision", 0), 1) + 1 or packet.get("supersedes_integrity_root") != prior.get("integrity_root"):
                raise Classify(RESULT_INVALID, "invalid revision chain")
            revision_link = "verified"
        gaps = ",".join(packet.get("coverage_gaps") or [])
        change = packet.get("change")
        commit_coverage = ""
        if change:
            commit_coverage = "unevaluated" if change.get("commit_coverage") is None else "evaluated"
        print(
            f"result={result} coverage={packet.get('coverage_state')} gaps={gaps} "
            f"commit_coverage={commit_coverage} revision_link={revision_link} session={packet.get('session_id')}"
        )
        write_output("result", result)
        write_output("coverage", str(packet.get("coverage_state") or ""))
        write_output("gaps", gaps)
        write_output("commit_coverage", commit_coverage)
        write_output("revision_link", revision_link)
        if result in (RESULT_INVALID, RESULT_UNTRUSTED, RESULT_STALE):
            return 1
        if result == RESULT_UNEVALUATED and not args.allow_unevaluated:
            return 1
        if result == RESULT_INCOMPLETE and not args.allow_incomplete:
            return 1
        return 0
    except Classify as err:
        print(f"result={err.result} error={err.message}", file=sys.stderr)
        write_output("result", err.result)
        write_output("coverage", "")
        write_output("gaps", "")
        write_output("commit_coverage", "")
        write_output("revision_link", "")
        return 1
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as err:
        print(f"result={RESULT_INVALID} error=malformed JSON: {err}", file=sys.stderr)
        write_output("result", RESULT_INVALID)
        write_output("commit_coverage", "")
        write_output("revision_link", "")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
