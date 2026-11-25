"""Archive bomb guard: declared-size estimation plus budgeted extraction.

Archives are described with plain dictionaries so the guards can be exercised
without crafting real zip bombs on disk:

    {
        "name": "upload.zip",
        "entries": [
            {
                "name": "docs/readme.txt",
                "compressed": 48,
                "size": 1024,
                "data": b"...",
                "is_dir": False,
                "nested": None,
            },
        ],
    }

A trailing slash in the entry name or an explicit is_dir flag marks a
directory record. A nested archive is attached to its entry through the
nested key and uses the same shape. The entry data field carries the payload
bytes so extraction can be walked chunk by chunk.

Policies use four keys:

    max_total   bytes one archive is allowed to expand to
    max_ratio   maximum allowed uncompressed to compressed ratio
    max_entry   maximum allowed size of a single file entry
    max_depth   maximum allowed archive nesting depth

Every archive in a batch is judged on its own.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

CHUNK_SIZE = 64 * 1024

DEFAULT_POLICY = {
    "max_total": 64 * 1024 * 1024,
    "max_ratio": 200,
    "max_entry": 8 * 1024 * 1024,
    "max_depth": 2,
}


class NestingLimitExceeded(ValueError):
    """Raised when an archive nests deeper than the policy allows."""


def read_entries(archive):
    """Return the declared entries of an archive as normalised dictionaries.

    Each returned item has the keys name, compressed, size, is_dir, data and
    nested. Directory records are kept so callers can decide whether they
    carry payload bytes; they never do.
    """
    if isinstance(archive, dict):
        raw_entries = archive.get("entries", [])
    else:
        raw_entries = list(archive)

    entries = []
    for raw in raw_entries:
        name = str(raw.get("name", ""))
        entries.append(
            {
                "name": name,
                "compressed": int(raw.get("compressed", 0) or 0),
                "size": int(raw.get("size", 0) or 0),
                "is_dir": name.endswith("/"),
                "data": raw.get("data", b"") or b"",
                "nested": raw.get("nested"),
            }
        )
    return entries


def estimate_total(entries):
    """Estimate the shallow expansion of the file entries in entries.

    The estimate is meant for the pre-flight decision, so it only looks at
    declared metadata and never touches payload bytes. Nested archives are
    accounted for separately by check_nesting.
    """
    return sum(
        entry["compressed"] for entry in entries if not entry["is_dir"]
    )


def check_ratio(entries, policy):
    """Return the names of file entries whose compression ratio is too high."""
    limit = policy.get("max_ratio")
    if not limit:
        return []

    offenders = []
    for entry in entries:
        if entry["is_dir"]:
            continue
        compressed = entry["compressed"]
        size = entry["size"]
        if size <= 0:
            continue
        ratio = compressed / size if compressed > 0 else 0.0
        if ratio > limit:
            offenders.append(entry["name"])
    return offenders


def check_entry_size(entry, policy):
    """Return True when a single entry stays within the per-entry cap."""
    if entry["is_dir"]:
        return True
    limit = policy.get("max_entry")
    if not limit:
        return True
    return entry["compressed"] <= limit


def check_nesting(archive, policy):
    """Return the expansion of archive with nested archives counted.

    The depth of the archive tree is limited by policy max_depth. A nested
    archive contributes its own expansion instead of the declared size of the
    container entry. Exceeding the depth limit raises NestingLimitExceeded.
    """
    depth_limit = policy.get("max_depth")
    total = 0
    pending = [(archive, 0)]
    while pending:
        node, level = pending.pop()
        for entry in read_entries(node):
            if entry["is_dir"]:
                continue
            if level == 0:
                total += entry["size"]
            nested = entry.get("nested")
            if not nested:
                continue
            next_level = level + 1
            if depth_limit is not None and next_level > depth_limit:
                raise NestingLimitExceeded(
                    "archive {0} nests deeper than {1}".format(
                        entry["name"], depth_limit
                    )
                )
            pending.append((nested, next_level))
    return total


def stream_extract(archive, budget, dest=None):
    """Extract archive without writing more than budget bytes.

    Extraction stops as soon as the written bytes would pass the budget. The
    returned dictionary always reports ok, aborted, reason, estimate, written,
    files and dest, and dest names the directory that received the payload.
    """
    entries = read_entries(archive)
    if dest is None:
        target = Path(tempfile.mkdtemp(prefix="bombguard-"))
    else:
        target = Path(dest)
    target.mkdir(parents=True, exist_ok=True)

    estimate = estimate_total(entries)
    if estimate > budget:
        return _outcome(
            False, "estimated expansion exceeds budget", budget, estimate, 0, [], target
        )

    written = 0
    files = []
    for entry in entries:
        destination = target / entry["name"]
        if entry["is_dir"]:
            destination.mkdir(parents=True, exist_ok=True)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = entry["data"]
        with destination.open("wb") as handle:
            handle.write(payload)
        files.append(entry["name"])
        written += entry["size"]
        if written > budget:
            return _outcome(
                False,
                "written bytes exceed budget",
                budget,
                estimate,
                written,
                files,
                target,
            )
    return _outcome(True, "", budget, estimate, written, files, target)


def _outcome(ok, reason, budget, estimate, written, files, target):
    return {
        "ok": ok,
        "aborted": not ok,
        "reason": reason,
        "budget": budget,
        "estimate": estimate,
        "written": written,
        "files": list(files),
        "dest": str(target),
    }


def validate_policy(policy):
    """Return the problems that make a policy too weak to guard an archive."""
    issues = []
    if not policy.get("max_ratio"):
        issues.append("policy has no compression ratio threshold (max_ratio)")
    if policy.get("max_depth") is None:
        issues.append("policy has no nesting depth limit (max_depth)")
    return issues


def _over_total(entries, limit):
    if not limit:
        return False
    return any(
        entry["size"] > limit for entry in entries if not entry["is_dir"]
    )


def _archive_name(archive, index):
    if isinstance(archive, dict) and archive.get("name"):
        return str(archive["name"])
    return "archive-{0}".format(index)


def bomb_batch(archives, policy):
    """Judge a batch of archives and return one verdict per archive."""
    limit = policy.get("max_total") or 0
    results = []
    carried = 0
    for index, archive in enumerate(archives):
        entries = read_entries(archive)
        carried += estimate_total(entries)
        reasons = []
        if _over_total(entries, limit):
            reasons.append("total expansion exceeds {0} bytes".format(limit))
        offenders = check_ratio(entries, policy)
        if offenders:
            reasons.append("compression ratio too high: " + ", ".join(offenders))
        oversized = [
            entry["name"]
            for entry in entries
            if not check_entry_size(entry, policy)
        ]
        if oversized:
            reasons.append("entry size above limit: " + ", ".join(oversized))
        results.append(
            {
                "name": _archive_name(archive, index),
                "accepted": not reasons,
                "reasons": reasons,
                "total": carried,
            }
        )
    accepted = [item["name"] for item in results if item["accepted"]]
    rejected = [item["name"] for item in results if not item["accepted"]]
    return {"results": results, "accepted": accepted, "rejected": rejected}