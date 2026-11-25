"""Public contract tests for the archive bomb guard."""

from pathlib import Path

from bombguard import (
    bomb_batch,
    check_nesting,
    check_ratio,
    estimate_total,
    read_entries,
    stream_extract,
)


POLICY = {
    "max_total": 100_000,
    "max_ratio": 100,
    "max_entry": 50_000,
    "max_depth": 2,
}


def file_entry(name, size, compressed, data):
    return {
        "name": name,
        "size": size,
        "compressed": compressed,
        "data": data,
        "is_dir": False,
    }


def archive(name, entries):
    return {"name": name, "entries": entries}


def disk_bytes(path):
    root = Path(path)
    if not root.exists():
        return 0
    return sum(item.stat().st_size for item in root.rglob("*") if item.is_file())


def test_normal_archive_passes_with_declared_expansion():
    payload = archive(
        "normal.zip",
        [
            file_entry("docs/a.txt", 1000, 40, b"a" * 1000),
            file_entry("docs/b.txt", 2000, 60, b"b" * 2000),
        ],
    )
    entries = read_entries(payload)
    assert estimate_total(entries) == 3000
    verdict = bomb_batch([payload], POLICY)["results"][0]
    assert verdict["accepted"] is True
    assert verdict["total"] == 3000


def test_high_compression_ratio_is_rejected():
    payload = archive(
        "bomb.zip",
        [file_entry("bomb.bin", 1_000_000, 50, b"z" * 1000)],
    )
    policy = dict(POLICY, max_ratio=200)
    assert check_ratio(read_entries(payload), policy) == ["bomb.bin"]


def test_expansion_over_total_budget_is_aborted(tmp_path):
    payload = archive(
        "heavy.zip",
        [
            file_entry("part-a.bin", 600, 5, b"a" * 600),
            file_entry("part-b.bin", 600, 5, b"b" * 600),
        ],
    )
    result = stream_extract(payload, 1000, dest=tmp_path / "out")
    assert result["aborted"] is True
    assert result["written"] <= 1000
    assert disk_bytes(tmp_path / "out") <= 1000


def test_nested_archive_expansion_is_counted():
    inner = archive(
        "inner.zip",
        [file_entry("payload.bin", 4000, 90, b"p" * 100)],
    )
    outer = archive(
        "outer.zip",
        [
            file_entry("readme.txt", 100, 10, b"r" * 100),
            {
                "name": "inner.zip",
                "size": 120,
                "compressed": 120,
                "data": b"i" * 120,
                "is_dir": False,
                "nested": inner,
            },
        ],
    )
    assert check_nesting(outer, POLICY) == 4100


def test_batch_judges_archives_independently():
    bomb = archive(
        "bomb.zip",
        [file_entry("big.bin", 5000, 50, b"b" * 5000)],
    )
    normal = archive(
        "normal.zip",
        [file_entry("note.txt", 600, 60, b"n" * 600)],
    )
    policy = dict(POLICY, max_total=1000, max_ratio=500, max_entry=50_000)
    batch = bomb_batch([bomb, normal], policy)
    assert batch["results"][0]["accepted"] is False
    assert batch["results"][1]["accepted"] is True
    assert batch["results"][1]["total"] == 600
    assert batch["rejected"] == ["bomb.zip"]