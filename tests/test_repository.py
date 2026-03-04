from __future__ import annotations

from pathlib import Path

import pytest

from lua_nil_guard.repository import (
    SourceEncodingError,
    audit_lua_source_encodings,
    discover_lua_files,
    normalize_lua_source_encodings,
    read_lua_source_text,
)


def test_discover_lua_files_finds_only_lua_sources(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.lua").write_text("-- ok", encoding="utf-8")
    (tmp_path / "src" / "b.txt").write_text("ignore", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "ignored.lua").write_text("-- ignore", encoding="utf-8")

    files = discover_lua_files(tmp_path)

    assert files == (tmp_path / "src" / "a.lua",)


def test_read_lua_source_text_reports_file_path_on_utf8_decode_error(tmp_path: Path) -> None:
    file_path = tmp_path / "bad.lua"
    file_path.write_bytes(b"local value = '\xbd'\n")

    with pytest.raises(SourceEncodingError) as exc_info:
        read_lua_source_text(file_path)

    message = str(exc_info.value)
    assert str(file_path) in message
    assert "not valid UTF-8" in message


def test_encoding_audit_and_normalize_detect_gb18030_file(tmp_path: Path) -> None:
    file_path = tmp_path / "legacy.lua"
    file_path.write_bytes("return '中文'\n".encode("gb18030"))

    records = audit_lua_source_encodings(tmp_path)
    assert len(records) == 1
    assert records[0].encoding == "gb18030"
    assert records[0].needs_normalization is True

    results = normalize_lua_source_encodings(tmp_path, write=False)
    assert results[0].action == "would_convert"
    assert file_path.read_bytes() == "return '中文'\n".encode("gb18030")

    results = normalize_lua_source_encodings(tmp_path, write=True)
    assert results[0].action == "converted"
    assert file_path.read_text(encoding="utf-8") == "return '中文'\n"


def test_encoding_audit_flags_utf8_sig_as_needing_normalization(tmp_path: Path) -> None:
    file_path = tmp_path / "bom.lua"
    file_path.write_bytes("return 'ok'\n".encode("utf-8-sig"))

    records = audit_lua_source_encodings(tmp_path)

    assert len(records) == 1
    assert records[0].encoding == "utf-8-sig"
    assert records[0].needs_normalization is True
