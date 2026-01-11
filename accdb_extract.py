#!/usr/bin/env python3
"""
Read-only extractor for Microsoft Access .accdb files (no ODBC/ACE drivers).

Usage examples:
    python accdb_extract.py --input ./sample.accdb --outdir ./out
    python accdb_extract.py --input ./sample.accdb --outdir ./out --format jsonl
    python accdb_extract.py --input ./sample.accdb --outdir ./out --tables Users,Departments
    python accdb_extract.py --input ./sample.accdb --outdir ./out --limit 100
    python accdb_extract.py --input ./sample.accdb --outdir ./out --self-test

This tool prefers access-parser and falls back to pyaccdb when needed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from pathlib import Path
from typing import Iterable, Iterator, Sequence

import pandas as pd


@dataclass
class TableResult:
    name: str
    sanitized_name: str
    row_count: int | None
    output_path: Path | None
    error: str | None = None


def _sanitize_name(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_]+", "_", name).strip("_")
    return sanitized or "table"


def _unique_names(names: Iterable[str]) -> list[str]:
    seen: dict[str, int] = {}
    result: list[str] = []
    for name in names:
        base = name
        if base not in seen:
            seen[base] = 0
            result.append(base)
            continue
        seen[base] += 1
        result.append(f"{base}_{seen[base]}")
    return result


def _normalize_column_names(columns: Sequence[str]) -> tuple[list[str], dict[str, str]]:
    sanitized = [_sanitize_name(name) for name in columns]
    unique = _unique_names(sanitized)
    mapping = {original: sanitized for original, sanitized in zip(columns, unique)}
    return unique, mapping


def _iter_access_parser_tables(
    accdb_path: Path, include_system: bool
) -> tuple[list[str], dict[str, Iterator[dict]]]:
    try:
        from access_parser import AccessParser  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - import guard
        raise RuntimeError("access-parser is not installed.") from exc

    parser = AccessParser(str(accdb_path))
    try:
        parser.parse_tables()
    except AttributeError:
        pass

    tables: dict[str, Iterator[dict]] = {}
    table_names: list[str] = []

    if hasattr(parser, "tables"):
        source = parser.tables
        if isinstance(source, dict):
            for name, table in source.items():
                if not include_system and _is_system_table(name):
                    continue
                table_names.append(name)
                tables[name] = _iter_access_parser_table(table)
        else:
            for table in source:
                name = getattr(table, "name", None) or getattr(table, "table_name", None)
                if not name:
                    continue
                if not include_system and _is_system_table(name):
                    continue
                table_names.append(name)
                tables[name] = _iter_access_parser_table(table)
    elif hasattr(parser, "list_tables"):
        for name in parser.list_tables():  # type: ignore[attr-defined]
            if not include_system and _is_system_table(name):
                continue
            table_names.append(name)
            table = parser.get_table(name)  # type: ignore[attr-defined]
            tables[name] = _iter_access_parser_table(table)

    return table_names, tables


def _iter_access_parser_table(table: object) -> Iterator[dict]:
    if hasattr(table, "rows"):
        rows = table.rows  # type: ignore[attr-defined]
        if callable(rows):
            yield from rows()
        else:
            yield from rows
        return
    if hasattr(table, "iter_records"):
        yield from table.iter_records()  # type: ignore[attr-defined]
        return
    if hasattr(table, "records"):
        records = table.records  # type: ignore[attr-defined]
        if callable(records):
            yield from records()
        else:
            yield from records
        return
    raise RuntimeError("Unsupported access-parser table API.")


def _iter_pyaccdb_tables(
    accdb_path: Path, include_system: bool
) -> tuple[list[str], dict[str, Iterator[dict]]]:
    try:
        from pyaccdb import AccessDatabase  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - import guard
        raise RuntimeError("pyaccdb is not installed.") from exc

    db = AccessDatabase(str(accdb_path))
    table_names: list[str] = []
    tables: dict[str, Iterator[dict]] = {}

    if hasattr(db, "table_names"):
        names = db.table_names()  # type: ignore[attr-defined]
    elif hasattr(db, "tables"):
        names = [table.name for table in db.tables]  # type: ignore[attr-defined]
    else:
        raise RuntimeError("Unsupported pyaccdb API.")

    for name in names:
        if not include_system and _is_system_table(name):
            continue
        table_names.append(name)
        table = db.table(name) if hasattr(db, "table") else db[name]  # type: ignore[index]
        tables[name] = _iter_pyaccdb_table(table)

    return table_names, tables


def _iter_pyaccdb_table(table: object) -> Iterator[dict]:
    if hasattr(table, "records"):
        records = table.records  # type: ignore[attr-defined]
        if callable(records):
            yield from records()
        else:
            yield from records
        return
    if hasattr(table, "iter_records"):
        yield from table.iter_records()  # type: ignore[attr-defined]
        return
    if hasattr(table, "rows"):
        rows = table.rows  # type: ignore[attr-defined]
        if callable(rows):
            yield from rows()
        else:
            yield from rows
        return
    raise RuntimeError("Unsupported pyaccdb table API.")


def _is_system_table(name: str) -> bool:
    return name.startswith("MSys") or name.startswith("~")


def _select_tables(
    available: Sequence[str], requested: Sequence[str] | None
) -> list[str]:
    if not requested:
        return list(available)
    requested_set = {name.strip() for name in requested if name.strip()}
    return [name for name in available if name in requested_set]


def _records_to_dataframe(records: Iterable[dict], limit: int | None) -> pd.DataFrame:
    rows = []
    count = 0
    for row in records:
        rows.append(row)
        count += 1
        if limit is not None and count >= limit:
            break
    return pd.DataFrame(rows)


def _write_table(
    df: pd.DataFrame,
    outdir: Path,
    table_name: str,
    output_format: str,
    column_mapping: dict[str, str],
    errors: list[str],
) -> Path:
    sanitized_name = _sanitize_name(table_name)
    output_path = outdir / f"{sanitized_name}.{output_format}"
    df_out = df.rename(columns=column_mapping)

    if output_format == "csv":
        df_out.to_csv(output_path, index=False)
    elif output_format == "jsonl":
        df_out.to_json(output_path, orient="records", lines=True)
    elif output_format == "parquet":
        df_out.to_parquet(output_path, index=False)
    else:
        errors.append(f"Unsupported output format: {output_format}")
    return output_path


def _write_metadata(
    outdir: Path,
    table_name: str,
    sanitized_name: str,
    column_mapping: dict[str, str],
    row_count: int | None,
    errors: list[str],
) -> Path:
    payload = {
        "original_table_name": table_name,
        "sanitized_table_name": sanitized_name,
        "extracted_at_utc": datetime.now(timezone.utc).isoformat(),
        "column_original_to_sanitized": column_mapping,
        "row_count": row_count,
        "errors": errors or None,
    }
    meta_path = outdir / f"{sanitized_name}_meta.json"
    meta_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return meta_path


def _extract_tables(
    accdb_path: Path,
    outdir: Path,
    output_format: str,
    requested_tables: Sequence[str] | None,
    include_system: bool,
    limit: int | None,
    self_test: bool,
) -> tuple[list[TableResult], list[str]]:
    errors: list[str] = []
    results: list[TableResult] = []

    access_parser_tables: dict[str, Iterator[dict]] = {}
    access_parser_names: list[str] = []
    pyaccdb_tables: dict[str, Iterator[dict]] = {}

    try:
        access_parser_names, access_parser_tables = _iter_access_parser_tables(
            accdb_path, include_system
        )
        parser_used = "access-parser"
    except Exception as exc:
        parser_used = f"access-parser unavailable ({exc})"

    try:
        _, pyaccdb_tables = _iter_pyaccdb_tables(accdb_path, include_system)
    except Exception:
        pyaccdb_tables = {}

    if not access_parser_tables and not pyaccdb_tables:
        raise RuntimeError(
            "Failed to open the Access file with access-parser and pyaccdb."
        )

    table_names = access_parser_names or list(pyaccdb_tables.keys())
    selected_tables = _select_tables(table_names, requested_tables)
    if requested_tables and not selected_tables:
        errors.append("None of the requested tables were found.")

    print(f"Using parser: {parser_used}")
    print(f"Detected tables: {', '.join(table_names) if table_names else 'None'}")

    for table_name in selected_tables:
        table_errors: list[str] = []
        sanitized_name = _sanitize_name(table_name)
        row_count: int | None = None
        output_path: Path | None = None
        columns: list[str] = []
        mapping: dict[str, str] = {}

        records_iter = access_parser_tables.get(table_name)
        fallback_iter = pyaccdb_tables.get(table_name)

        def _load_df(records: Iterator[dict]) -> pd.DataFrame:
            df_local = _records_to_dataframe(records, limit=limit)
            return df_local

        df: pd.DataFrame | None = None
        if records_iter is not None:
            try:
                df = _load_df(records_iter)
            except Exception as exc:
                table_errors.append(f"access-parser: {exc}")
                df = None

        if df is None and fallback_iter is not None:
            try:
                df = _load_df(fallback_iter)
            except Exception as exc:
                table_errors.append(f"pyaccdb: {exc}")

        if df is None:
            df = pd.DataFrame()

        row_count = int(df.shape[0])
        columns = list(df.columns)
        _, mapping = _normalize_column_names(columns)

        if self_test:
            preview = df.head(5)
            print(f"Self-test: {table_name} (rows: {row_count})")
            if not preview.empty:
                print(preview.to_string(index=False))
            else:
                print("(no rows)")
        else:
            if not table_errors:
                output_path = _write_table(
                    df, outdir, table_name, output_format, mapping, table_errors
                )
            _write_metadata(
                outdir,
                table_name,
                sanitized_name,
                mapping,
                row_count,
                table_errors,
            )

        if table_errors:
            errors.append(f"{table_name}: {', '.join(table_errors)}")

        results.append(
            TableResult(
                name=table_name,
                sanitized_name=sanitized_name,
                row_count=row_count,
                output_path=output_path,
                error="; ".join(table_errors) if table_errors else None,
            )
        )

    return results, errors


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract tables from an Access .accdb file.")
    parser.add_argument("--input", required=True, help="Path to the .accdb file.")
    parser.add_argument("--outdir", required=True, help="Output directory.")
    parser.add_argument(
        "--format",
        choices=["csv", "parquet", "jsonl"],
        default="csv",
        help="Output format (default: csv).",
    )
    parser.add_argument(
        "--tables",
        help="Comma-separated list of table names to extract (default: all user tables).",
    )
    parser.add_argument(
        "--include-system-tables",
        action="store_true",
        help="Include Access system tables.",
    )
    parser.add_argument("--limit", type=int, help="Limit rows per table.")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="List tables and preview first 5 rows (no output written).",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    accdb_path = Path(args.input)
    outdir = Path(args.outdir)

    if not accdb_path.exists():
        print(f"Input file does not exist: {accdb_path}")
        return 1

    if not args.self_test:
        outdir.mkdir(parents=True, exist_ok=True)

    requested_tables = [name.strip() for name in args.tables.split(",")] if args.tables else None

    results, errors = _extract_tables(
        accdb_path=accdb_path,
        outdir=outdir,
        output_format=args.format,
        requested_tables=requested_tables,
        include_system=args.include_system_tables,
        limit=args.limit,
        self_test=args.self_test,
    )

    print("\nSummary")
    for result in results:
        status = "OK" if not result.error else f"FAILED ({result.error})"
        output = str(result.output_path) if result.output_path else "n/a"
        print(
            f"- {result.name} -> {output} | rows: {result.row_count if result.row_count is not None else 'n/a'} | {status}"
        )

    if errors:
        print("\nFailures:")
        for err in errors:
            print(f"- {err}")
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
