"""
Plumber Loyalty Program — Code Generator (Phase 2)
===================================================

Generates unique, checksum-protected redemption codes for the loyalty
program, stores them in a local SQLite database (acts as your "codes"
table until you move to Supabase/Postgres — same schema, easy migration
later), and exports a batch as CSV ready for label printing.

Code format
-----------
12 characters total, shown to humans as: XXXX-XXXX-XXXX
  - First 11 characters: randomly generated from a 32-symbol alphabet
    that excludes visually-confusing letters (I, L, O, U are dropped;
    Crockford's Base32 alphabet).
  - 12th character: a checksum character, computed from the first 11,
    used to instantly catch typos (does NOT provide fraud protection —
    that comes from the database "already redeemed" check + rate
    limiting on the portal, described in the main guide).

Run this file directly for a demo, or import the functions into your
own admin script / web page backend.
"""

import sqlite3
import secrets
import csv
import time
import argparse
from datetime import datetime, timezone

# ---------------------------------------------------------------------
# Alphabet & checksum
# ---------------------------------------------------------------------

# Crockford's Base32 alphabet: excludes I, L, O, U to avoid confusion
# with 1, 1, 0, and to avoid forming awkward words.
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ALPHABET_INDEX = {ch: i for i, ch in enumerate(ALPHABET)}
BODY_LENGTH = 11  # random characters before the checksum character


def compute_checksum(body: str) -> str:
    """Weighted mod-32 checksum over the body characters.

    Catches single-character substitution errors and most adjacent
    transpositions — enough to tell a plumber "you mistyped the code"
    vs. "this code doesn't exist in our system".
    """
    total = 0
    for i, ch in enumerate(body):
        total += ALPHABET_INDEX[ch] * (i + 1)
    return ALPHABET[total % 32]


def generate_raw_code() -> str:
    """Generate one 12-char code (11 random + 1 checksum), no hyphens."""
    body = "".join(secrets.choice(ALPHABET) for _ in range(BODY_LENGTH))
    return body + compute_checksum(body)


def format_code(raw_code: str) -> str:
    """Turn 'ABCD1234EFGH' style 12-char code into 'ABCD-1234-EFGH'."""
    return f"{raw_code[0:4]}-{raw_code[4:8]}-{raw_code[8:12]}"


def unformat_code(display_code: str) -> str:
    """Strip hyphens/spaces and uppercase — call this on whatever the
    plumber types in before validating/looking it up."""
    return display_code.replace("-", "").replace(" ", "").upper()


def validate_checksum(raw_code: str) -> bool:
    """True if the checksum character matches the body. This is a fast,
    no-database check you should run BEFORE hitting the DB, so obvious
    typos get an instant 'check the code again' message."""
    if len(raw_code) != BODY_LENGTH + 1:
        return False
    body, check_char = raw_code[:-1], raw_code[-1]
    if any(ch not in ALPHABET_INDEX for ch in raw_code):
        return False
    return compute_checksum(body) == check_char


# ---------------------------------------------------------------------
# Database (SQLite for now — same columns you'd use in Postgres/Supabase)
# ---------------------------------------------------------------------

def get_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            denomination INTEGER NOT NULL,
            batch_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'unused',
            assigned_distributor_id TEXT,
            redeemed_by_plumber_id TEXT,
            redeemed_at TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_codes_code ON codes(code)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_codes_batch ON codes(batch_id)")
    conn.commit()
    return conn


# ---------------------------------------------------------------------
# Batch generation with collision checking
# ---------------------------------------------------------------------

def generate_batch(conn: sqlite3.Connection, denomination: int, quantity: int,
                    batch_id: str, max_attempts_multiplier: int = 20) -> dict:
    """
    Generates `quantity` unique codes for the given denomination/batch,
    checking collisions against the DB (and within this batch) before
    insert. Returns stats about the run.
    """
    start = time.time()
    inserted = 0
    collisions_hit = 0
    attempts = 0
    seen_this_run = set()
    created_at = datetime.now(timezone.utc).isoformat()

    cur = conn.cursor()
    max_attempts = quantity * max_attempts_multiplier

    while inserted < quantity and attempts < max_attempts:
        attempts += 1
        raw = generate_raw_code()

        if raw in seen_this_run:
            collisions_hit += 1
            continue

        cur.execute("SELECT 1 FROM codes WHERE code = ?", (raw,))
        if cur.fetchone() is not None:
            collisions_hit += 1
            continue

        seen_this_run.add(raw)
        cur.execute(
            """INSERT INTO codes (code, denomination, batch_id, status, created_at)
               VALUES (?, ?, ?, 'unused', ?)""",
            (raw, denomination, batch_id, created_at),
        )
        inserted += 1

    conn.commit()
    elapsed = time.time() - start

    return {
        "batch_id": batch_id,
        "denomination": denomination,
        "requested": quantity,
        "inserted": inserted,
        "attempts": attempts,
        "collisions_hit": collisions_hit,
        "elapsed_seconds": round(elapsed, 3),
        "codes_per_second": round(inserted / elapsed, 1) if elapsed > 0 else None,
    }


# ---------------------------------------------------------------------
# CSV export for label printing
# ---------------------------------------------------------------------

def append_to_batch(conn: sqlite3.Connection, batch_id: str, quantity: int,
                     max_attempts_multiplier: int = 20) -> dict:
    """
    Adds `quantity` MORE codes to an existing batch_id. Denomination is
    read from the batch's existing rows, so you don't need to repeat it.
    Uniqueness is checked against the ENTIRE database, not just this
    batch, so these new codes can't collide with B2026-08-A or any
    other batch you've ever generated.
    """
    cur = conn.cursor()
    cur.execute("SELECT denomination FROM codes WHERE batch_id = ? LIMIT 1", (batch_id,))
    row = cur.fetchone()
    if row is None:
        raise ValueError(f"Batch '{batch_id}' not found — check the batch name, "
                          f"or use 'generate' to create it fresh.")
    denomination = row[0]
    return generate_batch(conn, denomination, quantity, batch_id, max_attempts_multiplier)


def export_batch_csv(conn: sqlite3.Connection, batch_id: str, out_path: str) -> int:
    """Exports every code in a batch as a printable CSV: just the
    display code and denomination — no internal IDs or metadata should
    ever go to a label-printing vendor."""
    cur = conn.cursor()
    cur.execute(
        "SELECT code, denomination FROM codes WHERE batch_id = ? ORDER BY id",
        (batch_id,),
    )
    rows = cur.fetchall()

    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["code", "denomination_inr"])
        for raw_code, denomination in rows:
            writer.writerow([format_code(raw_code), denomination])

    return len(rows)


def export_all_denominations_xlsx(conn: sqlite3.Connection, out_path: str,
                                   batch_id: str = None) -> dict:
    """
    Exports codes into ONE .xlsx workbook, with a separate sheet per
    denomination (10, 20, 40). Each sheet only ever contains codes for
    that value — and since uniqueness is enforced across the whole
    database (not per-denomination), a code can never appear on more
    than one sheet.

    If batch_id is given, only that batch's codes are exported (still
    split across sheets by denomination). If omitted, ALL codes in the
    database are exported.
    """
    from openpyxl import Workbook
    from openpyxl.styles import Font

    cur = conn.cursor()
    wb = Workbook()
    wb.remove(wb.active)  # remove default blank sheet, we add our own below

    counts = {}
    for denom in (10, 20, 40):
        if batch_id:
            cur.execute(
                "SELECT code, batch_id, status FROM codes WHERE denomination = ? AND batch_id = ? ORDER BY id",
                (denom, batch_id),
            )
        else:
            cur.execute(
                "SELECT code, batch_id, status FROM codes WHERE denomination = ? ORDER BY id",
                (denom,),
            )
        rows = cur.fetchall()

        sheet = wb.create_sheet(title=str(denom))
        sheet.append(["code", "batch_id", "status"])
        for cell in sheet[1]:
            cell.font = Font(bold=True)
        for raw_code, b_id, status in rows:
            sheet.append([format_code(raw_code), b_id, status])
        sheet.column_dimensions["A"].width = 16
        sheet.column_dimensions["B"].width = 18
        sheet.column_dimensions["C"].width = 10

        counts[denom] = len(rows)

    wb.save(out_path)
    return counts


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Loyalty program code generator")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Generate a batch of codes")
    gen.add_argument("--denomination", type=int, required=True, choices=[10, 20, 40])
    gen.add_argument("--quantity", type=int, required=True)
    gen.add_argument("--batch", type=str, required=True, help="Batch ID, e.g. B2026-07-A")
    gen.add_argument("--db", type=str, default="codes.db")
    gen.add_argument("--export", type=str, help="CSV path to export after generation")

    app = sub.add_parser("append", help="Add more codes to an existing batch")
    app.add_argument("--batch", type=str, required=True, help="Existing batch ID to top up")
    app.add_argument("--quantity", type=int, required=True)
    app.add_argument("--db", type=str, default="codes.db")
    app.add_argument("--export", type=str, help="CSV path to export the FULL (old+new) batch after appending")

    val = sub.add_parser("validate", help="Check a code's checksum (no DB lookup)")
    val.add_argument("code", type=str)

    imp = sub.add_parser("import-csv", help="Load an external CSV of codes into the DB (e.g. to restore a lost db, or merge in a batch made elsewhere)")
    imp.add_argument("--file", type=str, required=True, help="CSV with columns: code,denomination_inr")
    imp.add_argument("--batch", type=str, required=True, help="Batch ID to tag these imported codes with")
    imp.add_argument("--db", type=str, default="codes.db")

    xls = sub.add_parser("export-xlsx", help="Export codes into one Excel file with a separate tab per denomination (10/20/40)")
    xls.add_argument("--db", type=str, default="codes.db")
    xls.add_argument("--output", type=str, required=True, help="Output .xlsx path")
    xls.add_argument("--batch", type=str, help="Only export this batch (omit to export ALL codes ever generated)")

    args = parser.parse_args()

    if args.command == "generate":
        conn = get_connection(args.db)
        stats = generate_batch(conn, args.denomination, args.quantity, args.batch)
        print("Batch generation complete:")
        for k, v in stats.items():
            print(f"  {k}: {v}")
        if args.export:
            n = export_batch_csv(conn, args.batch, args.export)
            print(f"Exported {n} codes to {args.export}")
        conn.close()

    elif args.command == "append":
        conn = get_connection(args.db)
        stats = append_to_batch(conn, args.batch, args.quantity)
        print(f"Appended to batch '{args.batch}':")
        for k, v in stats.items():
            print(f"  {k}: {v}")
        if args.export:
            n = export_batch_csv(conn, args.batch, args.export)
            print(f"Exported FULL batch ({n} codes total, old+new) to {args.export}")
        conn.close()

    elif args.command == "validate":
        raw = unformat_code(args.code)
        ok = validate_checksum(raw)
        print(f"{args.code} -> {'VALID checksum' if ok else 'INVALID checksum (likely a typo)'}")

    elif args.command == "import-csv":
        conn = get_connection(args.db)
        cur = conn.cursor()
        created_at = datetime.now(timezone.utc).isoformat()
        imported, skipped = 0, 0
        with open(args.file, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw = unformat_code(row["code"])
                denomination = int(row["denomination_inr"])
                cur.execute("SELECT 1 FROM codes WHERE code = ?", (raw,))
                if cur.fetchone() is not None:
                    skipped += 1
                    continue
                cur.execute(
                    """INSERT INTO codes (code, denomination, batch_id, status, created_at)
                       VALUES (?, ?, ?, 'unused', ?)""",
                    (raw, denomination, args.batch, created_at),
                )
                imported += 1
        conn.commit()
        print(f"Imported {imported} codes into batch '{args.batch}' ({skipped} already existed, skipped)")
        conn.close()

    elif args.command == "export-xlsx":
        conn = get_connection(args.db)
        counts = export_all_denominations_xlsx(conn, args.output, batch_id=args.batch)
        print(f"Exported to {args.output}:")
        for denom, n in counts.items():
            print(f"  ₹{denom} tab: {n} codes")
        conn.close()


if __name__ == "__main__":
    main()
