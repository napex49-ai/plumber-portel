"""
Plumber Loyalty Program — Code Generator (Neon Postgres Bulk Edition)
=====================================================================
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
import secrets
import csv
import time
import argparse
from datetime import datetime, timezone

# ---------------------------------------------------------------------
# Alphabet & checksum
# ---------------------------------------------------------------------

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ALPHABET_INDEX = {ch: i for i, ch in enumerate(ALPHABET)}
BODY_LENGTH = 11

def compute_checksum(body: str) -> str:
    total = 0
    for i, ch in enumerate(body):
        total += ALPHABET_INDEX[ch] * (i + 1)
    return ALPHABET[total % 32]

def generate_raw_code() -> str:
    body = "".join(secrets.choice(ALPHABET) for _ in range(BODY_LENGTH))
    return body + compute_checksum(body)

def format_code(raw_code: str) -> str:
    return f"{raw_code[0:4]}-{raw_code[4:8]}-{raw_code[8:12]}"

def unformat_code(display_code: str) -> str:
    return display_code.replace("-", "").replace(" ", "").upper()

def validate_checksum(raw_code: str) -> bool:
    if len(raw_code) != BODY_LENGTH + 1:
        return False
    body, check_char = raw_code[:-1], raw_code[-1]
    if any(ch not in ALPHABET_INDEX for ch in raw_code):
        return False
    return compute_checksum(body) == check_char

# ---------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------

def get_connection(db_url: str):
    conn = psycopg2.connect(db_url, cursor_factory=RealDictCursor)
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS codes (
                id SERIAL PRIMARY KEY,
                code VARCHAR(16) UNIQUE NOT NULL,
                denomination SMALLINT NOT NULL,
                batch_id VARCHAR(50) NOT NULL,
                status VARCHAR(20) DEFAULT 'active',
                redeemed_by_plumber_id INTEGER,
                redeemed_at TIMESTAMP
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_code ON codes(code)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_batch ON codes(batch_id)")
    conn.commit()
    return conn

# ---------------------------------------------------------------------
# Bulk Batch Generation for Cloud
# ---------------------------------------------------------------------

def generate_batch(conn, denomination: int, quantity: int, batch_id: str, max_attempts_multiplier: int = 20) -> dict:
    start = time.time()
    inserted = 0
    collisions_hit = 0
    attempts = 0

    cur = conn.cursor()
    max_attempts = quantity * max_attempts_multiplier
    chunk_size = 10000  # Generate 10,000 codes at a time

    print(f"Starting generation of {quantity} codes (₹{denomination}) in cloud...")

    while inserted < quantity and attempts < max_attempts:
        needed = quantity - inserted
        current_chunk_size = min(chunk_size, needed)
        
        # Generate unique codes locally in memory first
        local_codes = set()
        while len(local_codes) < current_chunk_size and attempts < max_attempts:
            local_codes.add(generate_raw_code())
            attempts += 1
            
        if not local_codes:
            break

        # Send the entire batch in one massive network packet
        # 4 columns specified, 4 values packed per row
        query = "INSERT INTO codes (code, denomination, batch_id, status) VALUES %s ON CONFLICT (code) DO NOTHING"
        records = [(c, denomination, batch_id, 'active') for c in local_codes]
        
        # page_size forces the library to push all 10,000 at once instead of in chunks of 100
        execute_values(cur, query, records, page_size=10000)
        
        actually_inserted = len(records)
        inserted += actually_inserted
        
        conn.commit()
        print(f" --> Inserted {inserted:,} / {quantity:,} codes...")

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

def append_to_batch(conn, batch_id: str, quantity: int, max_attempts_multiplier: int = 20) -> dict:
    cur = conn.cursor()
    cur.execute("SELECT denomination FROM codes WHERE batch_id = %s LIMIT 1", (batch_id,))
    row = cur.fetchone()
    if row is None:
        raise ValueError(f"Batch '{batch_id}' not found.")
    return generate_batch(conn, row["denomination"], quantity, batch_id, max_attempts_multiplier)

def export_batch_csv(conn, batch_id: str, out_path: str) -> int:
    print("Fetching codes from cloud to generate CSV...")
    cur = conn.cursor()
    cur.execute("SELECT code, denomination FROM codes WHERE batch_id = %s ORDER BY id", (batch_id,))
    rows = cur.fetchall()

    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["code", "denomination_inr"])
        for row in rows:
            writer.writerow([format_code(row["code"]), row["denomination"]])
    return len(rows)

def export_all_denominations_xlsx(conn, out_path: str, batch_id: str = None) -> dict:
    from openpyxl import Workbook
    from openpyxl.styles import Font

    print("Fetching codes from cloud to generate Excel file...")
    cur = conn.cursor()
    wb = Workbook()
    wb.remove(wb.active)

    counts = {}
    for denom in (10, 20, 40):
        if batch_id:
            cur.execute("SELECT code, batch_id, status FROM codes WHERE denomination = %s AND batch_id = %s ORDER BY id", (denom, batch_id))
        else:
            cur.execute("SELECT code, batch_id, status FROM codes WHERE denomination = %s ORDER BY id", (denom,))
        rows = cur.fetchall()

        sheet = wb.create_sheet(title=str(denom))
        sheet.append(["code", "batch_id", "status"])
        for cell in sheet[1]:
            cell.font = Font(bold=True)
        for row in rows:
            sheet.append([format_code(row["code"]), row["batch_id"], row["status"]])
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

    default_db = os.environ.get("DATABASE_URL")

    gen = sub.add_parser("generate")
    gen.add_argument("--denomination", type=int, required=True, choices=[10, 20, 40])
    gen.add_argument("--quantity", type=int, required=True)
    gen.add_argument("--batch", type=str, required=True)
    gen.add_argument("--db-url", type=str, default=default_db)
    gen.add_argument("--export", type=str)

    app = sub.add_parser("append")
    app.add_argument("--batch", type=str, required=True)
    app.add_argument("--quantity", type=int, required=True)
    app.add_argument("--db-url", type=str, default=default_db)
    app.add_argument("--export", type=str)

    xls = sub.add_parser("export-xlsx")
    xls.add_argument("--db-url", type=str, default=default_db)
    xls.add_argument("--output", type=str, required=True)
    xls.add_argument("--batch", type=str)

    val = sub.add_parser("validate")
    val.add_argument("code", type=str)

    args = parser.parse_args()

    if not args.db_url and args.command != "validate":
        print("Error: Provide a database URL via --db-url or set the DATABASE_URL environment variable.")
        return
        
    if args.command == "validate":
        raw = unformat_code(args.code)
        ok = validate_checksum(raw)
        print(f"{args.code} -> {'VALID checksum' if ok else 'INVALID checksum (likely a typo)'}")
        return

    conn = get_connection(args.db_url)

    if args.command == "generate":
        stats = generate_batch(conn, args.denomination, args.quantity, args.batch)
        for k, v in stats.items():
            print(f"  {k}: {v}")
        if args.export:
            n = export_batch_csv(conn, args.batch, args.export)
            print(f"Exported {n} codes to {args.export}")

    elif args.command == "append":
        stats = append_to_batch(conn, args.batch, args.quantity)
        for k, v in stats.items():
            print(f"  {k}: {v}")
        if args.export:
            n = export_batch_csv(conn, args.batch, args.export)
            print(f"Exported FULL batch ({n} codes total) to {args.export}")

    elif args.command == "export-xlsx":
        counts = export_all_denominations_xlsx(conn, args.output, batch_id=args.batch)
        print(f"Exported to {args.output}:")
        for denom, n in counts.items():
            print(f"  ₹{denom} tab: {n} codes")

    conn.close()

if __name__ == "__main__":
    main()