# firmae_lib/kb.py
import os
import json
import sqlite3
from datetime import datetime

def kb_init(db_path: str) -> None:
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.executescript("""
    PRAGMA journal_mode=WAL;

    CREATE TABLE IF NOT EXISTS runs (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      ts           TEXT NOT NULL,
      brand        TEXT,
      model        TEXT,
      firmware     TEXT,
      iid_dir      TEXT,
      exit_code    INTEGER,
      result_bool  INTEGER,
      duration_sec REAL
    );

    CREATE TABLE IF NOT EXISTS analyses (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id       INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
      at_ts        TEXT NOT NULL,
      source       TEXT NOT NULL,   -- 'heuristic' | 'llm' | 'summary'
      summary      TEXT,
      content      TEXT,
      reasons_json TEXT
    );

    CREATE VIRTUAL TABLE IF NOT EXISTS analyses_fts USING fts5(
      summary, content, content='analyses', content_rowid='id'
    );
    """)
    con.commit()
    con.close()

def kb_insert_run(
    db_path: str,
    *,
    brand: str | None,
    model: str | None,
    firmware: str,
    iid_dir: str | None,
    exit_code: int,
    result_bool: bool | None,
    duration_sec: float
) -> int:
    kb_init(db_path)
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("""
      INSERT INTO runs(ts, brand, model, firmware, iid_dir, exit_code, result_bool, duration_sec)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
      datetime.utcnow().isoformat(timespec="seconds") + "Z",
      brand, model, firmware, iid_dir, int(exit_code),
      None if result_bool is None else (1 if result_bool else 0),
      float(duration_sec),
    ))
    run_id = cur.lastrowid
    con.commit()
    con.close()
    return run_id

def kb_insert_analysis(
    db_path: str,
    *,
    run_id: int,
    source: str,
    summary: str | None,
    content: str,
    reasons_json: dict | None = None,
    max_content: int = 200_000
) -> int:
    kb_init(db_path)
    bounded = content if len(content) <= max_content else (content[:max_content] + "\n\n[truncated]")
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("""
      INSERT INTO analyses(run_id, at_ts, source, summary, content, reasons_json)
      VALUES (?, ?, ?, ?, ?, ?)
    """, (
      run_id,
      datetime.utcnow().isoformat(timespec="seconds") + "Z",
      source,
      summary,
      bounded,
      json.dumps(reasons_json, ensure_ascii=False) if isinstance(reasons_json, dict) else reasons_json
    ))
    rowid = cur.lastrowid
    cur.execute("INSERT INTO analyses_fts(rowid, summary, content) VALUES (?, ?, ?)",
                (rowid, summary or "", bounded))
    con.commit()
    con.close()
    return rowid
