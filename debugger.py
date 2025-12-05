import sqlite3
con = sqlite3.connect("firmae_kb.sqlite")
con.row_factory = sqlite3.Row
cur = con.cursor()

# Example: latest failures for DLINK DIR-868L
cur.execute("""
SELECT r.id, r.ts, r.brand, r.firmware, a.source, a.summary, a.content
FROM runs r
JOIN analyses a ON a.run_id = r.id
ORDER BY a.id DESC
LIMIT 20;
""")

for row in cur.fetchall():
    print(dict(row))
con.close()
