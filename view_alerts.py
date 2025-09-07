import sqlite3
import sys

DB_FILE = "alerts.db"

def view_alerts(limit=20):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Tumia jina sahihi la column: 'alert'
        cursor.execute("SELECT timestamp, message FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()

        if not rows:
            print("⚠️ Hakuna alerts zilizohifadhiwa bado.")
        else:
            print(f"\n--- {len(rows)} Latest Alerts ---")
            for row in rows:
                print(f"[{row[0]}] {row[1]}")

        conn.close()
    except Exception as e:
        print(f"[ERROR] Kushindwa kusoma alerts: {e}")

if __name__ == "__main__":
    # Angalia kama user ameweka limit
    if len(sys.argv) > 1:
        try:
            limit = int(sys.argv[1])
        except ValueError:
            print("⚠️ Tafadhali weka namba sahihi kwa limit (mfano: python view_alerts.py 50)")
            sys.exit(1)
    else:
        limit = 20

    view_alerts(limit)
