import os
import sqlite3
from datetime import datetime

# Hakikisha logs directory ipo
LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "alerts.log")
DB_FILE = os.path.join(os.path.dirname(__file__), "..", "alerts.db")

def log_alert(message: str):
    """
    Hifadhi alert kwenye alerts.log na pia kwenye database
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Hifadhi kwenye file
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"[ERROR] Kushindwa kuandika kwenye log file: {e}")

    # 2. Hifadhi kwenye database
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (timestamp, message) VALUES (?, ?)",
            (timestamp, message)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Kushindwa kuandika alert kwenye DB: {e}")
