import sqlite3

DB_FILE = "alerts.db"

def setup_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create table alerts ikiwa haipo
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        message TEXT NOT NULL
    )
    """)
    
    conn.commit()
    conn.close()
    print("✅ Database 'alerts.db' na table 'alerts' vimeundwa vizuri.")

if __name__ == "__main__":
    setup_database()
