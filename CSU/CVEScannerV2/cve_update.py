import os
import asyncio
import subprocess
from datetime import datetime, timedelta
import sqlite3

def CheckDB():
    con = sqlite3.connect("last_date.db")
    cursor = con.cursor()
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS Date(
                   id INTEGER PRIMARY KEY,
                   last_date TIME STUMP)
            """)
    
    con.commit()
    con.close()

def CheckLastDate():
    con = sqlite3.connect("last_date.db")
    cursor = con.cursor()
    cursor.execute("SELECT last_date FROM Date ORDER BY id DESC LIMIT 1")

    res = cursor.fetchone()

    con.commit()
    con.close()
    if res:
        return res[0]
    else:
        return None
    

def StartCommand():
    con = sqlite3.connect("last_date.db")
    cursor = con.cursor()

    last_date = CheckLastDate()
    if last_date:
        last_date = datetime.fromisoformat(last_date) + timedelta(days=2)
    else:
        last_date = datetime.now()

    if datetime.now() >= last_date:
        cursor.execute("INSERT INTO Date (last_date) VALUES (?)", (datetime.now().isoformat(),))
        subprocess.run(["python", "extra/database.py"])
    else:
        print("Data base have a last version update")

    con.commit()
    con.close()

async def main():
    CheckDB()
    StartCommand()


if __name__ == "__main__":
    asyncio.run(main())