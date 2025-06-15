import sqlite3
import nmap_pars

import asyncio
from datetime import datetime, timedelta

def CheckDB():
	mainDB = sqlite3.connect('server.db')
	mainDB_cursor = mainDB.cursor()

	mainDB_cursor.execute("""
		            CREATE TABLE IF NOT EXISTS Server(
		              id INTEGER PRIMARY KEY,
		              domain TEXT NOT NULL, 
		              at TEXT NOT NULL,
		              tg_user INTEGER NOT NULL) 
		            """)

	mainDB_cursor.execute("""
		            CREATE TABLE IF NOT EXISTS Software(
		              id INTEGER PRIMARY KEY,
		              port INTEGER NOT NULL,
		              name TEXT NOT NULL,
		              version TEXT NOT NULL,
		              server_id INTEGER NOT NULL,
		              vs INTEGER NOT NULL)  
		            """)

	mainDB_cursor.execute("""
		            CREATE TABLE IF NOT EXISTS VersionSoftware(
		              id INTEGER PRIMARY KEY,
		              name TEXT NOT NULL,
		              version TEXT NOT NULL,
		              cve_id TEXT NOT NULL)  
		            """)
	
	mainDB_cursor.execute("""
        CREATE TABLE IF NOT EXISTS ScanSchedule(
            id INTEGER PRIMARY KEY,
            tg_user INTEGER NOT NULL,
            last_scan_date TIME STUMP,
            period INTEGER NOT NULL)  
    """)

	mainDB.commit()
	mainDB.close()


def inData(logfile: str, user_id: int):
	mainDB = sqlite3.connect('server.db')
	mainDB_cursor = mainDB.cursor()

	'''mainDB_cursor.execute("""
		            CREATE TABLE IF NOT EXISTS Server(
		              id INTEGER PRIMARY KEY,
		              domain TEXT NOT NULL, 
		              at TEXT NOT NULL,
		              tg_user INTEGER NOT NULL) 
		            """)

	mainDB_cursor.execute("""
		            CREATE TABLE IF NOT EXISTS Software(
		              id INTEGER PRIMARY KEY,
		              port INTEGER NOT NULL,
		              name TEXT NOT NULL,
		              version TEXT NOT NULL,
		              server_id INTEGER NOT NULL,
		              vs INTEGER NOT NULL)  
		            """)

	mainDB_cursor.execute("""
		            CREATE TABLE IF NOT EXISTS VersionSoftware(
		              id INTEGER PRIMARY KEY,
		              name TEXT NOT NULL,
		              version TEXT NOT NULL,
		              cve_id TEXT NOT NULL)  
		            """)
	
	mainDB_cursor.execute("""
					CREATE TABLE IF NOT EXISTS ScanSchedule(
					  id INTEGER PRIMARY KEY,
					  tg_user INTEGER NOT NULL,
					  last_scan_date TIME STUMP,
					  period INTEGER NOT NULL)  
    				""")'''

	parsed_data = nmap_pars.parse_log_file(f'{logfile}')
	# Вставка данных в таблицы
	for data in parsed_data:
	    # Вставка в таблицу Software
		mainDB_cursor.execute("""
			INSERT INTO Software (port, name, version, server_id, vs)
			VALUES (?, ?, ?, ?, ?)
	    	""", (data['port'], data['product'], data['version'], 1, 1))  # Замените server_id и vs на нужные значения

	    # Получение id последней вставленной записи
		#software_id = mainDB_cursor.lastrowid

	    # Вставка CVE ID в таблицу VersionSoftware
		for cve in data['cves']:
			mainDB_cursor.execute("""
			INSERT INTO VersionSoftware (name, version, cve_id)
		    VALUES (?, ?, ?)
		""", (data['product'], data['version'], cve['id']))

	mainDB_cursor.execute("SELECT tg_user FROM Server")
	tg_user_list = mainDB_cursor.fetchone()

	for tg_user in tg_user_list:
		if user_id == tg_user:
			mainDB_cursor.execute("SELECT last_scan_date, period FROM ScanSchedule WHERE tg_user = ?", (user_id))
			last_date, period = mainDB_cursor.fetchone()
			if last_date:
				last_date = datetime.fromisoformat(last_date) + timedelta(days=period)
			else:
				last_date = datetime.now()

			if datetime.now() >= last_date:
				return 1
			else:
				return None

	mainDB.commit()
	mainDB.close()
	
#inData('logfile.log')

#New

