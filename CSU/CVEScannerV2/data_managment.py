import sqlite3
from datetime import datetime, timedelta
import nmap_pars


def check_db():
    with sqlite3.connect('server.db') as conn:
        cursor = conn.cursor()
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS Users (
                id INTEGER PRIMARY KEY,
                tg_user INTEGER UNIQUE NOT NULL
            );

            CREATE TABLE IF NOT EXISTS Servers (
                id INTEGER PRIMARY KEY,
                domain TEXT NOT NULL UNIQUE,
                user_id INTEGER UNIQUE NOT NULL,
                FOREIGN KEY (user_id) REFERENCES Users(id)
            );

            CREATE TABLE IF NOT EXISTS Scans (
                id INTEGER PRIMARY KEY,
                server_id INTEGER NOT NULL,
                scan_time TEXT NOT NULL,
                FOREIGN KEY (server_id) REFERENCES Servers(id)
            );

            CREATE TABLE IF NOT EXISTS Software (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES Scans(id)
            );

            CREATE TABLE IF NOT EXISTS CVEs (
                id INTEGER PRIMARY KEY,
                software_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                UNIQUE(software_id, cve_id),
                FOREIGN KEY (software_id) REFERENCES Software(id)
            );

            CREATE TABLE IF NOT EXISTS ScanSchedule (
                id INTEGER PRIMARY KEY,
                user_id INTEGER UNIQUE NOT NULL,
                last_scan_date TEXT,
                period INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES Users(id)
            );
        """)


def save_scan_data(logfile: str, user_id: int, domain: str):
    parsed_data = nmap_pars.parse_log_file(logfile)

    with sqlite3.connect('server.db') as conn:
        cursor = conn.cursor()

        cursor.execute("INSERT OR IGNORE INTO Users (tg_user) VALUES (?)", (user_id,))
        cursor.execute("SELECT id FROM Users WHERE tg_user = ?", (user_id,))
        user_db_id = cursor.fetchone()[0]

        cursor.execute("SELECT id, user_id FROM Servers WHERE domain = ?", (domain,))
        domain_row = cursor.fetchone()

        if domain_row:
            domain_id, domain_owner_id = domain_row
            if domain_owner_id != user_db_id:
                raise Exception(f"Домен '{domain}' уже зарегистрирован другим пользователем (user_id={domain_owner_id}).")
            server_id = domain_id  
        else:
            cursor.execute("SELECT id FROM Servers WHERE user_id = ?", (user_db_id,))
            existing_server = cursor.fetchone()

            if existing_server:
                server_id = existing_server[0]
                cursor.execute("UPDATE Servers SET domain = ? WHERE id = ?", (domain, server_id))
            else:
                cursor.execute("INSERT INTO Servers (domain, user_id) VALUES (?, ?)", (domain, user_db_id))
                server_id = cursor.lastrowid

        scan_time = datetime.now().isoformat()
        cursor.execute("INSERT INTO Scans (server_id, scan_time) VALUES (?, ?)", (server_id, scan_time))
        scan_id = cursor.lastrowid

        for entry in parsed_data:
            port = entry['port']
            name = entry['product']
            version = entry['version']
            new_cves = {cve['id'] for cve in entry['cves']}

            cursor.execute("""
                SELECT SW.id FROM Software SW
                JOIN Scans SC ON SW.scan_id = SC.id
                WHERE SC.server_id = ? AND SW.port = ? AND SW.name = ? AND SW.version = ?
                ORDER BY SC.scan_time DESC
                LIMIT 1
            """, (server_id, port, name, version))
            existing_software = cursor.fetchone()

            if existing_software:
                old_software_id = existing_software[0]
                cursor.execute("SELECT cve_id FROM CVEs WHERE software_id = ?", (old_software_id,))
                old_cves = {row[0] for row in cursor.fetchall()}
            else:
                old_cves = set()

            added_cves = new_cves - old_cves
            if not added_cves:
                continue

            cursor.execute("""
                INSERT INTO Software (scan_id, port, name, version)
                VALUES (?, ?, ?, ?)
            """, (scan_id, port, name, version))
            new_software_id = cursor.lastrowid

            for cve_id in added_cves:
                try:
                    cursor.execute("""
                        INSERT INTO CVEs (software_id, cve_id)
                        VALUES (?, ?)
                    """, (new_software_id, cve_id))
                except sqlite3.IntegrityError:
                    pass

        cursor.execute("""
            INSERT INTO ScanSchedule (user_id, last_scan_date, period)
            VALUES (?, ?, COALESCE((SELECT period FROM ScanSchedule WHERE user_id = ?), 1))
            ON CONFLICT(user_id) DO UPDATE SET last_scan_date = excluded.last_scan_date
        """, (user_db_id, scan_time, user_db_id))



def should_scan(user_id: int) -> bool:
    with sqlite3.connect('server.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Users WHERE tg_user = ?", (user_id,))
        result = cursor.fetchone()
        if not result:
            return False
        user_db_id = result[0]

        cursor.execute("SELECT last_scan_date, period FROM ScanSchedule WHERE user_id = ?", (user_db_id,))
        row = cursor.fetchone()
        if not row:
            return True

        last_scan_date, period = row
        if last_scan_date:
            next_scan_time = datetime.fromisoformat(last_scan_date) + timedelta(days=period)
            return datetime.now() >= next_scan_time
        return True


def get_latest_results(user_id: int):
    with sqlite3.connect('server.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Users WHERE tg_user = ?", (user_id,))
        user_db_id = cursor.fetchone()[0]

        cursor.execute("""
            SELECT S.domain, Sc.scan_time, SW.port, SW.name, SW.version, C.cve_id
            FROM Servers S
            JOIN Scans Sc ON Sc.server_id = S.id
            JOIN Software SW ON SW.scan_id = Sc.id
            LEFT JOIN CVEs C ON C.software_id = SW.id
            WHERE S.user_id = ?
            ORDER BY Sc.scan_time DESC
        """, (user_db_id,))

        return cursor.fetchall()
    

def save_scan_data_manual(user_id: int, domain: str, port: int):
    with sqlite3.connect('server.db') as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM Users WHERE tg_user = ?", (user_id,))
        user_row = cursor.fetchone()
        if user_row:
            user_db_id = user_row[0]
        else:
            cursor.execute("INSERT INTO Users (tg_user) VALUES (?)", (user_id,))
            user_db_id = cursor.lastrowid

        cursor.execute("SELECT id, user_id FROM Servers WHERE domain = ?", (domain,))
        domain_row = cursor.fetchone()

        if domain_row:
            server_id, current_owner_id = domain_row
            if current_owner_id != user_db_id:
                cursor.execute("UPDATE Servers SET user_id = ? WHERE id = ?", (user_db_id, server_id))
        else:
            cursor.execute("INSERT INTO Servers (domain, user_id) VALUES (?, ?)", (domain, user_db_id))
            server_id = cursor.lastrowid

        cursor.execute("""
            SELECT SW.id FROM Software SW
            JOIN Scans SC ON SW.scan_id = SC.id
            WHERE SC.server_id = ? AND SW.port = ? AND SW.name = 'unknown' AND SW.version = 'unknown'
            LIMIT 1
        """, (server_id, port))
        already_scanned = cursor.fetchone()

        scan_time = datetime.now().isoformat()

        if already_scanned:
            cursor.execute("""
                INSERT INTO ScanSchedule (user_id, last_scan_date, period)
                VALUES (?, ?, COALESCE((SELECT period FROM ScanSchedule WHERE user_id = ?), 1))
                ON CONFLICT(user_id) DO UPDATE SET last_scan_date = excluded.last_scan_date
            """, (user_db_id, scan_time, user_db_id))
            return

        cursor.execute("INSERT INTO Scans (server_id, scan_time) VALUES (?, ?)", (server_id, scan_time))
        scan_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO Software (scan_id, port, name, version)
            VALUES (?, ?, 'unknown', 'unknown')
        """, (scan_id, port))

        cursor.execute("""
            INSERT INTO ScanSchedule (user_id, last_scan_date, period)
            VALUES (?, ?, COALESCE((SELECT period FROM ScanSchedule WHERE user_id = ?), 1))
            ON CONFLICT(user_id) DO UPDATE SET last_scan_date = excluded.last_scan_date
        """, (user_db_id, scan_time, user_db_id))


def save_scan_data_if_new(log_file, user_id, domain):
    results = nmap_pars.parse_log_file(log_file)
    if results is None:
        return False

    conn = sqlite3.connect("server.db")
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM Users WHERE tg_user = ?", (user_id,))
    row = cursor.fetchone()
    if row:
        user_db_id = row[0]
    else:
        cursor.execute("INSERT INTO Users (tg_user) VALUES (?)", (user_id,))
        user_db_id = cursor.lastrowid

    cursor.execute("SELECT id FROM Servers WHERE user_id = ? AND domain = ?", (user_db_id, domain))
    row = cursor.fetchone()
    if row:
        server_id = row[0]
    else:
        cursor.execute("INSERT INTO Servers (user_id, domain) VALUES (?, ?)", (user_db_id, domain))
        server_id = cursor.lastrowid

    new_found = False

    cursor.execute("""
        SELECT SW.port, CVE.cve_id
        FROM Software SW
        JOIN Scans SC ON SW.scan_id = SC.id
        JOIN CVEs CVE ON CVE.software_id = SW.id
        WHERE SC.server_id = ?
    """, (server_id,))
    old_by_port = {}
    for port, cve_id in cursor.fetchall():
        old_by_port.setdefault(port, set()).add(cve_id)

    new_by_port = {e['port']: {c['id'] for c in e['cves']} for e in results}

    for entry in results:
        port = entry['port']
        product = entry['product']
        version = entry['version']
        new_cves = new_by_port.get(port, set())
        old_cves = old_by_port.get(port, set())

        to_add = new_cves - old_cves
        to_remove = old_cves - new_cves

        if not to_add and not to_remove:
            continue

        scan_time = datetime.now().isoformat()
        cursor.execute("INSERT INTO Scans (server_id, scan_time) VALUES (?, ?)", (server_id, scan_time))
        scan_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO Software (scan_id, port, name, version)
            VALUES (?, ?, ?, ?)
        """, (scan_id, port, product, version))
        software_id = cursor.lastrowid

        for cid in to_add:
            cursor.execute("INSERT OR IGNORE INTO CVEs (software_id, cve_id) VALUES (?, ?)", (software_id, cid))

        if to_remove:
            cursor.execute("""
                DELETE FROM CVEs
                WHERE software_id IN (
                    SELECT SW.id FROM Software SW
                    JOIN Scans SC ON SW.scan_id = SC.id
                    WHERE SC.server_id = ? AND SW.port = ?
                )
                AND cve_id IN ({})
            """.format(", ".join("?"*len(to_remove))), (server_id, port, *to_remove))

        new_found = True

    conn.commit()
    conn.close()
    return new_found


def update_scan_data_no_vuln(user_id: int, domain: str, port: int):
    con = sqlite3.connect("server.db")
    cursor = con.cursor()

    cursor.execute("""
        SELECT id FROM Servers WHERE user_id = ? AND domain = ?
    """, (user_id, domain))
    server = cursor.fetchone()
    if not server:
        con.close()
        return
    server_id = server[0]

    cursor.execute("""
        SELECT id FROM Software WHERE server_id = ? AND port = ?
    """, (server_id, port))
    software = cursor.fetchone()
    if software:
        software_id = software[0]
        cursor.execute("DELETE FROM CVE WHERE software_id = ?", (software_id,))
        cursor.execute("UPDATE Scans SET scan_time = ? WHERE server_id = ? ORDER BY scan_time DESC LIMIT 1", (datetime.now().isoformat(), server_id))
    else:
        cursor.execute("""
            INSERT INTO Software (server_id, port, product, version)
            VALUES (?, ?, ?, ?)
        """, (server_id, port, "Неизвестно", "Неизвестно"))

    con.commit()
    con.close()
