import sqlite3
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle, SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def export_user_scan_results_pdf(user_id: int, output_path: str = None) -> str:
    if output_path is None:
        output_path = f"user_{user_id}_scan_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    conn = sqlite3.connect('server.db')
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM Users WHERE tg_user = ?", (user_id,))
    result = cursor.fetchone()
    if not result:
        raise ValueError("User not found in database.")
    user_db_id = result[0]

    cursor.execute("""
        SELECT S.domain, Sc.scan_time, SW.port, SW.name, SW.version, C.cve_id
        FROM Servers S
        JOIN Scans Sc ON Sc.server_id = S.id
        JOIN Software SW ON SW.scan_id = Sc.id
        LEFT JOIN CVEs C ON C.software_id = SW.id
        WHERE S.user_id = ?
        ORDER BY Sc.scan_time DESC
    """, (user_db_id,))

    data = cursor.fetchall()
    conn.close()

    doc = SimpleDocTemplate(output_path, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()

    #now_formatted = datetime.now().strftime('%d.%m.%Y %H:%M')
    title = Paragraph(f"User Scan Report <br/><small>", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))

    if not data:
        elements.append(Paragraph("No data to display.", styles['Normal']))
    else:
        table_data = [['Domain', 'Scan Date', 'Port', 'Software', 'Version', 'CVE']]
        for row in data:
            domain, scan_time_str, port, name, version, cve = row
            try:
                scan_time = datetime.fromisoformat(scan_time_str)
                formatted_time = scan_time.strftime('%d.%m.%Y %H:%M')
            except Exception:
                formatted_time = scan_time_str

            table_data.append([
                domain,
                formatted_time,
                port if port is not None else '-',
                name if name else '-',
                version if version else '-',
                cve if cve else '-',
            ])


        table = Table(table_data, repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
        ]))
        elements.append(table)

    doc.build(elements)
    return output_path
