#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import sqlite3

# initialise variables to store data in lists
start = []
ip = []
port = []
n = 0
# initialize xml tree
tree = ET.parse('/usr/home/tim/nmaptest.xml')
root = tree.getroot()
# connect to the database and create cursor item that interacts with it
conn = sqlite3.connect('/usr/home/tim/Documents/scandata.db')
cursor = conn.cursor()

# creates table if not alredy existing
cursor.execute(
    """CREATE TABLE IF NOT EXISTS scanner (
        ipadress text,
        portnumber text,
        starttime text)""")

# for variable host find all tree element called host
for host in root.findall('host'):
    # add fields in xml.tree to lists
    start.append(host.get('starttime'))
    ip.append(host.findall('address')[0].get('addr'))
    port.append(host.findall('./ports/port')[0].get('portid'))

for n in range(0, len(ip)):
    cursor.execute(
        "INSERT INTO scanner VALUES (?, ?, ?)", (ip[n], port[n], start[n]))
conn.commit()

# delete unit removes duplicates by using the default uique rowid
# Group by with all colums to get all ips and all scnas from a single ip
cursor.execute("""DELETE FROM scanner
        WHERE rowid NOT IN (
        SELECT MIN(rowid)
        FROM scanner
        GROUP BY ipadress, portnumber, starttime)
        """)
conn.commit()

cursor.execute('SELECT * FROM scanner')
for row in cursor.fetchall():
    print(row)
conn.commit()
conn.close
