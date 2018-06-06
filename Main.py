#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import sqlite3


# initialize xml tree
tree = ET.parse('/usr/home/tim/nmaptest.xml')
root = tree.getroot()
# connect to the database and create cursor item that interacts with it
conn = sqlite3.connect('/usr/home/tim/Documents/scandata.db')
cursor = conn.cursor()

# creates table if not alredy existing
cursor.execute(
    """CREATE TABLE IF NOT EXISTS scanner_test (
        ipadress text,
        portnumber text,
        starttime text,
        accuracy text,
        cpe text)""")

# for variable host find all tree element called host
for host in root.findall('host'):
    dbrows = []  # database rows to save
    # add fields in xml.tree to lists
    starttime = host.get('starttime')
    ipaddr = host.findall('address')[0].get('addr')
    portnumber = host.findall('./ports/port')[0].get('portid')
    os_tags =list(host.findall('./os/osmatch/osclass'))
    if 0 != len(os_tags):
        for os in os_tags:
            accu = os.get('accuracy')
            cpe_tags = list(os.findall('cpe'))
            if 0 != len(cpe_tags):
                for tag in cpe_tags:
                    cpe = tag.text
                    row = (ipaddr, portnumber, starttime, accu, cpe)
                    dbrows.append(row)
            else:
                row = (ipaddr, portnumber, starttime, accu, '')
                dbrows.append(row)
    else:
        row = (ipaddr, portnumber, starttime, '', '')
        dbrows.append(row)

    cursor.executemany("INSERT INTO scanner_test VALUES (?,?,?,?,?)", dbrows)

conn.commit()

# delete unit removes duplicates by using the default uique rowid
# Group by with all colums to get all ips and all scnas from a single ip
cursor.execute("""DELETE FROM scanner_test
        WHERE rowid NOT IN (
        SELECT MIN(rowid)
        FROM scanner_test
        GROUP BY ipadress, portnumber, starttime, accuracy, cpe)
        """)
conn.commit()
print("... done")
conn.close()
