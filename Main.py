#!/usr/bin/env python3
"""

This programm extracts data from an CVE-XML and an NMAP-XML. Uploads this data
to a database and then joins it to get a list of possible dangerous hosts
in the scanned network.
"""
import xml.etree.ElementTree as ET
import sqlite3

def create_tables(dbcon):
    """

    Create all database tables as needed but only when they don't exist.
    :param dbcon: sqlite3 database connection
    :type dbcon: sqlite3.Connection
    :raises: TypeError
    """

    if not isinstance(dbcon, sqlite3.Connection):
        raise TypeError("parameter 'dbcon' not of type 'sqlite3.Connection'")

    cursor = dbcon.cursor()
    # creates table if not already existing
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS scanner_test (
            ipadress text,
            portnumber text,
            starttime text,
            accuracy text,
            cpe text)""")
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS cve (
            cveid text,
            cpe text,
            cvssscore text,
            accessvector text,
            authentication text,
            confimpact text,
            integrityimpact text,
            availimpact text)""")
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS join_test(
            ipadress text,
            portnumber text,
            starttime text,
            accuracy text,
            cpe2 text,
            cveid text,
            cpe text,
            cvssscore text,
            accessvector text,
            authentication text,
            confimpact text,
            integrityimpact text,
            availimpact text)""")
    dbcon.commit()
    print('tables created')


def extract_cve(cvexmlinput):
    """

    Extracts Data from the CVE XML File and returns it.
    :param cvexmlinput: XML file
    :returns: List of strings
    """
    #initialize cve tree
    cvetree = ET.parse(cvexmlinput)
    cveroot = cvetree.getroot()
    cverows = []
    for entry in cveroot.findall('./{http://scap.nist.gov/schema/feed/vulnerability/2.0}entry'):
        cveid = entry.get('id')
        cvtag = entry.find('./{http://scap.nist.gov/schema/vulnerability/0.4}cvss/{http://scap.nist.gov/schema/cvss-v2/0.2}base_metrics')
        vultag = list(entry.findall('./{http://scap.nist.gov/schema/vulnerability/0.4}vulnerable-software-list/{http://scap.nist.gov/schema/vulnerability/0.4}product'))
        if  cvtag and vultag is not None:
            cvsssc = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}score').text
            accv = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}access-vector').text
            auth = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}authentication').text
            confimp = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}confidentiality-impact').text
            intimp = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}integrity-impact').text
            avimo = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}availability-impact').text
            for vuln in vultag:
                cpe = vuln.text
                row = (cveid, cpe, cvsssc, accv, auth, confimp, intimp, avimo)
                cverows.append(row)
        elif cvtag is not None and vultag is None:
            cvsssc = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}score').text
            accv = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}access-vector').text
            auth = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}authentication').text
            confimp = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}confidentiality-impact').text
            intimp = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}integrity-impact').text
            avimo = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}availability-impact').text
            row = (cveid, None, cvsssc, accv, auth, confimp, intimp, avimo)
            cverows.append(row)
        elif cvtag is None and vultag is not None:
            for vuln in vultag:
                cpe = vuln.text
                row = (cveid, cpe, None, None, None, None, None, None)
                cverows.append(row)
        else:
            row = (cveid, None, None, None, None, None, None, None)
            cverows.append(row)
    print('extracted cve data')
    return cverows


def insert_cve_in_database(cverows, dbcon):
    """

    Uploads input data to the database.
    :param dbcon: sqlite3 database connection
    :type dbcon: sqlite3.Connection
    :raises: TypeError
    """

    if not isinstance(dbcon, sqlite3.Connection):
        raise TypeError("parameter 'dbcon' not of type 'sqlite3.Connection'")

    dbcon.executemany("INSERT INTO cve VALUES(?,?,?,?,?,?,?,?)", cverows)
    dbcon.commit()
    print('uploaded cve data')


def extract_nmap_results(nmapxmlinput):
    """

    Extracts data from NMAP-XML File and returns it.
    :param nmapxmlinput: XML File
    :returns: List of strings
    """
    # initialize xml nmaptree
    nmaptree = ET.parse(nmapxmlinput)
    nmaproot = nmaptree.getroot()
    # for variable host find all nmaptree element called host
    dbrows = []  # database rows to save
    for host in nmaproot.findall('host'):
        # add fields in xml.nmaptree to lists
        starttime = host.get('starttime')
        ipaddr = host.findall('address')[0].get('addr')
        portnumber = host.findall('./ports/port')[0].get('portid')
        os_tags = list(host.findall('./os/osmatch/osclass'))
        if len(os_tags) != 0:
            for os in os_tags:
                accu = os.get('accuracy')
                cpe_tags = list(os.findall('cpe'))
                if len(cpe_tags) != 0:
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
    print('extracted nmap data')
    return dbrows


def insert_nmap_in_database(dbrows, dbcon):
    """

    Inserts input Data into Scan Database.
    :param dbcon: sqlite3 database connection
    :type dbcon: sqlite3.Connection
    :raises: TypeError
    """

    if not isinstance(dbcon, sqlite3.Connection):
        raise TypeError("parameter 'dbcon' not of type 'sqlite3.Connection'")

    dbcon.executemany("INSERT INTO scanner_test VALUES (?,?,?,?,?)", dbrows)
    dbcon.commit()
    print('uploaded nmap data')


def delete_duplicates(dbcon):
    """

    Deletes duplicates from the Database.
    :param dbcon: sqlite3 database connection
    :type dbcon: sqlite3.Connection
    :raises: TypeError
    """

    if not isinstance(dbcon, sqlite3.Connection):
        raise TypeError("parameter 'dbcon' not of type 'sqlite3.Connection'")
    # delete unit removes duplicates by using the default uique rowid
    # Group by with all colums to get all ips and all scnas from a single ip
    cursor = dbcon.cursor()
    cursor.execute("""DELETE FROM scanner_test
            WHERE rowid NOT IN (
            SELECT MIN(rowid)
            FROM scanner_test
            GROUP BY ipadress, portnumber, starttime, accuracy, cpe)
            """)
    cursor.execute("""DELETE FROM cve
            WHERE rowid NOT IN (
            SELECT MIN(rowid)
            FROM cve
            GROUP BY cveid, cpe, cvssscore,accessvector,authentication,
            confimpact,integrityimpact,availimpact )
            """)
    cursor.execute("""DELETE FROM  join_test
            WHERE rowid NOT IN (
            SELECT MIN(rowid)
            FROM join_test
            GROUP BY ipadress, portnumber, starttime, accuracy, cpe,
            cveid, cpe2, cvssscore,accessvector,authentication,
            confimpact,integrityimpact,availimpact )
            """)
    dbcon.commit()
    print('duplicates deleted')


def cve_nmap_join(dbcon):
    """

    Joins the nmap and the cve table using the cpe  string.
    Uploads result to database.
    :param dbcon: sqlite3 database connection
    :type dbcon: sqlite3.Connection
    :raises: TypeError
    """

    if not isinstance(dbcon, sqlite3.Connection):
        raise TypeError("parameter 'dbcon' not of type 'sqlite3.Connection'")
    cursor = dbcon.cursor()
    cursor.execute("""SELECT * FROM scanner_test
            INNER JOIN cve ON scanner_test.cpe = cve.cpe
            """)
    print("cve and nmap joined")
    for row in cursor.fetchall():
        cursor.execute("INSERT INTO join_test VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ", row)
    dbcon.commit()
    print("uploaded join data")

if __name__ == "__main__":
    conn = sqlite3.connect('/usr/home/tim/Documents/scandata.db')
    create_tables(conn)

    cves = extract_cve(cvexmlinput='/usr/home/tim/Documents/nvdcve-2.0-modified.xml')
    insert_cve_in_database(cves, conn)

    nmapdata = extract_nmap_results(nmapxmlinput='/usr/home/tim/nmaptest.xml')
    insert_nmap_in_database(nmapdata, conn)

    cve_nmap_join(conn)

    delete_duplicates(conn)
    print("... done")
    conn.close()
