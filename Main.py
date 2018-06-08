#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import sqlite3

def create_tables(dbcon):
    """
    Create all database tables as needed.
    
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
            id text,
            productype text,
            cvssscore text,
            accessvector text,
            authentication text,
            confimpact text,
            integrityimpact text,
            availimpact text)""")
    dbcon.commit()


def extract_cve(dbcon):
    """
    
    Parses and uploads Data from the cve xml to the database.
    :param dbcon: sqlite3 database connection
    :type dbcon: sqlite3.Connection
    :raises: TypeError
    """
    
    if not isinstance(dbcon, sqlite3.Connection):
        raise TypeError("parameter 'dbcon' not of type 'sqlite3.Connection'")
    #initialize cve tree
    cvetree = ET.parse('/usr/home/tim/Documents/nvdcve-2.0-modified.xml')
    cveroot = cvetree.getroot()
    cverows = []
    for entry in cveroot.findall('./{http://scap.nist.gov/schema/feed/vulnerability/2.0}entry'):
        id = entry.get('id')
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
                row = (id, cpe, cvsssc, accv, auth, confimp, intimp, avimo)
                cverows.append(row)
        elif cvtag is not None and vultag is None:        
            cvsssc = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}score').text
            accv = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}access-vector').text
            auth = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}authentication').text
            confimp = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}confidentiality-impact').text
            intimp = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}integrity-impact').text
            avimo = cvtag.find('./{http://scap.nist.gov/schema/cvss-v2/0.2}availability-impact').text
            row = (id, None, cvsssc, accv, auth, confimp, intimp, avimo)
            cverows.append(row)
        elif cvtag is None and vultag is not None:
            for vuln in vultag:
                cpe = vuln.text
                row = (id, cpe, None, None, None, None, None, None)
                cverows.append(row)
        else:
            row = (id, None, None, None, None, None, None, None)
            cverows.append(row)       
    cursor = dbcon.cursor()        
    dbcon.executemany("INSERT INTO cve VALUES (?,?,?,?,?,?,?,?)",cverows)
    dbcon.commit()
      
                
def extract_nmap_results(dbcon):
    """
    
    Parses and uploads Data from the nmapscan xml to the database.
    :param dbcon: sqlite3 database connection
    :type dbcon: sqlite3.Connection
    :raises: TypeError
    """
    
    if not isinstance(dbcon, sqlite3.Connection):
        raise TypeError("parameter 'dbcon' not of type 'sqlite3.Connection'")
    # initialize xml nmaptree
    nmaptree = ET.parse('/usr/home/tim/nmaptest.xml')
    nmaproot = nmaptree.getroot()
    # for variable host find all nmaptree element called host
    for host in nmaproot.findall('host'):
        dbrows = []  # database rows to save
        # add fields in xml.nmaptree to lists
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
        cursor = dbcon.cursor()
        cursor.executemany("INSERT INTO scanner_test VALUES (?,?,?,?,?)", dbrows)
    
    dbcon.commit()


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
            GROUP BY id, productype, cvssscore,accessvector,authentication,
            confimpact,integrityimpact,availimpact )
            """)    
    dbcon.commit()


if __name__ == "__main__":
    conn = sqlite3.connect('/usr/home/tim/Documents/scandata.db')
    create_tables(conn)
    extract_cve(conn)
    #extract_nmap_results(conn)
    delete_duplicates(conn)
    print("... done")
    conn.close()
