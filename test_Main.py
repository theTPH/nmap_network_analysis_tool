import Main
import unittest
import sqlite3
import os



class TestMain (unittest.TestCase):
        
    def test_extract_cve(self):
        actual = Main.extract_cve('/usr/home/tim/Documents/cveunit.xml')
        expected = [('CVE-2005-4900', 'cpe:/a:google:chrome:47.0.2526.111', '4.3', 'NETWORK', 'NONE', 'PARTIAL', 'NONE', 'NONE'),                                                                         
                    ('CVE-2012-3350', 'cpe:/a:valarsoft:webmatic:3.1.1', '6.8', 'NETWORK', 'NONE', 'PARTIAL', 'PARTIAL', 'PARTIAL'),                                                                
                    ('CVE-2014-10068',None, None, None, None, None, None, None)]
        self.assertListEqual(actual, expected)           
                    

    def test_extract_nmap_results(self):
        actual = Main.extract_nmap_results('/usr/home/tim/Documents/nmapunit.xml')
        expected = [('10.15.0.0', '443', '1527667881', '86', 'cpe:/h:asus:rt-53n'),
                    ('10.15.0.0', '443', '1527667881', '86', 'cpe:/o:cisco:pix_os:6'),                                                                                                                    
                    ('10.15.0.0', '443', '1527667881', '85', 'cpe:/h:cisco:6506_router'),                                                                                                                 
                    ('10.15.0.0', '443', '1527667881', '85', 'cpe:/o:cisco:ios:12.2'),                                                                                                                    
                    ('10.15.0.0', '443', '1527667881', '85', 'cpe:/h:cisco:catalyst_2960'),
                    ('10.15.0.0', '443', '1527667881', '85', 'cpe:/o:cisco:ios:12.2'),                                                                                                             
                    ('10.15.0.0', '443', '1527667881', '85', 'cpe:/o:cisco:nx_os:4.0'),                                                                                                             
                    ('10.15.0.0', '443', '1527667881', '85', None),
                    ('10.15.0.0', '443', '1527667881', '85', 'cpe:/o:hp:hp-ux:11.11'),
                    ('10.15.0.0', '443', '1527667881', '85', 'cpe:/o:microsoft:windows_server_2003::sp2'),
                    ('10.15.0.0', '443', '1527667881', '85', 'cpe:/h:paloalto:pa-500'),
                    ('10.15.0.0', '443', '1527667881', '85', 'cpe:/h:vodafone:easybox_802'),
                    ('10.15.0.1', '443', '1527667881', None, None)]

        
        self.assertEqual(actual, expected)


    def test_create_tables(self):
        conn = sqlite3.connect('/usr/home/tim/Documents/test.db')
        cursor = conn.cursor()
        Main.create_tables(conn)
        
        cursor.execute("INSERT INTO cve VALUES(1,2,3,4,5,6,7,8)")
        cursor.execute('SELECT * FROM cve')
        actual = cursor.fetchall()
        expected = [('1', '2', '3', '4', '5', '6' ,'7', '8')]
        self.assertEqual(actual, expected)
        
        cursor.execute("INSERT INTO scanner_test VALUES(1,2,3,4,5)")
        cursor.execute('SELECT * FROM scanner_test')
        actual = cursor.fetchall()
        expected = [('1', '2', '3', '4', '5')]
        self.assertEqual(actual, expected)   
        
        cursor.execute("INSERT INTO join_test VALUES(1,2,3,4,5,6,7,8,9,10,11,12,13)")
        cursor.execute('SELECT * FROM join_test')
        actual = cursor.fetchall()
        expected = [('1', '2', '3', '4', '5', '6' ,'7', '8','9','10','11','12','13')]
        
        self.assertEqual(actual, expected)
        os.remove('/usr/home/tim/Documents/test.db')


    def test_insert_cve_in_database(self):
        conn = sqlite3.connect('/usr/home/tim/Documents/test.db')
        Main.create_tables(conn)
        cursor = conn.cursor()
        input = [('1', '2', '3', '4', '5', '6' ,'7', '8'),
                 ('1', '2', '3', '4', '5', '6' ,'7', '8')]
        Main.insert_cve_in_database(input, conn)
        cursor.execute('SELECT * FROM cve')
        actual = cursor.fetchall()
        expected = [('1', '2', '3', '4', '5', '6' ,'7', '8'),
                    ('1', '2', '3', '4', '5', '6' ,'7', '8')]
        self.assertListEqual(actual, expected)
        os.remove('/usr/home/tim/Documents/test.db')
        
        
    def test_insert_nmap_in_database(self):
        conn = sqlite3.connect('/usr/home/tim/Documents/test.db')
        Main.create_tables(conn)
        cursor = conn.cursor()
        input = [('1', '2', '3', '4', '5'),
                 ('1', '2', '3', '4', '5')]
        Main.insert_nmap_in_database(input, conn)
        cursor.execute('SELECT * FROM scanner_test')
        actual = cursor.fetchall()
        expected = [('1', '2', '3', '4', '5'),
                    ('1', '2', '3', '4', '5')]
        self.assertListEqual(actual, expected)
        os.remove('/usr/home/tim/Documents/test.db')
        
    def test_delete_duplicates(self):
        conn = sqlite3.connect('/usr/home/tim/Documents/test.db')
        cursor = conn.cursor()
        Main.create_tables(conn)
        cursor.execute("INSERT INTO cve VALUES(1,2,3,4,5,6,7,8)")
        cursor.execute("INSERT INTO cve VALUES(1,2,3,4,5,6,7,8)")
        Main.delete_duplicates(conn)
        cursor.execute('SELECT * FROM cve')
        actual = cursor.fetchall()
        expected = [('1', '2', '3', '4', '5', '6' ,'7', '8')]
        self.assertEqual(actual, expected)
        os.remove('/usr/home/tim/Documents/test.db')
        
if __name__ == '__main__':
    unittest.main()
    