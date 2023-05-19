import sqlite3 as sl
import logging
import ast


class mispLogger:
    def __init__(self):
        logging.basicConfig(filename="logs/mispLogger.log", level=logging.ERROR,
                            format="%(asctime)s:%(levelname)s:%(message)s")
        try:
            self.con = sl.connect(
                "data/app_database.sqlite", detect_types=sl.PARSE_DECLTYPES | sl.PARSE_COLNAMES)
            self.bd = self.con.cursor()
        except:
            logging.error("Error connecting to database")
            exit(1)
        self.create_bd()

    def create_bd(self):
        with self.con:
            self.bd.execute("""
                    CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY,
                        attribute_id TEXT,
                        succeed BOOL,
                        attribute TEXT,
                        error TEXT
                    );
                """)
            self.bd.execute('PRAGMA journal_mode=wal')
            self.con.commit()

    def insert(self, data):
        with self.con:
            try:
                columns = ', '.join(data.keys())
                placeholders = ', '.join('?' * len(data))
                sql = 'INSERT INTO logs ({}) VALUES ({})'.format(
                    columns, placeholders)
                values = [int(x) if isinstance(x, bool) or isinstance(x, int)
                          else str(x) for x in data.values()]
                self.bd.execute(sql, values)
                self.con.commit()
            except Exception as e:
                # TODO afegir valor del IOC
                logging.error("Error inserting data")
                return False
        return True

    def getData(self):
        with self.con:
            try:
                self.bd.execute(
                    'SELECT * FROM logs')
                result = self.bd.fetchall()
                res = [{'attribute_id': ast.literal_eval(a[1]), 'succeed':a[2]
                        == 1, 'value':ast.literal_eval(a[3])['value'], 'error':ast.literal_eval(a[4])} for a in result]
                return res
            except:
                pass
