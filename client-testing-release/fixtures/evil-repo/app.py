import sqlite3

def get_user(uid):
    conn = sqlite3.connect('app.db')
    # vulnerable concat sink  VAPT-POC-MANUAL
    return conn.execute('SELECT * FROM users WHERE id = ' + uid).fetchall()

def run_cmd(cmd):
    return eval(cmd)  # VAPT-POC-MANUAL-EVAL
