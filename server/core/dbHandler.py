import mysql.connector as mysql
from core import CryptoHandler
import os


class db(object):
    def __init__(self, host: str | None = None, username: str | None = None, password: str | None = None, database: str | None = None) -> None:
        self.db = mysql.connect(
            host=host or os.environ.get("CHAT_DB_HOST", "localhost"),
            username=username or os.environ.get("CHAT_DB_USER", "root"),
            password=password or os.environ.get("CHAT_DB_PASSWD", "root"),
            database=database or os.environ.get("CHAT_DB_NAME", "test")
        )
        
        self.crypto = CryptoHandler()
        

    def checkUser(self, username: str) -> bool:
        cursor = self.db.cursor()
        
        cursor.execute("SELECT 1 FROM users WHERE username='%s'", (username, ))
        res = cursor.fetchone()
        
        cursor.close()

        if res is None:
            return False
        
        return len(res) == 1 and res[0] == True

        
    def checkPw(self, username: str, password: str, silent: bool = False) -> bool:
        cursor = self.db.cursor()
        
        cursor.execute("SELECT password FROM credentials INNER JOIN (users) ON (users.UserID) = (credentials.user) WHERE username='%s' LIMIT 1", (username,))
        hs_passwd = cursor.fetchone()
        
        cursor.close()
        
        if hs_passwd is None or len(hs_passwd) == 0:
            if silent:
                return False
            raise RuntimeError("Database Response is NULL")
                
        return self.crypto.Bcrypt_Check(password, hs_passwd)


    def checkBan(self, username, silent: bool = False) -> bool:
        cursor = self.db.cursor()
        
        cursor.execute("SELECT banned FROM users WHERE username=%s", (username, ))
        res = cursor.fetchone()
        
        cursor.close()
        
        if res is None or len(res) == 0:
            if silent:
                return False
            raise RuntimeError("Database response is NULL")
        
        return res[0]