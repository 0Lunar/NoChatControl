import mysql.connector as mysql
from core import CryptoHandler
import os
from uuid import uuid4
from datetime import datetime


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
        
        return len(res) == 1 and res[0]
    
    
    def userID(self, username: str) -> (int | None):
        cursor = self.db.cursor()
        
        cursor.execute("SELECT users.UserID FROM users WHERE users.username = %s LIMIT 1", (username,))
        res = cursor.fetchone()
        
        cursor.close()
        
        if res is None:
            return None
        
        return res[0]

        
    def checkPw(self, username: str, password: str, silent: bool = False) -> bool:
        cursor = self.db.cursor()
        
        cursor.execute("SELECT credentials.password FROM credentials INNER JOIN (users) ON (users.UserID) = (credentials.user) WHERE users.username='%s' LIMIT 1", (username,))
        hs_passwd = cursor.fetchone()
        
        cursor.close()
        
        if hs_passwd is None or len(hs_passwd) == 0:
            if silent:
                return False
            raise RuntimeError("Database Response is NULL")
                
        return self.crypto.Bcrypt_Check(password, hs_passwd)


    def checkBan(self, username, silent: bool = False) -> bool:
        cursor = self.db.cursor()
        
        cursor.execute("SELECT users.banned FROM users WHERE users.username=%s", (username, ))
        res = cursor.fetchone()
        
        cursor.close()
        
        if res is None or len(res) == 0:
            if silent:
                return False
            raise RuntimeError("Database response is NULL")
        
        return res[0]
    

    def existToken(self, token: str) -> bool:
        cursor = self.db.cursor()
        cursor.execute("SELECT 1 FROM tokens WHERE tokens.token = %s LIMIT 1", (token,))
        res = cursor.fetchone()
        
        cursor.close()
        
        if res is None:
            return False
    
        return res[0]
    
    
    def isExpiredToken(self, token: str) -> (bool | None):
        cursor = self.db.cursor()
        
        cursor.execute("SELECT tokens.expire FROM tokens WHERE tokens.token = %s LIMIT 1", (token, ))
        expire = cursor.fetchone()
        
        cursor.close()
        
        if expire is None:
            return None
        
        expire = expire[0]  # type: datetime
        
        return expire.timestamp() < datetime.now().timestamp()
    
    
    def makeToken(self, user: int) -> str:
        token = str(uuid4())
        expire = datetime.now().timestamp() + 604800.0  # 1 week
        expire = datetime.fromtimestamp(expire).strftime("%Y-%m-%d %H:%M:%S")
        
        cursor = self.db.cursor()
        cursor.execute("INSERT INTO tokens(token, user, expire) VALUES (%s, %s, %s)", (token, user, expire, ))
        
        self.db.commit()
        
        cursor.close()
        
        return token