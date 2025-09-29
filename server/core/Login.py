from core import CryptoHandler, SocketHandler, db


class Login(object):
    def __init__(self, connection: SocketHandler) -> None:
        self.crypto = CryptoHandler()
        self.conn = connection
        self.db = db()
    

    def login(self) -> bool:
        # Get Credentials
        # Username

        try:
            username = self.conn.recv_char_bytes()
            username = username.decode()
        except:
            self.conn.fail_code()
            return False

    
        if not self.db.checkUser(username) or self.db.checkBan(username):
            self.conn.fail_code()
            return False
        
        self.conn.success_code()

        # Password

        try:
            password = self.conn.recv_char_bytes()
            password = password.decode()
        except:
            self.conn.fail_code()
            return False
        
        # Compare Credentials With Database
        
        if self.db.checkPw(username, password):
            self.conn.success_code()
            return True
        
        
        self.conn.fail_code()
        return False