from core import CryptoHandler, SocketHandler
import mysql.connector as mysql
import os


class Login(object):
    def __init__(self, connection: SocketHandler) -> None:
        self.crypto = CryptoHandler()
        self.conn = connection
        self.hs = False

        self.db = mysql.connect(
            host=os.environ.get("CHAT_DB_HOST", "localhost"),
            username=os.environ.get("CHAT_DB_USER", "root"),
            password=os.environ.get("CHAT_DB_PASSWD", "root"),
            database=os.environ.get("CHAT_DB_NAME", "test")
        )

    
    def handshake(self) -> None:
        if not self.conn.connected:
            raise RuntimeError("Connection closed")

        conn = self.conn
        _timeout = conn.timeout
        key_size = 2048

        try:
            # Public Key RSA

            self.crypto.New_RSA(key_size=key_size)

            pub = self.crypto.RSA_export_pub_key()

            if pub is None:
                raise RuntimeError("Error exporting RSA public key")

            pub_len = len(pub).to_bytes(length=2, byteorder='big')
            payload = pub_len + pub

            conn.settimeout(10)

            conn.send(payload)

            # Get Encrypted AES Key

            enc = conn.recv(key_size // 8)      #   2048 bit -> 256 bytes
            aes_key = self.crypto.RSA_decrypt(enc)


            self.crypto.New_AES(key=aes_key)

            # Get HMAC

            enc = conn.recv(64)
            iv, enc = enc[:16], enc[16:]

            self.crypto.AES_Update_Iv(iv)
            hmac_key = self.crypto.AES_Decrypt(enc)
            self.crypto.New_HMAC(key=hmac_key)

            self.hs = True
            conn.settimeout(_timeout)
    
        except Exception as ex:
            conn.settimeout(_timeout)
            raise Exception(ex)
    

    def login(self) -> bool:
        if not self.hs:
            raise RuntimeError("Handshake not initialized")

        # Get Credentials

        encrypted_username = self.conn.recv_char_bytes()
        iv, username, sig = encrypted_username[:16], encrypted_username[16:-32], encrypted_username[-32:]

        if not self.crypto.check_HMAC(username, sig):
            self.conn.fail_code()
            return False
        
        self.crypto.AES_Update_Iv(iv)
        if not (username := self.crypto.AES_Decrypt(username)):
            self.conn.fail_code()
            return False
        
        self.conn.success_code()

        encrypted_password = self.conn.recv_char_bytes()
        iv, password, sig = encrypted_password[:16], encrypted_password[16:-32], encrypted_password[-32:]

        if not self.crypto.check_HMAC(password, sig):
            self.conn.fail_code()
            return False
        
        self.crypto.AES_Update_Iv(iv)
        if not (password := self.crypto.AES_Decrypt(password)):
            self.conn.fail_code()
            return False
        
        username = username.decode()
        password = password

        self.conn.success_code()

        # Compare Credentials With Database

        cursor = self.db.cursor()
        cursor.execute("SELECT password FROM credentials WHERE username=%s LIMIT 1", (username, ))

        hashed_pwd = cursor.fetchone()
        cursor.close()
        
        if not hashed_pwd:
            self.conn.fail_code()
            cursor.close()
            return False
        
        hashed_pwd = hashed_pwd[0]

        if self.crypto.Bcrypt_Check(password, hashed_pwd.encode()):
            self.conn.success_code()
            return True
        
        self.conn.fail_code()
        return False