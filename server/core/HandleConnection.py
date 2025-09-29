from core import CryptoHandler
import socket


class SocketHandler(socket.socket):
    def __init__(self, family: socket.AddressFamily | int = -1, type: socket.SocketKind | int = -1, proto: int = -1, fileno: int | None = None) -> None:
        super().__init__(family, type, proto, fileno)
        self.crypto = CryptoHandler()

        if fileno:
            self.connected = True
        else:
            self.connected = False
    

    def listen(self, ip: str, port: int) -> tuple["SocketHandler", tuple[str, int]]:
        if self.connected:
            raise RuntimeError("Socket already connected")

        self._ip = ip
        self._port = port

        super().bind((self._ip, self._port))
        super().listen()
        conn, remote = super().accept()

        return ( SocketHandler(socket.AF_INET, socket.SOCK_STREAM, 0, conn.detach()), remote )
    

    def connect(self, address) -> None:
        if self.connected:
            raise RuntimeError("Already connected")

        try:
            super().connect(address)
            self.handshake()
            self.connected = True
        except:
            pass
        
    
    def handshake(self) -> None:
        if not self.connected:
            raise RuntimeError("Connection closed")

        conn = super()
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
        
    
    def recv(self, size: int) -> bytes:
        data = super().recv(size + (-size % 16))
        
        iv, data, sig = data[:16], data[16:-32], data[-32:]
        
        if not self.crypto.check_HMAC(data, sig):
            raise RuntimeError("Invalid HMAC")
        
        self.crypto.AES_Update_Iv(iv)
        if not (data := self.crypto.AES_Decrypt(data)):
            raise RuntimeError("Error decrypting msg with AES")
        
        return data


    def send(self, msg: bytes) -> None:
        if not msg:
            raise RuntimeError("Invalid Message")
        
        iv = self.crypto.Generate_iv()
        
        self.crypto.AES_Update_Iv(iv)
        data = self.crypto.AES_Encrypt(msg)
        
        sig = self.crypto.Sign_HMAC(data)
        
        payload = iv + data + sig
        
        super().send(payload)


    def success_code(self) -> None:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        if super().send(b'\x00') <= 0:
            raise RuntimeError("Connection error")
    

    def fail_code(self) -> None:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        if super().send(b'\x01') <= 0:
            raise RuntimeError("Connection error")
    

    def recv_byte(self) -> bytes:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        return super().recv(1)
    
    
    def recv_char_bytes(self) -> bytes:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        payload_len = super().recv(1)
        payload_len = int.from_bytes(payload_len, 'big')

        return self.recv(payload_len)


    def recv_short_bytes(self) -> bytes:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        payload_len = super().recv(2)
        payload_len = int.from_bytes(payload_len, 'big')

        return self.recv(payload_len)
    

    def recv_int_bytes(self) -> bytes:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        payload_len = super().recv(2)
        payload_len = int.from_bytes(payload_len, 'big')

        return self.recv(payload_len)
    

    def recv_long_bytes(self) -> bytes:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        payload_len = super().recv(8)
        payload_len = int.from_bytes(payload_len, 'big')

        return self.recv(payload_len)