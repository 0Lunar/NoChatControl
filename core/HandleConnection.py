import socket


class SocketHandler(socket.socket):
    def __init__(self, family: socket.AddressFamily | int = -1, type: socket.SocketKind | int = -1, proto: int = -1, fileno: int | None = None) -> None:
        super().__init__(family, type, proto, fileno)

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
            self.connected = True
        except:
            pass


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

        return super().recv(payload_len)


    def recv_short_bytes(self) -> bytes:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        payload_len = super().recv(2)
        payload_len = int.from_bytes(payload_len, 'big')

        return super().recv(payload_len)
    

    def recv_int_bytes(self) -> bytes:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        payload_len = super().recv(2)
        payload_len = int.from_bytes(payload_len, 'big')

        return super().recv(payload_len)
    

    def recv_long_bytes(self) -> bytes:
        if not self.connected:
            raise RuntimeError("Not connected")
        
        payload_len = super().recv(8)
        payload_len = int.from_bytes(payload_len, 'big')

        return super().recv(payload_len)