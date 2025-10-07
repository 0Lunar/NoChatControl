from core import SocketHandler


class ConnHandler(object):
    def __init__(self) -> None:
        self._conn_dict = {}
    
    
    def add(self, conn: SocketHandler, addr: tuple[str, int]) -> None:
        host, port = addr[0], addr[1]
        
        self._conn_dict[host] = [conn, port]
        
    
    def remove(self, host: str) -> None:
        self._conn_dict.pop(host)
        
        
    def get(self, host: str) -> (SocketHandler | None):
        return self._conn_dict.get(host, None)
    
    
    def get_all(self) -> dict[str, tuple[str, int]]:
        return self._conn_dict.copy()
    
    
    def clear(self) -> None:
        self._conn_dict.clear()