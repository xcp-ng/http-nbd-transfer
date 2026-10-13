import ctypes

from http_nbd_transfer.typing import Union

def buffer(
    data: Union[bytes, bytearray, memoryview, "ctypes.Array[ctypes.c_char]"], offset: int, size: int
) -> memoryview:
    return memoryview(data).cast("B")[offset:offset + size]
