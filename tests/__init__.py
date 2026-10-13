import ctypes

from http_nbd_transfer.typing import Union

def buffer(
    object: Union[bytes, bytearray, memoryview, 'ctypes.Array[ctypes.c_char]'], offset: int, size: int
) -> memoryview:
    return memoryview(object).cast('B')[offset:offset + size]
