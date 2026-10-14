def buffer(object, offset, size):
    return memoryview(object).cast('B')[offset:offset + size]
