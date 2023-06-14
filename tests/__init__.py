import sys

# Python2-3 compatibility.
if sys.version_info > (3,):
    def buffer(object, offset, size):
        return memoryview(object).cast('B')[offset:offset + size]
else:
    buffer = buffer
