import ctypes
import os
import random

import pytest

from tests import buffer

from http_nbd_transfer.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tests.conftest import MirrorDevice

# ==============================================================================

@pytest.mark.usefixtures("aligned_buffer")
@pytest.mark.usefixtures("backing_file_mirror")
class TestMirroring:
    def test_read_all(self, backing_file_mirror: "MirrorDevice") -> None:
        backing_file_mirror.check_read_all()

    def test_simple_write(
        self, aligned_buffer: "ctypes.Array[ctypes.c_char]", backing_file_mirror: "MirrorDevice"
    ) -> None:
        chunk_size = 512
        buffer(aligned_buffer, 0, chunk_size)[:] = b"X" * chunk_size
        backing_file_mirror.check_write(buffer(aligned_buffer, 0, chunk_size), 0)
        backing_file_mirror.check_read(chunk_size, 0)

    def test_random_write(
        self, aligned_buffer: "ctypes.Array[ctypes.c_char]", backing_file_mirror: "MirrorDevice"
    ) -> None:
        chunk_size = 512 * 1024

        i = 0
        while i < 20:
            print("Loop {}".format(i))
            offset = random.randint(0, backing_file_mirror.capacity)
            offset = (offset + (chunk_size - 1)) & ~(chunk_size - 1)

            buffer(aligned_buffer, 0, chunk_size)[:] = os.urandom(chunk_size)
            backing_file_mirror.check_write(buffer(aligned_buffer, 0, chunk_size), offset)
            backing_file_mirror.check_read(chunk_size, offset)

            i += 1

        print("Check final buffer.")
        backing_file_mirror.check_read_all()
