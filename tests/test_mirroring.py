import os
import random

import pytest

from tests import buffer

# ==============================================================================

@pytest.mark.usefixtures('aligned_buffer')
@pytest.mark.usefixtures('backing_file_mirror')
class TestMirroring:
    def test_read_all(self, backing_file_mirror):
        backing_file_mirror.check_read_all()

    def test_simple_write(self, aligned_buffer, backing_file_mirror):
        chunk_size = 512
        aligned_buffer[:chunk_size] = b'X' * chunk_size
        backing_file_mirror.check_write(buffer(aligned_buffer, 0, chunk_size), 0)
        backing_file_mirror.check_read(chunk_size, 0)

    def test_random_write(self, aligned_buffer, backing_file_mirror):
        chunk_size = 512 * 1024

        i = 0
        while i < 20:
            print('Loop {}'.format(i))
            offset = random.randint(0, backing_file_mirror.capacity)
            offset = (offset + (chunk_size - 1)) & ~(chunk_size - 1)

            aligned_buffer[:chunk_size] = os.urandom(chunk_size)
            backing_file_mirror.check_write(buffer(aligned_buffer, 0, chunk_size), offset)
            backing_file_mirror.check_read(chunk_size, offset)

            i += 1

        print('Check final buffer.')
        backing_file_mirror.check_read_all()
