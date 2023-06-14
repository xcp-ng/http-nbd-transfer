import os
import random

import pytest

# ==============================================================================

@pytest.mark.usefixtures('random_backing_file')
class TestRequests:
    def test_read_all(self, random_backing_file):
        random_backing_file.check_read_all()

    def test_simple_write(self, random_backing_file):
        chunk_size = 512
        random_backing_file.check_write(b'X' * chunk_size, 0)
        random_backing_file.check_read(chunk_size, 0)

    def test_unaligned_read(self, random_backing_file):
        random_backing_file.check_read(2518684, 4155625)

    def test_unaligned_write(self, random_backing_file):
        random_backing_file.check_write(os.urandom(3732428), 9458932)
        random_backing_file.check_read(3732428, 9458932)

    def test_write_all(self, random_backing_file):
        i = 0
        chunk_size = 4096 * 1024
        while i < random_backing_file.capacity:
            chunk = os.urandom(chunk_size)
            random_backing_file.check_write(chunk, i)
            i += chunk_size
        random_backing_file.check_read_all()

    def test_random_write(self, random_backing_file):
        chunk_size = 512 * 1024

        i = 0
        while i < 10:
            print('Loop {}'.format(i))
            offset = random.randint(0, random_backing_file.capacity)
            offset = (offset + (chunk_size - 1)) & ~(chunk_size - 1)

            chunk = os.urandom(chunk_size)
            random_backing_file.check_write(chunk, offset)
            random_backing_file.check_read(chunk_size, offset)

            i += 1

        print('Check final buffer.')
        random_backing_file.check_read_all()

    def test_random_unaligned_write(self, random_backing_file):
        base_chunk_size = 512 * 1024
        diff_percent = 0.25

        diff = base_chunk_size * diff_percent
        min_chunk_size = base_chunk_size - diff
        max_chunk_size = base_chunk_size + diff

        i = 0
        while i < 10:
            print('Loop {}'.format(i))
            chunk_size = random.randint(min_chunk_size, max_chunk_size)
            offset = random.randint(0, random_backing_file.capacity)

            chunk = os.urandom(chunk_size)
            random_backing_file.check_write(chunk, offset)
            random_backing_file.check_read(chunk_size, offset)

            i += 1

        print('Check final buffer.')
        random_backing_file.check_read_all()
