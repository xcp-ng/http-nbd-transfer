#!/usr/bin/env python

#
# Copyright (C) 2022  Vates SAS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

from setuptools import setup

setup(
    name="http-nbd-transfer",
    version="1.4.0",
    description="Set of tools to transfer NBD requests to an HTTP server",
    author="Ronan Abhamon <ronan.abhamon@vates.tech>",
    author_email="ronan.abhamon@vates.tech",
    url="https://vates.tech",
    license="GPLv3",
    py_modules=["http_disk_server", "nbd_http_server"],
    scripts=["scripts/http-disk-server", "scripts/nbd-http-server"]
)
