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

import contextlib
import typing
from typing import *  # noqa: F403

# TODO(XCPNG-3919): `NoReturn` is not in `typing.__all__` before python 3.7. Remove me later.
from typing import NoReturn  # noqa: F401

# ==============================================================================

# TODO(XCPNG-3919): Remove all hacks for python 3.11.

if not TYPE_CHECKING:  # noqa: F405, SIM102
    if not hasattr(typing, "override"):
        def override(method):  # type: ignore # noqa: ANN001, ANN201
            with contextlib.suppress(AttributeError, TypeError):
                # Set internal attr `__override__` like described in PEP 698.
                method.__override__ = True
            return method
