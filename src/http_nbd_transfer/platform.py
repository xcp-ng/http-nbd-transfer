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

from functools import lru_cache
from pathlib import Path

from http_nbd_transfer.typing import Final, Mapping, Tuple

# ==============================================================================
# Attributes that depend on the execution environment.
# Its primary purpose is to decouple the logic from the underlying host's
# specificities (OS, paths of executables, ...).
# ==============================================================================

_OS_RELEASE_PATH: Final = "/etc/os-release"

@lru_cache(maxsize=None)
def get_os_ids() -> Tuple[str, ...]:
    """
    Get the IDs of the current distribution, most specific first: `ID` followed
    by the values of `ID_LIKE` (e.g. `("ubuntu", "debian")`). The result is
    cached. An empty tuple is returned if `/etc/os-release` can't be read.
    """

    try:
        lines = Path(_OS_RELEASE_PATH).read_text(encoding="utf-8").splitlines()
    except OSError:
        return ()

    values = {}
    for line in lines:
        key, _separator, value = line.partition("=")
        values[key.strip()] = value.strip().strip("\"'")

    return tuple(values.get("ID", "").split() + values.get("ID_LIKE", "").split())

def get_exec_path(default: str, by_os_id: Mapping[str, str]) -> str:
    """
    Get the path of an executable: the one registered for the first matching OS
    ID, otherwise `default`.
    """

    return next((by_os_id[os_id] for os_id in get_os_ids() if os_id in by_os_id), default)

# ------------------------------------------------------------------------------
# Executables.
# ------------------------------------------------------------------------------

EXEC_PATH_DMESG: Final = get_exec_path("/usr/bin/dmesg", {})
EXEC_PATH_DRBDSETUP: Final = get_exec_path("/usr/sbin/drbdsetup", {})
EXEC_PATH_LSOF: Final = get_exec_path("/usr/sbin/lsof", {"debian": "/usr/bin/lsof"})
EXEC_PATH_MODPROBE: Final = get_exec_path("/usr/sbin/modprobe", {})
EXEC_PATH_NBD_CLIENT: Final = get_exec_path("/usr/sbin/nbd-client", {})
EXEC_PATH_NBDKIT: Final = get_exec_path("/usr/sbin/nbdkit", {"debian": "/usr/bin/nbdkit"})
