"""Target-scoped local authority. Tokens are public generations, not credentials.

The stable fence is independent of state_dir and XDG_RUNTIME_DIR. Never unlink
lock files on close: a locked unlinked inode cannot fence a replacement path.
This is cooperative same-UID coordination, not hostile-filesystem containment.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import secrets
import stat
import threading
import unicodedata
from pathlib import Path


class AuthorityError(RuntimeError):
    pass


def canonical_target(session_id: str, socket_path: str) -> str:
    # Conservatively coalesce path aliases even on case-sensitive test hosts.
    # Overblocking distinct case/Unicode paths is safer than split authority.
    path = unicodedata.normalize("NFKC", os.path.realpath(socket_path)).casefold()
    return session_id + "|" + path


class TargetAuthority:
    def __init__(self, session_id: str, socket_path: str):
        self.target = canonical_target(session_id, socket_path)
        identity = hashlib.sha256(self.target.encode()).hexdigest()
        runtime = Path(os.environ.get("XDG_RUNTIME_DIR", "/tmp")) / (
            "firefly-bridge-" + str(os.getuid())
        )
        # Fixed per-UID fence: choosing another DB or runtime cannot split authority.
        fence = Path("/tmp") / ("firefly-bridge-authority-" + str(os.getuid()))
        self.directories = (str(fence), str(runtime.absolute()))
        self.paths = (
            str(fence / (identity + ".fence")),
            str(runtime.absolute() / (identity + ".lock")),
        )
        self.lock = threading.RLock()
        self.fds = []
        self.inodes = []
        self.directory_inodes = []
        self.generation = (secrets.token_hex(16) + "\n").encode()
        self.lost = False
        self.pid = os.getpid()
        try:
            for directory in self.directories:
                base = Path(directory)
                base.mkdir(mode=0o700, exist_ok=True)
                info = base.lstat()
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700
                ):
                    raise AuthorityError("authority_directory_not_private")
                self.directory_inodes.append((info.st_dev, info.st_ino))
            for path in self.paths:
                fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                self.fds.append(fd)
                info = os.fstat(fd)
                if not self._private_file(info):
                    raise AuthorityError("authority_file_not_private")
                self.inodes.append((info.st_dev, info.st_ino))
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    raise AuthorityError("dispatch_authority_already_held") from None
            # Write only after both exclusive locks were acquired.
            for fd in self.fds:
                os.ftruncate(fd, 0)
                if os.pwrite(fd, self.generation, 0) != len(self.generation):
                    raise AuthorityError("authority_generation_write_failed")
                os.fsync(fd)
            if not self.held():
                raise AuthorityError("authority_changed_during_claim")
        except BaseException:
            self.close()
            raise

    @property
    def runtime_fd(self):
        return self.fds[-1] if len(self.fds) == 2 else None

    @staticmethod
    def _private_file(info):
        return (
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1
        )

    def _identities_match(self):
        for directory, inode in zip(self.directories, self.directory_inodes):  # noqa: B905
            info = os.lstat(directory)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != inode
            ):
                return False
        if len(self.paths) != len(self.fds) or len(self.paths) != len(self.inodes):
            return False
        for path, fd, inode in zip(self.paths, self.fds, self.inodes):  # noqa: B905
            info, opened = os.lstat(path), os.fstat(fd)
            if (
                not self._private_file(info)
                or not self._private_file(opened)
                or (info.st_dev, info.st_ino) != inode
                or (opened.st_dev, opened.st_ino) != inode
            ):
                return False
            if os.pread(fd, len(self.generation) + 1, 0) != self.generation:
                return False
        return True

    def held(self):
        """Never restore a lost authority. A new incarnation requires explicit close."""
        with self.lock:
            if self.lost or self.pid != os.getpid() or len(self.fds) != 2:
                return False
            try:
                if not self._identities_match():
                    raise AuthorityError("authority_identity_changed")
                for path, fd, inode in zip(self.paths, self.fds, self.inodes):  # noqa: B905
                    probe = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        info = os.fstat(probe)
                        if (info.st_dev, info.st_ino) != inode:
                            raise AuthorityError("authority_identity_changed")
                        try:
                            fcntl.flock(probe, fcntl.LOCK_SH | fcntl.LOCK_NB)
                        except OSError as exc:
                            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                                raise
                        else:
                            # No exclusive lock was held. Never repair a lost/downgraded lock.
                            raise AuthorityError("authority_lock_not_held")
                        # A blocked probe alone might be someone else's lock.
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally:
                        os.close(probe)
                if not self._identities_match():
                    raise AuthorityError("authority_identity_changed")
                return True
            except (OSError, ValueError, AuthorityError):
                self.lost = True
                return False

    def close(self):
        with self.lock:
            self.lost = True
            for index, fd in enumerate(self.fds):
                try:
                    # Unexpected close/reuse must not make cleanup close somebody
                    # else's descriptor. No LOCK_UN on an inherited/forked handle.
                    info = os.fstat(fd)
                    if (
                        index < len(self.inodes)
                        and (info.st_dev, info.st_ino) != self.inodes[index]
                    ):
                        continue
                    os.close(fd)
                except OSError:
                    pass
            self.fds = []
