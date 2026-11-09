"""Trusted, POSIX-only bounded intake. Never load code from artifact paths."""
import base64
import json
import os
import re
import stat
import sys

FILE_BYTES = 32 * 1024 * 1024
TOTAL_BYTES = 128 * 1024 * 1024
MAX_ENTRIES = 2048
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def identity(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def same(a, b):
    require(identity(a) == identity(b), 'file changed during intake')


def open_checked(parent, name, directory):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if directory:
        require(stat.S_ISDIR(before.st_mode), 'unsafe directory')
    else:
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and not before.st_mode & 0o7111, 'unsafe regular file')
    fd = os.open(name, DIR_FLAGS if directory else FILE_FLAGS, dir_fd=parent)
    try:
        same(before, os.fstat(fd))
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_file(parent, name, limit):
    fd = open_checked(parent, name, False)
    try:
        initial = os.fstat(fd)
        require(initial.st_size <= limit, 'file bytes budget')
        chunks = []
        length = 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - length))
            if not chunk:
                break
            length += len(chunk)
            require(length <= limit, 'file bytes budget')
            chunks.append(chunk)
        same(initial, os.fstat(fd))
        same(initial, os.stat(name, dir_fd=parent, follow_symlinks=False))
        return b''.join(chunks)
    finally:
        os.close(fd)


def intake(kind, path, byte_limit=TOTAL_BYTES, entry_limit=MAX_ENTRIES):
    require(isinstance(byte_limit, int) and 0 <= byte_limit <= TOTAL_BYTES
            and isinstance(entry_limit, int) and 0 <= entry_limit <= MAX_ENTRIES, 'invalid budgets')
    require(kind in ('directory', 'file') and isinstance(path, str)
            and path.startswith('/') and len(path.encode()) <= 4096, 'invalid request')
    parts = path.split('/')[1:]
    require(parts and all(p and p not in ('.', '..') for p in parts), 'invalid path')
    held = [os.open('/', DIR_FLAGS)]
    bindings = []
    files = []
    dirs = []
    seen = set()
    total = 0
    entries = 0

    def walk(fd, prefix):
        nonlocal total, entries
        initial = os.fstat(fd)
        names = []
        # Reserve globally while streaming; pending siblings also consume budget.
        # The first excess entry rejects before any further iterator consumption.
        with os.scandir(fd) as scan:
            for entry in scan:
                entries += 1
                require(entries <= entry_limit, 'tree count budget')
                names.append(entry.name)
        for name in sorted(names):
            key = prefix + '/' + name if prefix else name
            require(len(key) <= 512 and len(key.split('/')) <= 6
                    and all(re.fullmatch(r'[A-Za-z0-9_.-]+', p) and p not in ('.', '..')
                            for p in key.split('/')), 'unsafe payload path')
            require(key.lower() not in seen, 'case-colliding path')
            seen.add(key.lower())
            s = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(s.st_mode):
                child = open_checked(fd, name, True)
                try:
                    dirs.append(key)
                    walk(child, key)
                    same(s, os.stat(name, dir_fd=fd, follow_symlinks=False))
                finally:
                    os.close(child)
            else:
                data = read_file(fd, name, min(FILE_BYTES, byte_limit - total))
                total += len(data)
                files.append([key, base64.b64encode(data).decode('ascii')])
        same(initial, os.fstat(fd))

    try:
        for name in parts if kind == 'directory' else parts[:-1]:
            parent = held[-1]
            child = open_checked(parent, name, True)
            held.append(child)
            bindings.append((parent, name, child))
        if kind == 'directory':
            walk(held[-1], '')
        else:
            files.append(['', base64.b64encode(read_file(held[-1], parts[-1], byte_limit)).decode('ascii')])
        for parent, name, child in bindings:
            # Binding identity only: directory contents can legitimately differ at
            # ancestors; the scanned root's contents were checked separately.
            a, b = os.fstat(child), os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISDIR(b.st_mode) and (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino), 'directory changed during intake')
        return {'files': files, 'dirs': dirs, 'entries': entries}
    finally:
        for fd in reversed(held):
            os.close(fd)


def main():
    try:
        require(os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
                and os.scandir in os.supports_fd, 'POSIX capabilities unavailable')
        request = sys.stdin.buffer.read(8193)
        require(len(request) <= 8192, 'request budget')
        value = json.loads(request)
        require(set(value) == {'kind', 'path', 'byteLimit', 'entryLimit'}, 'invalid request')
        result = intake(value['kind'], value['path'], value['byteLimit'], value['entryLimit'])
        sys.stdout.write(json.dumps(result, separators=(',', ':')))
    except BaseException:
        # No paths, bytes, exception repr, environment, or diagnostics cross here.
        sys.stderr.write('Invalid artifact: safe POSIX intake failed\n')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
