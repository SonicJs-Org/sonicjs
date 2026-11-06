"""Test-owned syscall instrumentation; never imported by production intake."""
import base64
import json
import os
import runpy
import sys

helper, root, outside, mode, kind = sys.argv[1:]
api = runpy.run_path(helper)
if mode == 'capability':
    os.supports_fd = os.supports_fd - {os.scandir}
    assert api['main']() == 1
    print(json.dumps({'rejected': True}))
    sys.exit(0)

# Synthetic enumeration seam: real anchored descriptors, instrumented streaming names.
if mode in ('enumeration-root', 'enumeration-nested'):
    real_scandir, real_listdir = os.scandir, os.listdir
    original_open, original_close = os.open, os.close
    held = set()
    def track_open(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        held.add(fd)
        return fd
    def track_close(fd):
        held.remove(fd)
        return original_close(fd)
    os.open, os.close = track_open, track_close
    scans = []
    class Scan:
        def __init__(self, fd):
            assert isinstance(fd, int), 'enumeration must use held FD'
            self.iterator = real_scandir(fd)
            self.index = len(scans)
            self.count = 0
            self.closed = False
            scans.append(self)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.closed = True
            self.iterator.close()
        def __iter__(self):
            return self
        def __next__(self):
            entry = next(self.iterator)
            self.count += 1
            # Root budget=3; nested root reserves its two names, leaving one.
            maximum = 4 if mode == 'enumeration-root' else (3 if self.index == 0 else 2)
            assert self.count <= maximum, 'enumeration consumed beyond remaining+1'
            return entry
    def eager(fd):
        with Scan(fd) as scan:
            return [entry.name for entry in scan]
    os.scandir, os.listdir = Scan, eager
    rejected = False
    try:
        api['intake']('directory', root, entry_limit=3)
    except ValueError as error:
        assert str(error) == 'tree count budget'
        rejected = True
    finally:
        os.scandir, os.listdir = real_scandir, real_listdir
        os.open, os.close = original_open, original_close
    assert not held
    assert rejected
    assert [s.count for s in scans] == ([4] if mode == 'enumeration-root' else [2, 2])
    assert all(s.closed for s in scans)
    print(json.dumps({'consumed': [s.count for s in scans], 'closed': True, 'rejected': rejected}))
    sys.exit(0)

real_open, real_read, real_close = os.open, os.read, os.close
tracked = set()
outside_id = os.stat(outside + '/report.json')
inside_id = os.stat(root + '/vendor/report.json')
inside_chunks = []
reads = 0
swapped = False


def opened(path, flags, *args, **kwargs):
    global swapped
    if path == 'report.json' and not swapped:
        if mode == 'ancestor':
            os.rename(root + '/vendor', root + '/vendor-held')
            os.symlink(outside, root + '/vendor')
        elif mode == 'fifo':
            os.rename(root + '/vendor/report.json', root + '/vendor/held')
            os.mkfifo(root + '/vendor/report.json')
        elif mode == 'leaf':
            os.rename(root + '/vendor/report.json', root + '/vendor/held')
            os.symlink(outside + '/report.json', root + '/vendor/report.json')
        swapped = True
    fd = real_open(path, flags, *args, **kwargs)
    tracked.add(fd)
    if path == 'report.json' and mode == 'mutation':
        os.utime('report.json', (0, 0), dir_fd=kwargs['dir_fd'])
    return fd


def read(fd, size):
    global reads
    s = os.fstat(fd)
    if (s.st_dev, s.st_ino) == (outside_id.st_dev, outside_id.st_ino):
        reads += 1
    chunk = real_read(fd, size)
    if (s.st_dev, s.st_ino) == (inside_id.st_dev, inside_id.st_ino):
        inside_chunks.append(chunk)
    return chunk


def close(fd):
    tracked.remove(fd)
    return real_close(fd)


os.open, os.read, os.close = opened, read, close
result = None
rejected = False
try:
    result = api['intake'](kind, root if kind == 'directory' else root + '/vendor/report.json')
except (OSError, ValueError):
    rejected = True
finally:
    os.open, os.read, os.close = real_open, real_read, real_close
print(json.dumps({'outsideReads': reads, 'remainingFDs': len(tracked),
                  'insideBytes': base64.b64encode(b''.join(inside_chunks)).decode('ascii'),
                  'swapped': swapped, 'rejected': rejected, 'result': result}))
