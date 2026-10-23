import fnmatch
import os
import stat

from hasher import sha256_file


def relative(root, full):
    return os.path.relpath(full, root).replace(os.sep, "/")


def matches(rel, patterns):
    name = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) for p in patterns)


def take_snapshot(root, ignore=()):
    root = os.path.abspath(root)
    files = {}
    unreadable = []
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            d for d in dirs
            if not matches(relative(root, os.path.join(current, d)), ignore)
        )
        for name in sorted(names):
            full = os.path.join(current, name)
            rel = relative(root, full)
            if matches(rel, ignore) or os.path.islink(full):
                continue
            try:
                info = os.stat(full)
                files[rel] = {
                    "sha256": sha256_file(full),
                    "size": info.st_size,
                    "mode": format(stat.S_IMODE(info.st_mode), "04o"),
                }
            except OSError:
                unreadable.append(rel)
    return files, unreadable
