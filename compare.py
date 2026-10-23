def compare(old, new):
    added = set(new) - set(old)
    removed = set(old) - set(new)

    pool = {}
    for path in sorted(removed):
        pool.setdefault(old[path]["sha256"], []).append(path)

    renamed = []
    for path in sorted(added):
        if new[path]["size"] == 0:
            continue
        candidates = pool.get(new[path]["sha256"])
        if candidates:
            source = candidates.pop(0)
            renamed.append([source, path])
            added.discard(path)
            removed.discard(source)

    modified = []
    permissions = []
    for path in sorted(set(old) & set(new)):
        before, after = old[path], new[path]
        if before["sha256"] != after["sha256"]:
            modified.append(path)
        elif before["mode"] != after["mode"]:
            permissions.append(path)

    return {
        "modified": modified,
        "added": sorted(added),
        "removed": sorted(removed),
        "renamed": renamed,
        "permissions": permissions,
    }
