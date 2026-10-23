LABELS = (
    ("modified", "MODIFIED"),
    ("added", "ADDED"),
    ("removed", "REMOVED"),
    ("permissions", "PERMISSIONS CHANGED"),
)


def count_changes(result):
    return sum(len(result[key]) for key in ("modified", "added", "removed", "renamed", "permissions"))


def render(result):
    lines = []
    for key, label in LABELS:
        for path in result[key]:
            lines.append(f"[{label}] {path}")
    for source, target in result["renamed"]:
        lines.append(f"[RENAMED] {source} -> {target}")
    for path in result.get("unreadable", []):
        lines.append(f"[UNREADABLE] {path}")
    total = count_changes(result)
    if total == 0 and not lines:
        return "OK: no changes since baseline"
    if total == 0:
        return "\n".join(lines) + "\nno content changes, but some files could not be read"
    return "\n".join(lines) + f"\n{total} change(s) detected"
