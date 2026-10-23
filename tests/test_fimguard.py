import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fimguard
import store
from compare import compare
from hasher import sha256_file
from snapshot import take_snapshot


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write(text)


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = fimguard.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class HashTests(unittest.TestCase):
    def test_known_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "a.txt")
            with open(path, "wb") as handle:
                handle.write(b"abc")
            self.assertEqual(
                sha256_file(path),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = self.folder.name
        write(os.path.join(self.root, "a.txt"), "alpha")
        write(os.path.join(self.root, "sub", "b.txt"), "bravo")
        write(os.path.join(self.root, "c.log"), "charlie")
        self.before, _ = take_snapshot(self.root)

    def tearDown(self):
        self.folder.cleanup()

    def test_no_change(self):
        after, _ = take_snapshot(self.root)
        result = compare(self.before, after)
        self.assertFalse(any(result.values()))

    def test_modified_added_removed(self):
        write(os.path.join(self.root, "a.txt"), "ALPHA")
        write(os.path.join(self.root, "new.txt"), "fresh")
        os.remove(os.path.join(self.root, "c.log"))
        after, _ = take_snapshot(self.root)
        result = compare(self.before, after)
        self.assertEqual(result["modified"], ["a.txt"])
        self.assertEqual(result["added"], ["new.txt"])
        self.assertEqual(result["removed"], ["c.log"])

    def test_rename_is_not_reported_as_add_and_remove(self):
        os.rename(os.path.join(self.root, "a.txt"), os.path.join(self.root, "z.txt"))
        after, _ = take_snapshot(self.root)
        result = compare(self.before, after)
        self.assertEqual(result["renamed"], [["a.txt", "z.txt"]])
        self.assertEqual(result["added"], [])
        self.assertEqual(result["removed"], [])

    def test_empty_files_are_not_paired_as_renames(self):
        write(os.path.join(self.root, "e1"), "")
        before, _ = take_snapshot(self.root)
        os.remove(os.path.join(self.root, "e1"))
        write(os.path.join(self.root, "e2"), "")
        after, _ = take_snapshot(self.root)
        result = compare(before, after)
        self.assertEqual(result["renamed"], [])
        self.assertEqual(result["added"], ["e2"])
        self.assertEqual(result["removed"], ["e1"])

    @unittest.skipIf(os.name == "nt", "permission bits are not meaningful on Windows")
    def test_permission_change(self):
        os.chmod(os.path.join(self.root, "a.txt"), 0o600)
        after, _ = take_snapshot(self.root)
        result = compare(self.before, after)
        self.assertEqual(result["permissions"], ["a.txt"])

    def test_ignore_patterns(self):
        files, _ = take_snapshot(self.root, ["*.log", "sub"])
        self.assertEqual(sorted(files), ["a.txt"])


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.folder.name, "watched")
        self.baseline = os.path.join(self.folder.name, "baseline.json")
        self.keyfile = os.path.join(self.folder.name, "secret.key")
        write(os.path.join(self.root, "app.conf"), "port=22")
        write(os.path.join(self.root, "data", "users.txt"), "root")
        with open(self.keyfile, "w") as handle:
            handle.write("correct horse battery staple")

    def tearDown(self):
        self.folder.cleanup()

    def test_clean_then_dirty(self):
        code, out, _ = run("init", self.root, "--baseline", self.baseline)
        self.assertEqual(code, 0)
        code, out, _ = run("check", self.root, "--baseline", self.baseline)
        self.assertEqual(code, 0)
        self.assertIn("OK", out)
        write(os.path.join(self.root, "app.conf"), "port=2222")
        code, out, _ = run("check", self.root, "--baseline", self.baseline)
        self.assertEqual(code, 1)
        self.assertIn("[MODIFIED] app.conf", out)

    def test_baseline_inside_watched_folder_is_ignored(self):
        inside = os.path.join(self.root, "baseline.json")
        run("init", self.root, "--baseline", inside)
        code, out, _ = run("check", self.root, "--baseline", inside)
        self.assertEqual(code, 0)

    def test_json_output(self):
        run("init", self.root, "--baseline", self.baseline)
        write(os.path.join(self.root, "extra.txt"), "x")
        code, out, _ = run("check", self.root, "--baseline", self.baseline, "--json")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["added"], ["extra.txt"])

    def test_signed_baseline_round_trip(self):
        code, out, _ = run("init", self.root, "--baseline", self.baseline, "--key-file", self.keyfile)
        self.assertIn("signed", out)
        code, _, _ = run("check", self.root, "--baseline", self.baseline, "--key-file", self.keyfile)
        self.assertEqual(code, 0)

    def test_tampered_baseline_is_rejected(self):
        run("init", self.root, "--baseline", self.baseline, "--key-file", self.keyfile)
        with open(self.baseline) as handle:
            document = json.load(handle)
        document["files"]["app.conf"]["sha256"] = "0" * 64
        with open(self.baseline, "w") as handle:
            json.dump(document, handle)
        code, _, err = run("check", self.root, "--baseline", self.baseline, "--key-file", self.keyfile)
        self.assertEqual(code, 2)
        self.assertIn("signature mismatch", err)

    def test_wrong_key_is_rejected(self):
        run("init", self.root, "--baseline", self.baseline, "--key-file", self.keyfile)
        other = os.path.join(self.folder.name, "other.key")
        with open(other, "w") as handle:
            handle.write("a different secret")
        code, _, err = run("check", self.root, "--baseline", self.baseline, "--key-file", other)
        self.assertEqual(code, 2)

    def test_signed_baseline_needs_a_key(self):
        run("init", self.root, "--baseline", self.baseline, "--key-file", self.keyfile)
        code, _, err = run("check", self.root, "--baseline", self.baseline)
        self.assertEqual(code, 2)
        self.assertIn("signed", err)

    def test_missing_directory(self):
        code, _, err = run("init", os.path.join(self.folder.name, "nope"))
        self.assertEqual(code, 2)

    def test_missing_baseline(self):
        code, _, err = run("check", self.root, "--baseline", self.baseline)
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
