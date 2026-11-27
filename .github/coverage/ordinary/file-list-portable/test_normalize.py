import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from normalize import CORE, CORE_FILES, GROUPS, NODE, InvalidProfile, normalize, sha256


ROOT = "/toy checkout/source"
ROW = ":1.2,3.4 2 1\n"


def profile(*rows):
    return ("mode: atomic\n" + "".join(rows)).encode()


class NormalizeTests(unittest.TestCase):
    def test_exact_four_groups_and_preserved_coordinates(self):
        for group, filename in GROUPS.items():
            with self.subTest(group=group):
                rows = [ROOT + "/" + filename + ROW]
                if group == "memory_display_units":
                    rows += [CORE + name + ":8.1,9.2 3 0\n" for name in CORE_FILES]
                raw = profile(*rows)
                expected = profile(NODE + filename + ROW, *rows[1:])
                for mode in ("normal", "race"):
                    portable, receipt = normalize(raw, ROOT, group, mode)
                    self.assertEqual(expected, portable)
                    self.assertEqual(sha256(raw), receipt["raw_sha256"])
                    self.assertEqual(sha256(portable), receipt["portable_sha256"])
                    self.assertEqual(mode, receipt["execution_mode"])
                    self.assertEqual({"blocks": 1, "covered": 2, "total": 2},
                                     receipt["scope_counts"]["node"])
                    if group == "memory_display_units":
                        self.assertEqual({"blocks": 17, "covered": 0, "total": 51},
                                         receipt["scope_counts"]["core"])
                    else:
                        self.assertNotIn("core", receipt["scope_counts"])
                    self.assertNotIn(ROOT, json.dumps(receipt))
                    self.assertNotIn(ROOT.encode(), portable)

    def test_different_checkouts_produce_same_portable_bytes(self):
        group = "assessment_existing"
        filename = GROUPS[group]
        a, r_a = normalize(profile(ROOT + "/" + filename + ROW), ROOT, group, "normal")
        b, r_b = normalize(profile("/other/source/" + filename + ROW),
                           "/other/source", group, "normal")
        self.assertEqual(a, b)
        self.assertNotEqual(r_a["raw_sha256"], r_b["raw_sha256"])
        self.assertEqual(r_a["portable_sha256"], r_b["portable_sha256"])

    def test_unmapped_exact_or_similar_names_rejected(self):
        group = "host_display_wrap"
        filename = GROUPS[group]
        for name in ("/other/" + filename, ROOT + "/" + filename + ".old",
                     ROOT + "/./" + filename, NODE + filename, CORE + "converters.go"):
            with self.subTest(name=name), self.assertRaisesRegex(InvalidProfile, "unmapped"):
                normalize(profile(name + ROW), ROOT, group, "normal")

    def test_core_roster_missing_or_extra_is_rejected(self):
        group = "memory_display_units"
        local = ROOT + "/" + GROUPS[group] + ROW
        core = [CORE + name + ROW for name in CORE_FILES]
        with self.assertRaisesRegex(InvalidProfile, "incomplete"):
            normalize(profile(local, *core[:-1]), ROOT, group, "race")
        with self.assertRaisesRegex(InvalidProfile, "unmapped"):
            normalize(profile(local, *core, CORE + "extra.go" + ROW), ROOT, group, "race")

    def test_duplicate_block_disallowed_even_if_counts_differ(self):
        group = "assessment_existing"
        name = ROOT + "/" + GROUPS[group]
        with self.assertRaisesRegex(InvalidProfile, "duplicate"):
            normalize(profile(name + ROW, name + ":1.2,3.4 2 0\n"), ROOT, group, "normal")

    def test_malformed_coordinates_and_profiles(self):
        group = "assessment_existing"
        name = ROOT + "/" + GROUPS[group]
        for raw in (b"mode: atomic\n", b"mode: count\n", b"\xff",
                    profile(name + ":0.2,3.4 2 1\n"),
                    profile(name + ":3.2,1.4 2 1\n"),
                    profile(name + ":1.2,3.4 -2 1\n"),
                    profile(name + ":1.2,3.4 2 9223372036854775808\n"),
                    profile(name + ":1.2,3.4 2 " + "9"*20 + "\n"),
                    profile(name + ROW).replace(b"\n", b"\r\n"),
                    profile(name + ROW).rstrip()):
            with self.subTest(raw=raw), self.assertRaises(InvalidProfile):
                normalize(raw, ROOT, group, "normal")

    def test_zero_statement_and_zero_count_blocks_retained(self):
        group = "assessment_existing"
        name = ROOT + "/" + GROUPS[group]
        raw = profile(name + ":1.1,1.2 0 1\n", name + ":2.1,2.2 5 0\n")
        portable, receipt = normalize(raw, ROOT, group, "normal")
        self.assertEqual(raw.replace((ROOT + "/").encode(), NODE.encode()), portable)
        self.assertEqual({"blocks": 2, "covered": 0, "total": 5},
                         receipt["scope_counts"]["node"])

    def test_invalid_group_mode_and_root(self):
        for root, group, mode in (("relative", "assessment_existing", "normal"),
                                  (ROOT + "/", "assessment_existing", "normal"),
                                  ("/", "assessment_existing", "normal"),
                                  (ROOT, "unknown", "normal"),
                                  (ROOT, "assessment_existing", "unknown")):
            with self.assertRaises(InvalidProfile):
                normalize(b"", root, group, mode)

    def test_cli_success_and_fail_closed_output(self):
        script = Path(__file__).with_name("normalize.py")
        group = "assessment_existing"
        with tempfile.TemporaryDirectory() as d:
            local = Path(d)
            raw = local / "raw.cover"
            OUT = local / "portable"
            command = [sys.executable, "-B", str(script), "--profile", str(raw),
                       "--checkout", ROOT, "--group", group, "--mode", "race",
                       "--output", str(OUT)]
            raw.write_bytes(profile("/unmapped/private-name.go" + ROW))
            result = subprocess.run(command, capture_output=True)
            self.assertEqual(1, result.returncode)
            self.assertNotIn(b"private-name", result.stderr)
            self.assertFalse(OUT.exists())
            raw.write_bytes(profile(ROOT + "/" + GROUPS[group] + ROW))
            result = subprocess.run(command, capture_output=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual({"coverage.cover", "receipt.json"},
                             {item.name for item in OUT.iterdir()})
            before = (OUT / "coverage.cover").read_bytes()
            receipt = json.loads((OUT / "receipt.json").read_text())
            self.assertEqual(sha256(before), receipt["portable_sha256"])
            self.assertEqual(1, subprocess.run(command, capture_output=True).returncode)
            self.assertEqual(before, (OUT / "coverage.cover").read_bytes())


if __name__ == "__main__":
    unittest.main()
