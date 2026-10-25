"""Tests for checksum-claim-audit."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from checksum_claim_audit import __version__  # noqa: E402
from checksum_claim_audit.__main__ import main  # noqa: E402
from checksum_claim_audit.audit import (  # noqa: E402
    VERSION,
    audit,
    collect_evidence,
    extract_claims,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def make_project(files):
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp, root


def run_main(args):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(args)
    return code, buf.getvalue()


class FixtureTests(unittest.TestCase):
    def test_good_verified_pass(self):
        res = audit(FIXTURES / "good" / "verified")
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["findings"], [])
        self.assertEqual(len(res["verified_claims"]), 1)
        self.assertEqual(res["verified_claims"][0]["family"], "verified")

    def test_good_noverify_pass(self):
        res = audit(FIXTURES / "good" / "noverify")
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["verified_claims"][0]["family"], "noverify")

    def test_bad_verified_high(self):
        res = audit(FIXTURES / "bad" / "verified")
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["findings"][0]["rule"], "documented-checksum-claim-false")
        self.assertEqual(res["findings"][0]["severity"], "HIGH")

    def test_bad_noverify_high(self):
        res = audit(FIXTURES / "bad" / "noverify")
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["findings"][0]["rule"], "documented-no-verification-claim-false")
        self.assertEqual(res["findings"][0]["severity"], "HIGH")
        self.assertTrue(res["findings"][0]["evidence"])

    def test_testonly_verified_medium(self):
        res = audit(FIXTURES / "testonly" / "verified")
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["findings"][0]["rule"], "documented-checksum-claim-false-test-only")
        self.assertEqual(res["findings"][0]["severity"], "MEDIUM")

    def test_testonly_noverify_medium(self):
        res = audit(FIXTURES / "testonly" / "noverify")
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["findings"][0]["rule"], "documented-no-verification-claim-false-test-only")
        self.assertEqual(res["findings"][0]["severity"], "MEDIUM")

    def test_testonly_fail_on_high_exits_zero(self):
        code, _ = run_main([str(FIXTURES / "testonly" / "verified"), "--fail-on", "HIGH"])
        self.assertEqual(code, 0)
        code, _ = run_main([str(FIXTURES / "testonly" / "noverify"), "--fail-on", "HIGH"])
        self.assertEqual(code, 0)

    def test_bad_json_valid_and_marker_absent(self):
        code, out = run_main([str(FIXTURES / "bad" / "verified"), "--json"])
        self.assertEqual(code, 2)
        parsed = json.loads(out)
        self.assertEqual(parsed["status"], "FAIL")
        self.assertNotIn("CHECKSUM_MARKER_DO_NOT_READ", out)
        self.assertNotIn("7f3a9c1e", out)

    def test_cli_exits(self):
        code, _ = run_main([str(FIXTURES / "good" / "verified")])
        self.assertEqual(code, 0)
        code, _ = run_main([str(FIXTURES / "bad" / "verified")])
        self.assertEqual(code, 2)
        code, _ = run_main([str(FIXTURES / "does-not-exist")])
        self.assertEqual(code, 1)

    def test_version(self):
        self.assertEqual(VERSION, "0.1.0")
        self.assertEqual(__version__, "0.1.0")
        with self.assertRaises(SystemExit) as ctx:
            run_main(["--version"])
        self.assertEqual(ctx.exception.code, 0)


class ClaimTests(unittest.TestCase):
    def claim_families(self, readme, extra=None):
        files = {"README.md": readme, "main.py": "x = 1\n"}
        if extra:
            files.update(extra)
        tmp, root = make_project(files)
        with tmp:
            return extract_claims(root, [])

    def test_sha256_phrase(self):
        self.assertIn("verified", self.claim_families("This tool verifies sha256 before use.\n"))

    def test_sha_256_hyphen_phrase(self):
        self.assertIn("verified", self.claim_families("Downloads are SHA-256 verified.\n"))

    def test_integrity_phrase(self):
        self.assertIn("verified", self.claim_families("The installer verifies file integrity.\n"))

    def test_hash_verified_phrase(self):
        self.assertIn("verified", self.claim_families("Every hash verified on download.\n"))

    def test_checksum_checked_phrase(self):
        self.assertIn("verified", self.claim_families("Each checksum checked before install.\n"))

    def test_noverify_phrases(self):
        for text in (
            "No checksum verification is performed.\n",
            "This tool never verifies checksums.\n",
            "Without checksum verification, files are used as-is.\n",
            "No integrity verification is done.\n",
            "Checksums are not verified here.\n",
        ):
            with self.subTest(text=text):
                families = self.claim_families(text)
                self.assertIn("noverify", families)
                self.assertNotIn("verified", families)

    def test_negated_verified_suppressed(self):
        families = self.claim_families("This tool never verifies checksums.\n")
        self.assertEqual(set(families), {"noverify"})

    def test_negated_sentence_no_verified(self):
        families = self.claim_families("This tool does not verify checksums.\n")
        self.assertEqual(set(families), {"noverify"})

    def test_apostrophe_negation(self):
        families = self.claim_families("This tool doesn't verify checksums.\n")
        self.assertIn("noverify", families)

    def test_fenced_code_excluded(self):
        readme = "```\nThis tool verifies checksums.\n```\nNothing here.\n"
        self.assertEqual(self.claim_families(readme), {})

    def test_inline_code_counts(self):
        families = self.claim_families("This tool `verifies checksums` on install.\n")
        self.assertIn("verified", families)

    def test_bare_checksum_noun_no_claim(self):
        self.assertEqual(self.claim_families("Checksums are important in general.\n"), {})

    def test_bare_integrity_noun_no_claim(self):
        self.assertEqual(self.claim_families("File integrity matters a lot.\n"), {})

    def test_docs_subdir_claims(self):
        families = self.claim_families(
            "Intro.\n", {"docs/guide.md": "This tool verifies checksums.\n"})
        self.assertIn("verified", families)

    def test_docs_nested_subdir_claims(self):
        families = self.claim_families(
            "Intro.\n", {"docs/a/b.md": "This tool verifies checksums.\n"})
        self.assertIn("verified", families)

    def test_case_insensitive_claim(self):
        self.assertIn("verified", self.claim_families("This Tool Verifies Checksums.\n"))

    def test_hyphen_variant_claim(self):
        self.assertIn("verified", self.claim_families("Downloads are checksum-verified.\n"))

    def test_sentence_split_newline(self):
        families = self.claim_families("Intro line\nThis tool verifies checksums\nDone.\n")
        self.assertIn("verified", families)

    def test_no_claims_pass(self):
        tmp, root = make_project({"README.md": "Hello.\n", "main.py": "x = 1\n"})
        with tmp:
            res = audit(root)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["findings"], [])

    def test_no_source_verified_high(self):
        tmp, root = make_project({"README.md": "This tool verifies checksums.\n"})
        with tmp:
            res = audit(root)
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["findings"][0]["evidence"], ["no-source"])
        self.assertEqual(res["findings"][0]["severity"], "HIGH")

    def test_no_source_noverify_high(self):
        tmp, root = make_project({"README.md": "This tool does not verify checksums.\n"})
        with tmp:
            res = audit(root)
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["findings"][0]["rule"], "documented-no-verification-claim-false")
        self.assertEqual(res["findings"][0]["evidence"], ["no-source"])

    def test_ignore_glob_skips_docs(self):
        tmp, root = make_project({"README.md": "This tool verifies checksums.\n",
                                   "main.py": "x = 1\n"})
        with tmp:
            res = audit(root, ["README.md"])
        self.assertEqual(res["status"], "PASS")

    def test_ignore_source_glob_no_source(self):
        tmp, root = make_project({"README.md": "This tool verifies checksums.\n",
                                   "main.py": "import hashlib\nprint(hashlib.sha256(b'x').hexdigest())\n"})
        with tmp:
            res = audit(root, ["main.py"])
        self.assertEqual(res["findings"][0]["evidence"], ["no-source"])

    def test_both_families_one_finding(self):
        tmp, root = make_project({
            "README.md": "This tool verifies checksums. It does not verify checksums twice.\n",
            "main.py": "import hashlib\nprint(hashlib.sha256(b'x').hexdigest())\n"})
        with tmp:
            res = audit(root)
        # Verified claim holds (evidence present); the noverify sentence is
        # a second claim in the same README and is falsified by the evidence.
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["findings"][0]["rule"], "documented-no-verification-claim-false")

    def test_multiple_phrases_one_finding(self):
        tmp, root = make_project({
            "README.md": "This tool verifies checksums. File integrity verified too.\n",
            "main.py": "x = 1\n"})
        with tmp:
            res = audit(root)
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(len(res["findings"][0]["evidence"]), 1)

    def test_symlink_doc_skipped(self):
        tmp, root = make_project({"real.md": "This tool verifies checksums.\n",
                                   "main.py": "x = 1\n"})
        with tmp:
            try:
                os.symlink(root / "real.md", root / "README.md")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            res = audit(root)
        self.assertEqual(res["status"], "PASS")


class EvidenceTests(unittest.TestCase):
    def evidence(self, code):
        tmp, root = make_project({"README.md": "x\n", "main.py": code})
        with tmp:
            return collect_evidence(root / "main.py", "main.py")

    def test_each_digest_call(self):
        for name in ("sha1", "sha224", "sha256", "sha384", "sha512",
                     "sha3_256", "blake2b", "blake2s", "md5"):
            with self.subTest(name=name):
                items = self.evidence("import hashlib\nprint(hashlib.%s(b'x').hexdigest())\n" % name)
                self.assertEqual(len(items), 1)

    def test_hashlib_new_literal(self):
        items = self.evidence("import hashlib\nprint(hashlib.new('sha256', b'x').hexdigest())\n")
        self.assertEqual(len(items), 1)

    def test_hashlib_new_variable(self):
        items = self.evidence("import hashlib\nprint(hashlib.new(algo, b'x').hexdigest())\n")
        self.assertEqual(len(items), 1)

    def test_file_digest(self):
        items = self.evidence("import hashlib\nprint(hashlib.file_digest(f, 'sha256'))\n")
        self.assertEqual(len(items), 1)

    def test_hmac_digest(self):
        items = self.evidence("import hmac\nprint(hmac.digest(b'k', b'm', 'sha256'))\n")
        self.assertEqual(len(items), 1)

    def test_hmac_compare_digest(self):
        items = self.evidence("import hmac\nprint(hmac.compare_digest(a, b))\n")
        self.assertEqual(len(items), 1)

    def test_bare_imported_name(self):
        items = self.evidence("from hashlib import sha256\nprint(sha256(b'x').hexdigest())\n")
        self.assertEqual(len(items), 1)

    def test_aliased_imported_name(self):
        items = self.evidence("from hashlib import sha256 as h256\nprint(h256(b'x').hexdigest())\n")
        self.assertEqual(len(items), 1)

    def test_module_alias(self):
        items = self.evidence("import hashlib as hl\nprint(hl.sha256(b'x').hexdigest())\n")
        self.assertEqual(len(items), 1)

    def test_chained_digest_method(self):
        items = self.evidence("import hashlib\nprint(hashlib.sha256(b'x').digest())\n")
        self.assertEqual(len(items), 1)

    def test_shadowed_local_name_not_evidence(self):
        code = ("from hashlib import sha256\ndef sha256(data):\n    return data\n"
                "print(sha256(b'x'))\n")
        self.assertEqual(self.evidence(code), [])

    def test_bare_import_not_evidence(self):
        self.assertEqual(self.evidence("import hashlib\nx = 1\n"), [])
        self.assertEqual(self.evidence("import hmac\nx = 1\n"), [])

    def test_hash_builtin_not_evidence(self):
        self.assertEqual(self.evidence("print(hash('x'))\n"), [])

    def test_crc32_not_evidence(self):
        self.assertEqual(self.evidence("import zlib\nprint(zlib.crc32(b'x'))\n"), [])
        self.assertEqual(self.evidence("import binascii\nprint(binascii.crc32(b'x'))\n"), [])

    def test_syntax_error_no_crash(self):
        self.assertEqual(self.evidence("def broken(:\n"), [])

    def test_examples_excluded(self):
        tmp, root = make_project({
            "README.md": "This tool verifies checksums.\n",
            "main.py": "x = 1\n",
            "examples/demo.py": "import hashlib\nprint(hashlib.sha256(b'x').hexdigest())\n"})
        with tmp:
            res = audit(root)
        self.assertEqual(res["findings"][0]["severity"], "HIGH")

    def test_test_file_prefix_is_test_evidence(self):
        tmp, root = make_project({
            "README.md": "This tool verifies checksums.\n",
            "main.py": "x = 1\n",
            "test_main.py": "import hashlib\nprint(hashlib.sha256(b'x').hexdigest())\n"})
        with tmp:
            res = audit(root)
        self.assertEqual(res["findings"][0]["severity"], "MEDIUM")

    def test_evidence_sorted_in_finding(self):
        tmp, root = make_project({
            "README.md": "This tool does not verify checksums.\n",
            "b.py": "import hashlib\nprint(hashlib.sha256(b'x').hexdigest())\n",
            "a.py": "import hashlib\nprint(hashlib.md5(b'x').hexdigest())\n"})
        with tmp:
            res = audit(root)
        ev = res["findings"][0]["evidence"]
        self.assertEqual(ev, sorted(ev))
        self.assertTrue(ev[0].startswith("a.py:"))

    def test_symlink_source_skipped(self):
        tmp, root = make_project({
            "README.md": "This tool verifies checksums.\n",
            "main.py": "x = 1\n"})
        with tmp:
            outside = Path(tmp.name).parent / "outside-target.py"
            outside.write_text(
                "import hashlib\nprint(hashlib.sha256(b'x').hexdigest())\n",
                encoding="utf-8")
            try:
                os.symlink(outside, root / "linked.py")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            res = audit(root)
        # The only digest evidence lives behind a symlink, which is skipped.
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(res["findings"][0]["rule"], "documented-checksum-claim-false")


class ExtraTests(unittest.TestCase):
    def test_self_audit_pass(self):
        root = Path(__file__).resolve().parents[1]
        res = audit(root)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["claims"], {})

    def test_subdir_readme_not_counted(self):
        tmp, root = make_project({
            "README.md": "Intro.\n",
            "sub/README.md": "This tool verifies checksums.\n",
            "main.py": "x = 1\n"})
        with tmp:
            res = audit(root)
        self.assertEqual(res["status"], "PASS")

    def test_noverify_in_docs_subdir(self):
        tmp, root = make_project({
            "README.md": "Intro.\n",
            "docs/guide.md": "This tool does not verify checksums.\n",
            "main.py": "import hashlib\nprint(hashlib.sha256(b'x').hexdigest())\n"})
        with tmp:
            res = audit(root)
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["findings"][0]["rule"], "documented-no-verification-claim-false")

    def test_word_boundary_blocks_partial(self):
        tmp, root = make_project({
            "README.md": "This tool verifies checksumsx daily.\n",
            "main.py": "x = 1\n"})
        with tmp:
            self.assertEqual(extract_claims(root, []), {})

    def test_hmac_module_alias(self):
        tmp, root = make_project({"README.md": "x\n",
                                   "main.py": "import hmac as hm\nprint(hm.compare_digest(a, b))\n"})
        with tmp:
            items = collect_evidence(root / "main.py", "main.py")
        self.assertEqual(len(items), 1)

    def test_shake_digest(self):
        tmp, root = make_project({"README.md": "x\n",
                                   "main.py": "import hashlib\nprint(hashlib.shake_256(b'x').hexdigest(8))\n"})
        with tmp:
            items = collect_evidence(root / "main.py", "main.py")
        self.assertEqual(len(items), 1)

    def test_new_via_bare_import(self):
        tmp, root = make_project({"README.md": "x\n",
                                   "main.py": "from hashlib import new\nprint(new('sha256', b'x').hexdigest())\n"})
        with tmp:
            items = collect_evidence(root / "main.py", "main.py")
        self.assertEqual(len(items), 1)

    def test_file_digest_via_bare_import(self):
        tmp, root = make_project({"README.md": "x\n",
                                   "main.py": "from hashlib import file_digest\nprint(file_digest(f, 'sha256'))\n"})
        with tmp:
            items = collect_evidence(root / "main.py", "main.py")
        self.assertEqual(len(items), 1)


class OutputTests(unittest.TestCase):
    def test_json_structure(self):
        code, out = run_main([str(FIXTURES / "bad" / "noverify"), "--json"])
        self.assertEqual(code, 2)
        parsed = json.loads(out)
        self.assertEqual(set(parsed), {"status", "findings", "verified_claims", "claims"})
        self.assertEqual(parsed["claims"]["noverify"], ["does not verify checksums"])

    def test_human_output_lists_evidence(self):
        code, out = run_main([str(FIXTURES / "bad" / "noverify")])
        self.assertEqual(code, 2)
        self.assertIn("documented-no-verification-claim-false", out)
        self.assertIn("evidence:", out)
        self.assertIn("main.py:", out)

    def test_verbose_lists_phrases(self):
        code, out = run_main([str(FIXTURES / "good" / "verified"), "--verbose"])
        self.assertEqual(code, 0)
        self.assertIn("verifies checksums", out)

    def test_fail_on_default_medium_exits_two(self):
        code, _ = run_main([str(FIXTURES / "testonly" / "verified")])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
