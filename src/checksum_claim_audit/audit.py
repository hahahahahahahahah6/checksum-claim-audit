"""Core audit logic: docs checksum claims vs Python source evidence."""

import ast
import fnmatch
import json
import re
from pathlib import Path

VERSION = "0.1.0"

# Longest first so a longer phrase wins when both match one sentence;
# families collapse matches anyway, order only affects reported phrases.
VERIFIED_PHRASES = [
    "verifies checksums",
    "checksum verification",
    "checksums are verified",
    "checksum verified",
    "checksum checked",
    "verifies file integrity",
    "file integrity verified",
    "integrity verified",
    "verifies integrity",
    "integrity checked",
    "hash verified",
    "verifies hashes",
    "sha 256 verified",
    "verifies sha 256",
    "sha256 verified",
    "verifies sha256",
]

NOVERIFY_PHRASES = [
    "no checksum verification",
    "does not verify checksums",
    "never verifies checksums",
    "without checksum verification",
    "no integrity verification",
    "does not verify integrity",
    "checksums are not verified",
]

VERIFIED = "verified"
NOVERIFY = "noverify"

PHRASE_FAMILIES = (
    [(p, VERIFIED) for p in VERIFIED_PHRASES]
    + [(p, NOVERIFY) for p in NOVERIFY_PHRASES]
)

NEGATIONS = {"no", "not", "never", "without"}
DIGESTS = {
    "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
    "blake2b", "blake2s", "md5", "shake_128", "shake_256",
}
EXCLUDE_DIRS = {"tests", "fixtures", "docs", "examples"}
TEST_DIRS = {"tests", "fixtures"}


def normalize(text):
    text = text.lower().replace("n't", " not")
    text = text.replace("-", " ")
    return re.sub(r"\s+", " ", text).strip()


def strip_fenced(text):
    lines = text.splitlines()
    out = []
    in_fence = False
    for line in lines:
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            out.append(line)
    return "\n".join(out)


def split_sentences(text):
    parts = re.split(r"[.!?\n]+", text)
    return [p.strip() for p in parts if p.strip()]


def extract_claims(root, ignore):
    """Return {family: [phrase, ...]} found in root README + docs/**/*.md."""
    doc_files = []
    readme = root / "README.md"
    if readme.is_file() and not readme.is_symlink():
        doc_files.append(readme)
    docs_dir = root / "docs"
    if docs_dir.is_dir():
        for path in sorted(docs_dir.rglob("*.md")):
            if not path.is_symlink():
                doc_files.append(path)
    found = {}
    for path in doc_files:
        rel = path.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(rel, pat) for pat in ignore):
            continue
        text = strip_fenced(path.read_text(encoding="utf-8", errors="replace"))
        for sentence in split_sentences(normalize(text)):
            tokens = set(sentence.split(" "))
            negated = bool(tokens & NEGATIONS)
            for phrase, family in PHRASE_FAMILIES:
                if family == VERIFIED and negated:
                    continue
                pattern = r"\b" + re.escape(phrase) + r"\b"
                if not re.search(pattern, sentence):
                    continue
                found.setdefault(family, [])
                if phrase not in found[family]:
                    found[family].append(phrase)
    return found


def dotted(node):
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)
    return None


def local_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        if isinstance(node, ast.arguments):
            for arg in list(node.posonlyargs) + list(node.args) + list(node.kwonlyargs):
                names.add(arg.arg)
            if node.vararg:
                names.add(node.vararg.arg)
            if node.kwarg:
                names.add(node.kwarg.arg)
    return names


def import_aliases(tree):
    """Map local name -> canonical dotted target for hashlib/hmac imports."""
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in ("hashlib", "hmac"):
                    aliases[alias.asname or top] = alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module in ("hashlib", "hmac"):
                for alias in node.names:
                    aliases[alias.asname or alias.name] = node.module + "." + alias.name
    return aliases


def call_target(node):
    """Dotted target of a Call, resolving through .hexdigest()/.digest()."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        if func.attr in ("hexdigest", "digest") and isinstance(func.value, ast.Call):
            return call_target(func.value)
        return dotted(func)
    return None


def collect_evidence(path, rel):
    """Return [evidence items] for one .py file."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return []
    shadowed = local_names(tree)
    aliases = import_aliases(tree)
    items = []

    def add(kind, lineno, detail):
        item = "%s:%s %s (%s)" % (rel, lineno, kind, detail)
        if item not in items:
            items.append(item)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = call_target(node)
        if target is None:
            continue
        parts = target.split(".")
        # Resolve a leading alias: hl.sha256 -> hashlib.sha256, h256 -> hashlib.sha256.
        # A bare name shadowed by a local definition does not count.
        if len(parts) == 1 and parts[0] in shadowed and parts[0] in aliases:
            continue
        if parts[0] in aliases:
            canonical = aliases[parts[0]]
            parts = canonical.split(".") + parts[1:]
            target = ".".join(parts)
        if len(parts) >= 2 and parts[0] == "hashlib":
            if parts[1] in DIGESTS:
                add("call", node.lineno, target)
            elif parts[1] in ("new", "file_digest"):
                add("call", node.lineno, target)
        elif len(parts) >= 2 and parts[0] == "hmac":
            if parts[1] in ("digest", "compare_digest"):
                add("call", node.lineno, target)
        elif len(parts) == 1 and parts[0] in DIGESTS:
            # Bare digest name with no hashlib import in this file: not
            # evidence (could be anything); only imported names count.
            continue
    return items


def classify(path, root):
    rel = path.relative_to(root)
    parts = set(rel.parts[:-1])
    if parts & TEST_DIRS or path.name.startswith("test_") or path.name.endswith("_test.py"):
        return "test"
    if parts & EXCLUDE_DIRS:
        return "skip"
    return "prod"


def audit(root, ignore=()):
    ignore = list(ignore or [])
    claims = extract_claims(root, ignore)
    prod_files = []
    test_files = []
    for path in sorted(root.rglob("*.py")):
        if path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(rel, pat) for pat in ignore):
            continue
        kind = classify(path, root)
        if kind == "prod":
            prod_files.append(path)
        elif kind == "test":
            test_files.append(path)
    prod_ev = []
    test_ev = []
    for path in prod_files:
        prod_ev += collect_evidence(path, path.relative_to(root).as_posix())
    for path in test_files:
        test_ev += collect_evidence(path, path.relative_to(root).as_posix())

    findings = []
    verified = []

    def check_positive(family, high_rule, med_rule):
        if family not in claims:
            return
        if not prod_files:
            findings.append({
                "rule": high_rule, "severity": "HIGH", "family": family,
                "evidence": ["no-source"],
            })
        elif prod_ev:
            verified.append({"family": family, "phrases": claims[family]})
        elif test_ev:
            findings.append({
                "rule": med_rule, "severity": "MEDIUM", "family": family,
                "evidence": sorted(test_ev),
            })
        else:
            findings.append({
                "rule": high_rule, "severity": "HIGH", "family": family,
                "evidence": ["no evidence"],
            })

    def check_negative(family, high_rule, med_rule):
        if family not in claims:
            return
        if not prod_files:
            findings.append({
                "rule": high_rule, "severity": "HIGH", "family": family,
                "evidence": ["no-source"],
            })
        elif prod_ev:
            findings.append({
                "rule": high_rule, "severity": "HIGH", "family": family,
                "evidence": sorted(prod_ev),
            })
        elif test_ev:
            findings.append({
                "rule": med_rule, "severity": "MEDIUM", "family": family,
                "evidence": sorted(test_ev),
            })
        else:
            verified.append({"family": family, "phrases": claims[family]})

    check_positive(VERIFIED,
                   "documented-checksum-claim-false",
                   "documented-checksum-claim-false-test-only")
    check_negative(NOVERIFY,
                   "documented-no-verification-claim-false",
                   "documented-no-verification-claim-false-test-only")
    status = "PASS" if not findings else "FAIL"
    return {
        "status": status,
        "findings": findings,
        "verified_claims": verified,
        "claims": {k: v for k, v in claims.items()},
    }


def result_json(result):
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def format_human(result):
    lines = ["%s" % result["status"]]
    for f in result["findings"]:
        lines.append("%s %s (%s)" % (f["severity"], f["rule"], f["family"]))
        for item in f["evidence"]:
            lines.append("  evidence: %s" % item)
    for claim in result["verified_claims"]:
        lines.append("verified: %s" % claim["family"])
    return "\n".join(lines) + "\n"
