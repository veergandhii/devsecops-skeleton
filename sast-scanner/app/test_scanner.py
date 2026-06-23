"""
test_scanner.py — CodeSheriff SAST Scanner Test Suite

Option 1 — Install locally (quickest, run tests on your machine)
bashpip install bandit semgrep
Option 2 — Run pytest inside the container (no local install needed)

bashdocker compose exec sast-scanner pytest test_scanner.py -v
Tests every Semgrep rule and key Bandit tests with:
  - A VULNERABLE payload that MUST trigger the rule
  - A SAFE payload that MUST NOT trigger the rule
  - Expected rule_id and minimum finding count

Run with: pytest test_scanner.py -v
Or a single test: pytest test_scanner.py::TestHardcodedPassword -v

IMPORTANT: semgrep and bandit must be installed in your environment.
  pip install bandit semgrep

If running locally (not in Docker):
  export RULES_PATH="./sast-scanner/rules/python-security.yml"

DESIGN NOTE — rules_path injection:
  scan() now accepts an optional rules_path kwarg so integration tests can
  pass RULES_PATH directly instead of relying on __file__ resolution, which
  breaks when pytest is invoked from a directory other than the project root.
"""

import pytest
import os
import sys

# Add the app directory to path so we can import scanner.py
# Adjust this path to match your actual project structure
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "sast-scanner", "app"))

from scanner import run_semgrep, run_bandit, scan

# Path to our local Semgrep rules — injected into run_semgrep() and scan() calls
# so tests are not sensitive to the working directory pytest is invoked from.
RULES_PATH = os.environ.get(
    "RULES_PATH",
    # test file lives in sast-scanner/app/ → go up one level to sast-scanner/,
    # then into rules/. Same resolution scan() uses internally, so it works
    # regardless of the directory pytest is invoked from.
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "python-security.yml")
)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def semgrep_findings(code: str) -> list[dict]:
    """Run semgrep and return the full findings list."""
    return run_semgrep(code, "python", RULES_PATH)

def semgrep_rule_ids(code: str) -> set[str]:
    """Run semgrep and return the set of rule_ids found."""
    return {f["rule_id"] for f in semgrep_findings(code)}

def bandit_findings(code: str) -> list[dict]:
    """Run bandit and return the full findings list."""
    return run_bandit(code)

def bandit_test_ids(code: str) -> set[str]:
    """Run bandit and return the set of test_ids found."""
    return {f["rule_id"] for f in bandit_findings(code)}


# ─────────────────────────────────────────────────────────────────────────────
# FINDING SCHEMA VALIDATORS
# ─────────────────────────────────────────────────────────────────────────────

# Keys every semgrep finding must have (col is present in semgrep findings)
SEMGREP_REQUIRED_KEYS = {"tool", "rule_id", "message", "severity", "line", "col", "code_snippet", "remediation"}

# Keys every bandit finding must have (col is not in bandit output)
BANDIT_REQUIRED_KEYS  = {"tool", "rule_id", "message", "severity", "confidence", "line", "code_snippet", "remediation"}


def assert_semgrep_schema(finding: dict):
    missing = SEMGREP_REQUIRED_KEYS - set(finding.keys())
    assert not missing, f"Semgrep finding {finding.get('rule_id')} missing keys: {missing}"

def assert_bandit_schema(finding: dict):
    missing = BANDIT_REQUIRED_KEYS - set(finding.keys())
    assert not missing, f"Bandit finding {finding.get('rule_id')} missing keys: {missing}"


# ─────────────────────────────────────────────────────────────────────────────
# RULE 1: hardcoded-password (Semgrep) + B105/B106/B107 (Bandit)
# ─────────────────────────────────────────────────────────────────────────────

class TestHardcodedPassword:
    RULE_ID = "hardcoded-password"

    VULNERABLE = [
        'password = "super_secret_123"',
        'api_key = "sk-abc123xyz"',
        'secret = "hunter2"',
        'token = "ghp_mytoken"',
        'auth_token = "Bearer abc123"',
    ]

    SAFE = [
        'password = os.environ["PASSWORD"]',
        'username = "admin"',                        # not a secret keyword
        'message = "hello world"',                   # not a secret variable name
        'description = "my password is strong"',     # 'password' in value, not var name
    ]

    def test_vulnerable_triggers(self):
        for code in self.VULNERABLE:
            found = semgrep_rule_ids(code)
            assert self.RULE_ID in found, (
                f"Expected '{self.RULE_ID}' to fire on:\n{code}\nGot: {found}"
            )

    def test_safe_does_not_trigger(self):
        for code in self.SAFE:
            found = semgrep_rule_ids(code)
            assert self.RULE_ID not in found, (
                f"Expected '{self.RULE_ID}' NOT to fire on:\n{code}\nGot: {found}"
            )

    def test_semgrep_finding_schema(self):
        results = semgrep_findings(self.VULNERABLE[0])
        target = [f for f in results if f["rule_id"] == self.RULE_ID]
        assert target, "No finding returned for hardcoded-password"
        assert_semgrep_schema(target[0])

    def test_bandit_hardcoded_password_string(self):
        # B105 fires when a string literal is assigned to a password-like variable
        code = 'password = "hunter2"'
        assert "B105" in bandit_test_ids(code)

    def test_bandit_hardcoded_password_funcarg(self):
        # B106 fires when a hardcoded string is passed as a password argument
        code = 'import db\ndb.connect(password="admin")'
        assert "B106" in bandit_test_ids(code)

    def test_bandit_hardcoded_password_default(self):
        # B107 fires when a function has a hardcoded default for a password param
        code = 'def connect(host, password="admin123"): pass'
        assert "B107" in bandit_test_ids(code)


# ─────────────────────────────────────────────────────────────────────────────
# RULE 2: pickle-deserialization (Semgrep) + B301/B403 (Bandit)
# ─────────────────────────────────────────────────────────────────────────────

class TestPickleDeserialization:
    SEMGREP_RULE = "pickle-deserialization"
    BANDIT_LOADS = "B301"   # pickle.loads() call
    BANDIT_IMPORT = "B403"  # import pickle

    VULNERABLE = "import pickle\ndata = pickle.loads(user_bytes)"
    SAFE = "import json\ndata = json.loads(user_bytes)"

    def test_semgrep_triggers(self):
        assert self.SEMGREP_RULE in semgrep_rule_ids(self.VULNERABLE)

    def test_bandit_loads_triggers(self):
        assert self.BANDIT_LOADS in bandit_test_ids(self.VULNERABLE)

    def test_bandit_import_triggers(self):
        # Bandit always warns on `import pickle` regardless of usage
        assert self.BANDIT_IMPORT in bandit_test_ids(self.VULNERABLE)

    def test_safe_no_semgrep(self):
        assert self.SEMGREP_RULE not in semgrep_rule_ids(self.SAFE)

    def test_safe_no_bandit_loads(self):
        assert self.BANDIT_LOADS not in bandit_test_ids(self.SAFE)

    def test_semgrep_finding_schema(self):
        results = semgrep_findings(self.VULNERABLE)
        target = [f for f in results if f["rule_id"] == self.SEMGREP_RULE]
        assert target
        assert_semgrep_schema(target[0])

    def test_bandit_finding_schema(self):
        results = bandit_findings(self.VULNERABLE)
        target = [f for f in results if f["rule_id"] == self.BANDIT_LOADS]
        assert target
        assert_bandit_schema(target[0])


# ─────────────────────────────────────────────────────────────────────────────
# RULE 3: subprocess-shell-true (Semgrep) + B602/B404 (Bandit)
# ─────────────────────────────────────────────────────────────────────────────

class TestSubprocessShellTrue:
    SEMGREP_RULE = "subprocess-shell-true"
    BANDIT_SHELL = "B602"   # shell=True call
    BANDIT_IMPORT = "B404"  # import subprocess

    VULNERABLE_PATTERNS = [
        "import subprocess\nsubprocess.call('ls', shell=True)",
        "import subprocess\nsubprocess.run('ls', shell=True)",
        "import subprocess\nsubprocess.Popen('ls', shell=True)",
        "import subprocess\nsubprocess.check_output('ls', shell=True)",
    ]

    SAFE = "import subprocess\nsubprocess.run(['ls', '-la'])"

    def test_semgrep_triggers_all_patterns(self):
        for code in self.VULNERABLE_PATTERNS:
            assert self.SEMGREP_RULE in semgrep_rule_ids(code), (
                f"semgrep should fire on: {code}"
            )

    def test_bandit_shell_triggers(self):
        assert self.BANDIT_SHELL in bandit_test_ids(self.VULNERABLE_PATTERNS[0])

    def test_bandit_import_triggers(self):
        assert self.BANDIT_IMPORT in bandit_test_ids(self.VULNERABLE_PATTERNS[0])

    def test_safe_no_semgrep(self):
        assert self.SEMGREP_RULE not in semgrep_rule_ids(self.SAFE)

    def test_semgrep_finding_schema(self):
        results = semgrep_findings(self.VULNERABLE_PATTERNS[0])
        target = [f for f in results if f["rule_id"] == self.SEMGREP_RULE]
        assert target
        assert_semgrep_schema(target[0])


# ─────────────────────────────────────────────────────────────────────────────
# RULE 4: dangerous-eval (Semgrep) + B307 (Bandit)
# ─────────────────────────────────────────────────────────────────────────────

class TestDangerousEval:
    SEMGREP_RULE = "dangerous-eval"
    BANDIT_RULE = "B307"

    VULNERABLE_EVAL = "user_input = input()\nresult = eval(user_input)"
    VULNERABLE_EXEC = "user_input = input()\nexec(user_input)"
    SAFE = "import ast\nresult = ast.literal_eval(user_input)"

    def test_semgrep_triggers_eval(self):
        assert self.SEMGREP_RULE in semgrep_rule_ids(self.VULNERABLE_EVAL)

    def test_semgrep_triggers_exec(self):
        assert self.SEMGREP_RULE in semgrep_rule_ids(self.VULNERABLE_EXEC)

    def test_bandit_triggers(self):
        assert self.BANDIT_RULE in bandit_test_ids(self.VULNERABLE_EVAL)

    def test_safe_no_semgrep(self):
        assert self.SEMGREP_RULE not in semgrep_rule_ids(self.SAFE)

    def test_semgrep_finding_schema(self):
        results = semgrep_findings(self.VULNERABLE_EVAL)
        target = [f for f in results if f["rule_id"] == self.SEMGREP_RULE]
        assert target
        assert_semgrep_schema(target[0])


# ─────────────────────────────────────────────────────────────────────────────
# RULE 5: sql-injection-string-format (Semgrep) + B608 (Bandit)
# ─────────────────────────────────────────────────────────────────────────────

class TestSQLInjection:
    SEMGREP_RULE = "sql-injection-string-format"
    BANDIT_RULE = "B608"

    VULNERABLE_PATTERNS = [
        'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
        'cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
        'cursor.execute("SELECT * FROM users WHERE id=%s" % user_id)',
    ]

    SAFE = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'

    def test_semgrep_triggers_all(self):
        for code in self.VULNERABLE_PATTERNS:
            assert self.SEMGREP_RULE in semgrep_rule_ids(code), (
                f"Expected SQL injection rule on: {code}"
            )

    def test_bandit_triggers(self):
        # B608 fires on string-constructed SQL
        assert self.BANDIT_RULE in bandit_test_ids(self.VULNERABLE_PATTERNS[1])

    def test_safe_no_semgrep(self):
        assert self.SEMGREP_RULE not in semgrep_rule_ids(self.SAFE)

    def test_semgrep_finding_schema(self):
        results = semgrep_findings(self.VULNERABLE_PATTERNS[0])
        target = [f for f in results if f["rule_id"] == self.SEMGREP_RULE]
        assert target
        assert_semgrep_schema(target[0])


# ─────────────────────────────────────────────────────────────────────────────
# RULE 6: hardcoded-ip-address (Semgrep)
# ─────────────────────────────────────────────────────────────────────────────

class TestHardcodedIPAddress:
    SEMGREP_RULE = "hardcoded-ip-address"

    VULNERABLE_PATTERNS = [
        'host = "192.168.1.1"',
        'db_host = "10.0.0.5"',
        'server = "172.16.0.100"',
    ]

    SAFE = [
        'host = os.environ.get("DB_HOST", "localhost")',
        'host = "localhost"',
        'url = "https://api.example.com"',
    ]

    def test_triggers_on_private_ips(self):
        for code in self.VULNERABLE_PATTERNS:
            assert self.SEMGREP_RULE in semgrep_rule_ids(code), (
                f"Expected hardcoded-ip-address on: {code}"
            )

    def test_safe_no_trigger(self):
        for code in self.SAFE:
            assert self.SEMGREP_RULE not in semgrep_rule_ids(code)

    def test_semgrep_finding_schema(self):
        results = semgrep_findings(self.VULNERABLE_PATTERNS[0])
        target = [f for f in results if f["rule_id"] == self.SEMGREP_RULE]
        assert target
        assert_semgrep_schema(target[0])


# ─────────────────────────────────────────────────────────────────────────────
# RULE 7: weak-hash-algorithm (Semgrep) + B303/B324 (Bandit)
# ─────────────────────────────────────────────────────────────────────────────

class TestWeakHashAlgorithm:
    SEMGREP_RULE = "weak-hash-algorithm"
    BANDIT_RULES = {"B303", "B324"}

    VULNERABLE_PATTERNS = [
        "import hashlib\nhashlib.md5(data.encode())",
        "import hashlib\nhashlib.sha1(data.encode())",
        'import hashlib\nhashlib.new("md5", data.encode())',
        'import hashlib\nhashlib.new("sha1", data.encode())',
    ]

    SAFE = "import hashlib\nhashlib.sha256(data.encode())"

    def test_semgrep_triggers(self):
        for code in self.VULNERABLE_PATTERNS:
            assert self.SEMGREP_RULE in semgrep_rule_ids(code)

    def test_bandit_triggers(self):
        found = bandit_test_ids(self.VULNERABLE_PATTERNS[0])
        assert found & self.BANDIT_RULES, f"Expected one of {self.BANDIT_RULES}, got {found}"

    def test_safe_no_semgrep(self):
        assert self.SEMGREP_RULE not in semgrep_rule_ids(self.SAFE)

    def test_semgrep_finding_schema(self):
        results = semgrep_findings(self.VULNERABLE_PATTERNS[0])
        target = [f for f in results if f["rule_id"] == self.SEMGREP_RULE]
        assert target
        assert_semgrep_schema(target[0])


# ─────────────────────────────────────────────────────────────────────────────
# RULE 8: insecure-random (Semgrep) + B311 (Bandit)
# ─────────────────────────────────────────────────────────────────────────────

class TestInsecureRandom:
    SEMGREP_RULE = "insecure-random"
    BANDIT_RULE = "B311"

    VULNERABLE_PATTERNS = [
        "import random\ntoken = random.randint(100000, 999999)",
        "import random\nval = random.random()",
        "import random\nitem = random.choice(options)",
        "import random\nn = random.randrange(100)",
    ]

    SAFE = "import secrets\ntoken = secrets.token_hex(16)"

    def test_semgrep_triggers_all_patterns(self):
        for code in self.VULNERABLE_PATTERNS:
            assert self.SEMGREP_RULE in semgrep_rule_ids(code), (
                f"Expected insecure-random on: {code}"
            )

    def test_bandit_triggers(self):
        assert self.BANDIT_RULE in bandit_test_ids(self.VULNERABLE_PATTERNS[0])

    def test_safe_no_trigger(self):
        assert self.SEMGREP_RULE not in semgrep_rule_ids(self.SAFE)

    def test_semgrep_finding_schema(self):
        results = semgrep_findings(self.VULNERABLE_PATTERNS[0])
        target = [f for f in results if f["rule_id"] == self.SEMGREP_RULE]
        assert target
        assert_semgrep_schema(target[0])


# ─────────────────────────────────────────────────────────────────────────────
# RULE 9: assert-used-for-auth (Semgrep)
# ─────────────────────────────────────────────────────────────────────────────

class TestAssertUsedForAuth:
    SEMGREP_RULE = "assert-used-for-auth"

    VULNERABLE_PATTERNS = [
        "assert user.is_admin()",
        "assert is_authenticated(token)",
        "assert user.has_permission('write')",  # 'has_perm' in regex; 'permission' also matches
        "assert authorized",
    ]

    SAFE = [
        # Non-auth assert — 'len(items) > 0' doesn't match the auth regex
        "assert len(items) > 0, 'Items must not be empty'",
        # Correct pattern: explicit if/raise
        "if not user.is_admin(): raise PermissionError('Admin required')",
    ]

    def test_semgrep_triggers(self):
        for code in self.VULNERABLE_PATTERNS:
            assert self.SEMGREP_RULE in semgrep_rule_ids(code), (
                f"Expected assert-used-for-auth on: {code}"
            )

    def test_safe_no_trigger(self):
        for code in self.SAFE:
            assert self.SEMGREP_RULE not in semgrep_rule_ids(code)

    def test_semgrep_finding_schema(self):
        results = semgrep_findings(self.VULNERABLE_PATTERNS[0])
        target = [f for f in results if f["rule_id"] == self.SEMGREP_RULE]
        assert target
        assert_semgrep_schema(target[0])


# ─────────────────────────────────────────────────────────────────────────────
# RULE 10: bind-all-interfaces (Semgrep)
# ─────────────────────────────────────────────────────────────────────────────

class TestBindAllInterfaces:
    SEMGREP_RULE = "bind-all-interfaces"

    VULNERABLE_PATTERNS = [
        'import uvicorn\nuvicorn.run(app, host="0.0.0.0", port=8000)',
        'app.run(host="0.0.0.0", port=5000)',
    ]

    SAFE = 'import uvicorn\nuvicorn.run(app, host="127.0.0.1", port=8000)'

    def test_semgrep_triggers(self):
        for code in self.VULNERABLE_PATTERNS:
            assert self.SEMGREP_RULE in semgrep_rule_ids(code)

    def test_safe_no_trigger(self):
        assert self.SEMGREP_RULE not in semgrep_rule_ids(self.SAFE)

    def test_semgrep_finding_schema(self):
        results = semgrep_findings(self.VULNERABLE_PATTERNS[0])
        target = [f for f in results if f["rule_id"] == self.SEMGREP_RULE]
        assert target
        assert_semgrep_schema(target[0])


# ─────────────────────────────────────────────────────────────────────────────
# RULE 11: xxe-via-xml-parse (Semgrep) + B314/B318/B320 (Bandit)
# ─────────────────────────────────────────────────────────────────────────────

class TestXXEViaXMLParse:
    SEMGREP_RULE = "xxe-via-xml-parse"
    BANDIT_RULES = {"B314", "B318", "B320"}

    VULNERABLE_PATTERNS = [
        "import xml.etree.ElementTree as ET\nET.parse('data.xml')",
        "import xml.etree.ElementTree as ET\nET.fromstring(user_xml)",
    ]

    SAFE = "import defusedxml.ElementTree as ET\nET.parse('data.xml')"

    def test_semgrep_triggers(self):
        for code in self.VULNERABLE_PATTERNS:
            assert self.SEMGREP_RULE in semgrep_rule_ids(code)

    def test_bandit_triggers(self):
        found = bandit_test_ids(self.VULNERABLE_PATTERNS[0])
        assert found & self.BANDIT_RULES, f"Expected one of {self.BANDIT_RULES}, got {found}"

    def test_semgrep_finding_schema(self):
        results = semgrep_findings(self.VULNERABLE_PATTERNS[0])
        target = [f for f in results if f["rule_id"] == self.SEMGREP_RULE]
        assert target
        assert_semgrep_schema(target[0])


# ─────────────────────────────────────────────────────────────────────────────
# RULE 12: flask-debug-mode (Semgrep)
# ─────────────────────────────────────────────────────────────────────────────

class TestFlaskDebugMode:
    SEMGREP_RULE = "flask-debug-mode"

    VULNERABLE = "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)"
    SAFE = "from flask import Flask\napp = Flask(__name__)\napp.run(debug=False)"

    def test_semgrep_triggers(self):
        assert self.SEMGREP_RULE in semgrep_rule_ids(self.VULNERABLE)

    def test_safe_no_trigger(self):
        assert self.SEMGREP_RULE not in semgrep_rule_ids(self.SAFE)

    def test_semgrep_finding_schema(self):
        results = semgrep_findings(self.VULNERABLE)
        target = [f for f in results if f["rule_id"] == self.SEMGREP_RULE]
        assert target
        assert_semgrep_schema(target[0])


# ─────────────────────────────────────────────────────────────────────────────
# RULE 13: yaml-load-unsafe (Semgrep) + B506 (Bandit)
# ─────────────────────────────────────────────────────────────────────────────

class TestYAMLLoadUnsafe:
    SEMGREP_RULE = "yaml-load-unsafe"
    BANDIT_RULE = "B506"

    VULNERABLE = "import yaml\ndata = yaml.load(user_input)"
    SAFE_PATTERNS = [
        "import yaml\ndata = yaml.safe_load(user_input)",
        "import yaml\ndata = yaml.load(user_input, Loader=yaml.SafeLoader)",
    ]

    def test_semgrep_triggers(self):
        assert self.SEMGREP_RULE in semgrep_rule_ids(self.VULNERABLE)

    def test_bandit_triggers(self):
        assert self.BANDIT_RULE in bandit_test_ids(self.VULNERABLE)

    def test_safe_no_semgrep(self):
        for code in self.SAFE_PATTERNS:
            assert self.SEMGREP_RULE not in semgrep_rule_ids(code), (
                f"Expected '{self.SEMGREP_RULE}' NOT to fire on safe pattern:\n{code}"
            )

    def test_semgrep_finding_schema(self):
        results = semgrep_findings(self.VULNERABLE)
        target = [f for f in results if f["rule_id"] == self.SEMGREP_RULE]
        assert target
        assert_semgrep_schema(target[0])

    def test_bandit_finding_schema(self):
        results = bandit_findings(self.VULNERABLE)
        target = [f for f in results if f["rule_id"] == self.BANDIT_RULE]
        assert target
        assert_bandit_schema(target[0])


# ─────────────────────────────────────────────────────────────────────────────
# REMEDIATION COVERAGE
# Verifies every finding produced by either tool has a non-trivial remediation.
# Catches any new rule_id added to the rules YAML that's missing from REMEDIATION_MAP.
# ─────────────────────────────────────────────────────────────────────────────

class TestRemediationCoverage:
    """
    Runs a code sample that hits every rule in our YAML and confirms
    that remediation text is present and longer than 20 chars (not the
    empty string or a stub).
    """

    ALL_RULES_CODE = """
import pickle
import subprocess
import random
import yaml
import hashlib
import xml.etree.ElementTree as ET
from flask import Flask

password = "super_secret_123"
host = "192.168.1.1"

def load(data):
    return pickle.loads(data)

def run(cmd):
    return subprocess.run(cmd, shell=True)

def token():
    return random.randint(0, 999999)

def weak_hash(data):
    return hashlib.md5(data.encode())

def load_config(data):
    return yaml.load(data)

def parse_xml(s):
    return ET.fromstring(s)

def evaluate(expr):
    return eval(expr)

def check_admin(user):
    assert user.is_admin()

app = Flask(__name__)
app.run(host="0.0.0.0", debug=True)
"""

    def test_all_findings_have_remediation(self):
        sg = semgrep_findings(self.ALL_RULES_CODE)
        bd = bandit_findings(self.ALL_RULES_CODE)
        for finding in sg + bd:
            assert "remediation" in finding, (
                f"Finding missing 'remediation' key: {finding}"
            )
            assert len(finding["remediation"]) > 20, (
                f"Remediation too short for {finding['rule_id']}: '{finding['remediation']}'"
            )


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRATION TEST: scan() function
# ─────────────────────────────────────────────────────────────────────────────

class TestScanIntegration:
    """
    Tests the top-level scan() function with a code sample that intentionally
    violates multiple rules. Confirms findings JSON structure is correct.

    RULES_PATH is injected explicitly so the test works regardless of the
    directory pytest is invoked from.
    """

    MULTI_VULN_CODE = """
import pickle
import subprocess
import random
import yaml

# Rule 1: hardcoded-password
password = "hunter2"

# Rule 2: pickle-deserialization
def load_user(data):
    return pickle.loads(data)

# Rule 3: subprocess-shell-true
def run_cmd(cmd):
    return subprocess.run(cmd, shell=True)

# Rule 8: insecure-random
def generate_token():
    return random.randint(100000, 999999)

# Rule 13: yaml-load-unsafe
def load_config(data):
    return yaml.load(data)
"""

    def _scan(self):
        return scan(self.MULTI_VULN_CODE, "python", "integration-test-001", rules_path=RULES_PATH)

    def test_scan_returns_dict(self):
        assert isinstance(self._scan(), dict)

    def test_scan_has_required_keys(self):
        result = self._scan()
        for key in ["job_id", "language", "service", "total_findings", "findings", "rule_coverage"]:
            assert key in result, f"Missing top-level key: {key}"

    def test_scan_job_id_passthrough(self):
        result = self._scan()
        assert result["job_id"] == "integration-test-001"

    def test_scan_language_passthrough(self):
        result = self._scan()
        assert result["language"] == "python"

    def test_scan_service_name(self):
        result = self._scan()
        assert result["service"] == "sast-scanner"

    def test_scan_total_findings_matches_list(self):
        result = self._scan()
        assert result["total_findings"] == len(result["findings"])

    def test_scan_finds_multiple_issues(self):
        result = self._scan()
        # hardcoded-password, pickle-deserialization, subprocess-shell-true,
        # insecure-random, yaml-load-unsafe from Semgrep PLUS B105/B403/B301/
        # B404/B602/B311/B506 from Bandit — well over 5
        assert result["total_findings"] >= 5, (
            f"Expected ≥5 findings, got {result['total_findings']}"
        )

    def test_both_tools_represented(self):
        result = self._scan()
        tools = {f["tool"] for f in result["findings"]}
        assert "semgrep" in tools, "No semgrep findings in result"
        assert "bandit" in tools, "No bandit findings in result"

    def test_rule_coverage_block(self):
        result = self._scan()
        rc = result["rule_coverage"]
        assert rc["semgrep_rules_loaded"] is True
        assert rc["bandit_enabled"] is True
        assert rc["semgrep_rules_path"] != "NOT FOUND"

    def test_each_finding_has_remediation(self):
        result = self._scan()
        for finding in result["findings"]:
            assert "remediation" in finding, f"Finding missing remediation: {finding}"
            assert len(finding["remediation"]) > 20, (
                f"Remediation too short for rule {finding['rule_id']}: {finding['remediation']}"
            )

    def test_semgrep_finding_schema(self):
        result = self._scan()
        for finding in result["findings"]:
            if finding["tool"] == "semgrep":
                assert_semgrep_schema(finding)

    def test_bandit_finding_schema(self):
        result = self._scan()
        for finding in result["findings"]:
            if finding["tool"] == "bandit":
                assert_bandit_schema(finding)

    def test_non_python_skips_bandit(self):
        """scan() must not run bandit on non-Python languages."""
        result = scan(
            "const x = 1;",
            "javascript",
            "test-js-001",
            rules_path=RULES_PATH,
        )
        tools = {f["tool"] for f in result["findings"]}
        assert "bandit" not in tools, "Bandit should not run on JavaScript"
        assert result["rule_coverage"]["bandit_enabled"] is False


# ─────────────────────────────────────────────────────────────────────────────
# CLEAN CODE — zero findings
# ─────────────────────────────────────────────────────────────────────────────

class TestCleanCode:
    """
    Clean, idiomatic Python should produce zero findings from both tools.
    This is a regression guard: if a rule change causes a false positive on
    clean code, this class will catch it.
    """

    CLEAN_CODE = """
import os
import json
import hashlib
import secrets

def get_config():
    return {
        "db_host": os.environ["DB_HOST"],
        "password": os.environ["DB_PASSWORD"],
        "token": secrets.token_hex(32),
    }

def hash_data(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def load_data(raw_json: str) -> dict:
    return json.loads(raw_json)
"""

    def test_semgrep_no_findings(self):
        found = semgrep_rule_ids(self.CLEAN_CODE)
        assert not found, f"Unexpected semgrep findings on clean code: {found}"

    def test_bandit_no_high_severity(self):
        # Clean code should have no HIGH severity bandit findings.
        # B404 (import subprocess) is LOW and won't be present here anyway.
        results = bandit_findings(self.CLEAN_CODE)
        high = [f for f in results if f["severity"] == "HIGH"]
        assert not high, f"Unexpected HIGH bandit findings on clean code: {high}"

    def test_scan_zero_semgrep_findings(self):
        result = scan(self.CLEAN_CODE, "python", "test-clean-001", rules_path=RULES_PATH)
        semgrep = [f for f in result["findings"] if f["tool"] == "semgrep"]
        assert not semgrep, f"Unexpected semgrep findings on clean code: {semgrep}"


# ─────────────────────────────────────────────────────────────────────────────
# RABBITMQ MANUAL TEST PAYLOADS
# Print these to console for manual RabbitMQ UI testing.
# Run: python test_scanner.py --manual
# ─────────────────────────────────────────────────────────────────────────────

MANUAL_TEST_PAYLOADS = {
    "hardcoded_password": {
        "description": "Tests hardcoded-password Semgrep rule + B105/B106/B107 Bandit",
        "expected_rules": ["hardcoded-password", "B105"],
        "payload": {
            "job_id": "test-hardcoded-pw-001",
            "language": "python",
            "code": 'import os\npassword = "super_secret_123"\napi_key = "sk-abc123"\ntoken = "ghp_mytoken"\n'
        }
    },
    "pickle_and_subprocess": {
        "description": "Tests pickle-deserialization + subprocess-shell-true (Semgrep + Bandit)",
        "expected_rules": ["pickle-deserialization", "subprocess-shell-true", "B301", "B403", "B404", "B602"],
        "payload": {
            "job_id": "test-pickle-sub-001",
            "language": "python",
            "code": 'import pickle\nimport subprocess\n\ndef load_data(raw):\n    return pickle.loads(raw)\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n'
        }
    },
    "sql_injection": {
        "description": "Tests sql-injection-string-format (Semgrep) + B608 (Bandit)",
        "expected_rules": ["sql-injection-string-format", "B608"],
        "payload": {
            "job_id": "test-sqli-001",
            "language": "python",
            "code": 'def get_user(cursor, user_id):\n    query = "SELECT * FROM users WHERE id=" + user_id\n    cursor.execute(query)\n    return cursor.fetchone()\n'
        }
    },
    "weak_crypto": {
        "description": "Tests weak-hash-algorithm (Semgrep) + insecure-random (Semgrep + Bandit)",
        "expected_rules": ["weak-hash-algorithm", "insecure-random", "B303", "B311"],
        "payload": {
            "job_id": "test-crypto-001",
            "language": "python",
            "code": 'import hashlib\nimport random\n\ndef hash_password(password):\n    return hashlib.md5(password.encode()).hexdigest()\n\ndef generate_token():\n    return random.randint(100000, 999999)\n'
        }
    },
    "yaml_eval_xxe": {
        "description": "Tests yaml-load-unsafe + dangerous-eval + xxe-via-xml-parse",
        "expected_rules": ["yaml-load-unsafe", "dangerous-eval", "xxe-via-xml-parse", "B307", "B506", "B314"],
        "payload": {
            "job_id": "test-yaml-eval-xxe-001",
            "language": "python",
            "code": 'import yaml\nimport xml.etree.ElementTree as ET\n\ndef load_config(data):\n    return yaml.load(data)\n\ndef parse_xml(xml_data):\n    return ET.fromstring(xml_data)\n\ndef calculate(expr):\n    return eval(expr)\n'
        }
    },
    "clean_code": {
        "description": "Should produce ZERO semgrep findings and no HIGH bandit findings",
        "expected_rules": [],
        "payload": {
            "job_id": "test-clean-001",
            "language": "python",
            "code": 'import os\nimport json\nimport hashlib\nimport secrets\n\ndef get_config():\n    return {\n        "db_host": os.environ["DB_HOST"],\n        "password": os.environ["DB_PASSWORD"],\n        "token": secrets.token_hex(32),\n    }\n\ndef hash_data(data):\n    return hashlib.sha256(data.encode()).hexdigest()\n\ndef load_data(raw_json):\n    return json.loads(raw_json)\n'
        }
    },
}


if __name__ == "__main__":
    import sys
    import json

    if "--manual" in sys.argv:
        print("\n" + "=" * 70)
        print("RABBITMQ MANUAL TEST PAYLOADS")
        print("Paste each payload into: RabbitMQ UI → Queues → scan_jobs → Publish")
        print("Then check: docker compose logs -f scan-orchestrator")
        print("=" * 70)

        for name, test in MANUAL_TEST_PAYLOADS.items():
            print(f"\n{'─' * 60}")
            print(f"TEST: {name.upper()}")
            print(f"Description: {test['description']}")
            print(f"Expected rules: {test['expected_rules']}")
            print(f"\nPayload to paste into RabbitMQ UI:")
            print(json.dumps(test["payload"], indent=2))

        print(f"\n{'─' * 60}")
        print("VERIFICATION STEPS:")
        print("1. docker compose up -d")
        print("2. Open http://localhost:15672 (guest/guest)")
        print("3. Queues → scan_jobs → Publish message")
        print("4. Set 'Delivery mode' to Persistent")
        print("5. Paste payload JSON into 'Payload' field")
        print("6. Click 'Publish message'")
        print("7. docker compose logs -f sast-scanner      ← see findings count")
        print("8. docker compose logs -f scan-orchestrator ← see full findings JSON")
    else:
        print("Run tests with: pytest test_scanner.py -v")
        print("View manual payloads with: python test_scanner.py --manual")
