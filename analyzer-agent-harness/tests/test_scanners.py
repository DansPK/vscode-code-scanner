import logging

from conftest import FIXTURE, needs_scanners
from harness.scanners import merge, runner, sonarqube
from harness.scanners.findings import make_finding

SECRETS = ["sk_live_51HxQz8Kd93kfJd8s7Hq2LmNpQ4rStUvWxYz012345", "AKIAZ7Q4XK3P9T2WLM5D"]


def _files(folder):
    return [str(p.relative_to(folder)) for p in folder.rglob("*") if p.is_file()]


@needs_scanners
async def test_planted_problems_found_and_secrets_masked(vuln_app, cfg, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    findings, errors = await runner.run_all(vuln_app, _files(vuln_app), "s1", cfg, tmp_path / "raw")
    assert "sonarqube" in errors  # no SonarQube here; the other tools still ran
    assert "semgrep" not in errors and "gitleaks" not in errors

    def has(path, cwe):
        return any(f["path"] == path and f["cwe"] == cwe for f in findings)

    assert has("config.py", "CWE-798")                # hard-coded API key
    assert has("db.py", "CWE-89")                     # SQL built from user input
    assert has("auth.py", "CWE-327")                  # MD5 for passwords
    assert has("tools.py", "CWE-78")                  # shell command from user input
    assert any("gitleaks" in f["tools"] for f in findings)
    assert len({f["id"] for f in findings}) == len(findings)
    assert (tmp_path / "raw" / "semgrep.json").exists() and (tmp_path / "raw" / "gitleaks.json").exists()

    blob = repr(findings) + caplog.text
    for secret in SECRETS:
        assert secret not in blob
    key = next(f for f in findings if f["path"] == "config.py" and "gitleaks" in f["tools"])
    assert "sk_l" in key["snippet"] and "****" in key["snippet"]


@needs_scanners
async def test_ids_stable_when_lines_move(vuln_app, cfg, tmp_path):
    files = _files(vuln_app)
    before, _ = await runner.run_all(vuln_app, files, "s1", cfg, tmp_path / "r1")
    p = vuln_app / "auth.py"
    p.write_text("\n\n\n" + p.read_text())
    after, _ = await runner.run_all(vuln_app, files, "s1", cfg, tmp_path / "r2")
    md5 = lambda fs: {f["id"] for f in fs if f["path"] == "auth.py"}
    assert md5(before) and md5(before) == md5(after)


def _f(tool, cwe, title="SQL injection", line=10, sev="medium", path="a.py"):
    f = make_finding(tool, f"{tool}.rule", title, sev, cwe, path, line, line, None, None, "m", "/nonexistent")
    return f


def test_merge_same_line_different_tools():
    out = merge.merge([_f("semgrep", "CWE-89", sev="medium"), _f("sonarqube", "CWE-89", sev="critical")])
    assert len(out) == 1
    assert out[0]["tools"] == ["semgrep", "sonarqube"]
    assert out[0]["severity"] == "critical"
    assert out[0]["rule_id"] == "semgrep.rule"


def test_merge_keeps_different_problems_apart():
    assert len(merge.merge([_f("semgrep", "CWE-89"), _f("sonarqube", "CWE-78")])) == 2
    assert len(merge.merge([_f("semgrep", "CWE-89"), _f("sonarqube", "CWE-89", line=30)])) == 2
    assert len(merge.merge([_f("semgrep", "CWE-89"), _f("sonarqube", "CWE-89", path="b.py")])) == 2
    # No CWE on either side: titles must be close
    assert len(merge.merge([_f("semgrep", None, "Weak hash MD5"), _f("sonarqube", None, "Weak hash md5")])) == 1
    assert len(merge.merge([_f("semgrep", None, "Weak hash MD5"), _f("sonarqube", None, "Open redirect")])) == 2


class FakeSonar:
    async def get(self, path, **params):
        assert path == "/api/rules/search" and params["facets"] == "cwe"
        return {"rules": [{"name": "SQL injection"}],
                "facets": [{"property": "cwe", "values": [{"val": "89", "count": 1}, {"val": "20", "count": 0}]}]}


async def test_sonar_mapping(vuln_app):
    key = sonarqube.project_key("s1")
    issues = [{"rule": "python:S3649", "severity": "BLOCKER", "component": f"{key}:db.py",
               "textRange": {"startLine": 14, "endLine": 14, "startOffset": 4, "endOffset": 60}, "message": "m"},
              {"rule": "x", "severity": "MAJOR", "component": key, "message": "project-level, no file"}]
    hotspots = [{"ruleKey": "python:S4790", "vulnerabilityProbability": "HIGH", "component": f"{key}:auth.py",
                 "textRange": {"startLine": 6, "endLine": 6}, "message": "hash"},
                {"ruleKey": "python:S4790", "vulnerabilityProbability": "LOW", "component": f"{key}:auth.py",
                 "textRange": {"startLine": 6, "endLine": 6}, "message": "hash"}]
    out = await sonarqube.to_findings(issues, hotspots, key, FakeSonar(), vuln_app)
    assert [f["severity"] for f in out] == ["critical", "high", "medium"]
    assert out[0]["path"] == "db.py" and out[0]["cwe"] == "CWE-89" and out[0]["start_col"] == 5


POLYGLOT = FIXTURE.parent / "polyglot_app"
LANGUAGE_FILES = ["py/views.py", "java/UserDao.java", "csharp/UserController.cs", "ts/server.ts",
                  "web/Profile.tsx", "web/Comment.jsx", "js/app.js", "go/main.go", "php/index.php",
                  "ruby/users_controller.rb", "kotlin/Repo.kt"]


@needs_scanners
async def test_every_language_gets_findings(cfg, tmp_path):
    import shutil
    code = tmp_path / "poly"
    shutil.copytree(POLYGLOT, code)
    findings, errors = await runner.run_all(code, LANGUAGE_FILES, "s1", cfg, tmp_path / "raw")
    assert "semgrep" not in errors
    found = {f["path"] for f in findings if "semgrep" in f["tools"]}
    assert found == set(LANGUAGE_FILES), set(LANGUAGE_FILES) - found


SQLI = FIXTURE.parent / "sqli_cases"
SQLI_VULNERABLE = ["java/A_JdbcConcat.java", "java/B_EntityManager.java", "java/C_StringFormat.java",
                   "java/D_CrossMethod.java", "ts/a_template.ts", "ts/b_sequelize.ts", "ts/c_prisma.ts",
                   "ts/e_crossfile_repo.ts"]
# ui/Ui.tsx: React className templates and UI text such as "Order by " + field are not SQL.
SQLI_SAFE = ["java/E_SafePrepared.java", "java/F_SpringQuery.java", "ts/d_safe.ts", "ts/e_crossfile_route.ts",
             "ui/Ui.tsx"]


@needs_scanners
async def test_sql_injection_detection(cfg, tmp_path):
    import shutil
    code = tmp_path / "sqli"
    shutil.copytree(SQLI, code)
    findings, _ = await runner.run_all(code, SQLI_VULNERABLE + SQLI_SAFE, "s1", cfg, tmp_path / "raw")
    sqli = [f for f in findings if f["cwe"] == "CWE-89"]
    assert {f["path"] for f in sqli} == set(SQLI_VULNERABLE)
    # One problem on one line is one finding, even when several rules matched it.
    lines = [(f["path"], f["start_line"]) for f in sqli]
    assert len(lines) == len(set(lines))


def test_merge_same_tool_same_line_same_cwe():
    out = merge.merge([_f("semgrep", "CWE-78", "Rule A", sev="medium"), _f("semgrep", "CWE-78", "Rule B", sev="high")])
    assert len(out) == 1 and out[0]["tools"] == ["semgrep"] and out[0]["severity"] == "high"
    assert len(merge.merge([_f("semgrep", "CWE-78"), _f("semgrep", "CWE-89")])) == 2
    assert len(merge.merge([_f("semgrep", None, "X"), _f("semgrep", None, "X")])) == 2  # no CWE: kept apart
