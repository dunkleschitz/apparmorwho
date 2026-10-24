#!/usr/bin/env python3
"""Tests for apparmorwho. Plain python3 + stdlib unittest (no pytest).

Every fixture policy tree lives under a temp dir passed via --root, so
tests are hermetic. Live-agreement tests are skip-guarded: they skip
when AppArmor sysfs is absent, which is the state of the build box.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "apparmorwho")


def run(args, cwd=None):
    return subprocess.run([sys.executable, TOOL] + args,
                          capture_output=True, text=True, cwd=cwd)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="apparmorwho-test-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def write(self, rel, content):
        path = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
        return path

    def q(self, *args, **kw):
        return run(list(args) + ["--root", self.dir], cwd=kw.get("cwd"))

    def verdict(self, exe, path, op, extra=()):
        r = self.q(exe, "--path", path, "--op", op, *extra)
        return r

    def assertVerdict(self, r, word, code=0):
        self.assertEqual(r.returncode, code, r.stdout + r.stderr)
        self.assertIn(word, r.stdout)


def prof(name, attach, body, flags=""):
    flag = (" " + flags) if flags else ""
    if attach is None:
        head = "profile %s%s {" % (name, flag)
    elif name == attach:
        head = "%s%s {" % (attach, flag)
    else:
        head = "profile %s %s%s {" % (name, attach, flag)
    return head + "\n" + body + "\n}\n"


class TestSelection(Fixture):
    def test_exact_attachment(self):
        self.write("a", prof("app", "/usr/bin/app", "  /x r,\n"))
        r = self.verdict("/usr/bin/app", "/x", "read")
        self.assertVerdict(r, "WOULD-ALLOW")

    def test_glob_attachment(self):
        self.write("a", prof("app", "/usr/bin/*", "  /x r,\n"))
        r = self.verdict("/usr/bin/thing", "/x", "read")
        self.assertVerdict(r, "WOULD-ALLOW")

    def test_longest_prefix_wins(self):
        self.write("a", prof("glob", "/usr/bin/*", "  /x r,\n"))
        self.write("b", prof("exact", "/usr/bin/foo", "  deny /x r,\n"))
        r = self.verdict("/usr/bin/foo", "/x", "read")
        self.assertVerdict(r, "WOULD-DENY")

    def test_tie_means_no_attach(self):
        self.write("a", prof("one", "/usr/bin/dup", "  /x r,\n"))
        self.write("b", prof("two", "/usr/bin/dup", "  /x r,\n"))
        r = self.q("/usr/bin/dup", "--path", "/x", "--op", "read")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("NO-ATTACH", r.stdout)
        self.assertIn("AA01", r.stdout)

    def test_name_only_never_attaches_but_profile_bypass_works(self):
        self.write("a", prof("loner", None, "  /x r,\n"))
        r = self.q("/usr/bin/anything", "--path", "/x", "--op", "read")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("NO-PROFILE", r.stdout)
        r = self.q("--profile", "loner", "--path", "/x", "--op", "read")
        self.assertVerdict(r, "WOULD-ALLOW")

    def test_child_attachment(self):
        body = "  profile kid /usr/bin/kid {\n    /x r,\n  }\n"
        self.write("a", prof("par", "/usr/bin/par", body))
        r = self.verdict("/usr/bin/kid", "/x", "read")
        self.assertVerdict(r, "WOULD-ALLOW")
        r = self.q("--list")
        self.assertIn("par//kid", r.stdout)

    def test_xattr_selection_unknown_and_profile_bypass(self):
        self.write("a", prof("x", "/usr/bin/xapp", "  /x r,\n",
                             flags="xattrs=(foo=bar)"))
        r = self.q("/usr/bin/xapp", "--path", "/x", "--op", "read")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("SELECTION-UNKNOWN", r.stdout)
        self.assertIn("AA02", r.stdout)
        r = self.q("--profile", "x", "--path", "/x", "--op", "read")
        self.assertVerdict(r, "WOULD-ALLOW")

    def test_non_absolute_executable_exit_2(self):
        self.write("a", prof("app", "/usr/bin/app", "  /x r,\n"))
        r = self.q("bin/app", "--path", "/x", "--op", "read")
        self.assertEqual(r.returncode, 2)
        self.assertIn("AA03", r.stderr)

    def test_no_profile(self):
        self.write("a", prof("app", "/usr/bin/app", "  /x r,\n"))
        r = self.q("/usr/bin/other", "--path", "/x", "--op", "read")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("NO-PROFILE", r.stdout)


class TestVerdicts(Fixture):
    def test_allow(self):
        self.write("a", prof("app", "/usr/bin/app", "  /data/f r,\n"))
        self.assertVerdict(self.verdict("/usr/bin/app", "/data/f", "read"), "WOULD-ALLOW")

    def test_deny_beats_allow_same_priority(self):
        body = "  /data/** rw,\n  deny /data/*.key w,\n"
        self.write("a", prof("app", "/usr/bin/app", body))
        self.assertVerdict(self.verdict("/usr/bin/app", "/data/a.key", "write"), "WOULD-DENY")

    def test_priority_high_allow_beats_low_deny(self):
        body = "  deny /data/** w,\n  priority=10 /data/pub/** w,\n"
        self.write("a", prof("app", "/usr/bin/app", body))
        self.assertVerdict(self.verdict("/usr/bin/app", "/data/pub/f", "write"), "WOULD-ALLOW")

    def test_priority_high_deny_beats_low_allow(self):
        body = "  /data/** w,\n  priority=10 deny /data/pub/** w,\n"
        self.write("a", prof("app", "/usr/bin/app", body))
        self.assertVerdict(self.verdict("/usr/bin/app", "/data/pub/f", "write"), "WOULD-DENY")

    def test_default_deny(self):
        self.write("a", prof("app", "/usr/bin/app", "  /other r,\n"))
        self.assertVerdict(self.verdict("/usr/bin/app", "/data/f", "read"), "WOULD-DENY")

    def test_owner_both_ways_unknown(self):
        self.write("a", prof("app", "/usr/bin/app", "  owner /home/u/** r,\n"))
        r = self.verdict("/usr/bin/app", "/home/u/f", "read")
        self.assertVerdict(r, "UNKNOWN", code=1)
        self.assertIn("AA07", r.stdout)

    def test_owner_deny_only_denies(self):
        self.write("a", prof("app", "/usr/bin/app", "  deny owner /home/u/** r,\n"))
        self.assertVerdict(self.verdict("/usr/bin/app", "/home/u/f", "read"), "WOULD-DENY")

    def test_complain_allows(self):
        self.write("a", prof("app", "/usr/bin/app", "  deny /x r,\n", flags="(complain)"))
        r = self.verdict("/usr/bin/app", "/x", "read")
        self.assertVerdict(r, "WOULD-ALLOW")
        self.assertIn("AA09", r.stdout)

    def test_default_allow_inversion(self):
        self.write("a", prof("app", "/usr/bin/app", "  deny /x r,\n  /y r,\n",
                             flags="(default_allow)"))
        self.assertVerdict(self.verdict("/usr/bin/app", "/z", "read"), "WOULD-ALLOW")
        self.assertVerdict(self.verdict("/usr/bin/app", "/x", "read"), "WOULD-DENY")

    def test_unconfined_allows(self):
        self.write("a", prof("app", "/usr/bin/app", "  deny /x r,\n", flags="(unconfined)"))
        self.assertVerdict(self.verdict("/usr/bin/app", "/x", "read"), "WOULD-ALLOW")

    def test_prompt_unknown(self):
        self.write("a", prof("app", "/usr/bin/app", "  /x r,\n", flags="(prompt)"))
        r = self.verdict("/usr/bin/app", "/x", "read")
        self.assertVerdict(r, "UNKNOWN", code=1)

    def test_kill_note(self):
        self.write("a", prof("app", "/usr/bin/app", "  deny /x r,\n", flags="(kill)"))
        r = self.verdict("/usr/bin/app", "/x", "read")
        self.assertVerdict(r, "WOULD-DENY")
        self.assertIn("kill mode", r.stdout)

    def test_shadowed_listed(self):
        body = "  deny /data/** w,\n  priority=10 /data/pub/** w,\n"
        self.write("a", prof("app", "/usr/bin/app", body))
        r = self.verdict("/usr/bin/app", "/data/pub/f", "write")
        self.assertIn("shadowed", r.stdout)
        self.assertIn("AA05", r.stdout)

    def test_qualifier_block(self):
        body = "  deny {\n    /x r,\n  }\n  /x w,\n"
        self.write("a", prof("app", "/usr/bin/app", body))
        self.assertVerdict(self.verdict("/usr/bin/app", "/x", "read"), "WOULD-DENY")
        self.assertVerdict(self.verdict("/usr/bin/app", "/x", "write"), "WOULD-ALLOW")

    def test_known_classes_counted_not_poisoning(self):
        body = "  capability sys_admin,\n  network inet stream,\n  mount,\n  /x r,\n"
        self.write("a", prof("app", "/usr/bin/app", body))
        r = self.verdict("/usr/bin/app", "/x", "read")
        self.assertVerdict(r, "WOULD-ALLOW")
        self.assertIn("AA23", r.stdout)

    def test_unparseable_selected_poisons(self):
        body = "  /x r,\n  this is not a rule,\n"
        self.write("a", prof("app", "/usr/bin/app", body))
        r = self.verdict("/usr/bin/app", "/x", "read")
        self.assertVerdict(r, "UNKNOWN", code=1)
        self.assertIn("AA13", r.stdout)

    def test_unparseable_nonselected_does_not_poison(self):
        self.write("a", prof("app", "/usr/bin/app", "  /x r,\n"))
        self.write("b", prof("bad", "/usr/bin/bad", "  nonsense here,\n"))
        r = self.verdict("/usr/bin/app", "/x", "read")
        self.assertVerdict(r, "WOULD-ALLOW")


class TestIncludes(Fixture):
    def test_magic_include(self):
        self.write("main", prof("app", "/usr/bin/app",
                                "  #include <abstractions/base>\n  /y r,\n"))
        self.write("abstractions/base", "  /x r,\n")
        self.assertVerdict(self.verdict("/usr/bin/app", "/x", "read"), "WOULD-ALLOW")

    def test_if_exists_missing_is_silent(self):
        self.write("a", prof("app", "/usr/bin/app",
                             "  #include if exists <abstractions/nope>\n  /x r,\n"))
        r = self.verdict("/usr/bin/app", "/x", "read")
        self.assertVerdict(r, "WOULD-ALLOW")
        self.assertNotIn("AA11", r.stdout)

    def test_missing_include_fatal_when_selected(self):
        self.write("a", prof("app", "/usr/bin/app",
                             "  #include <abstractions/nope>\n  /x r,\n"))
        r = self.verdict("/usr/bin/app", "/x", "read")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("AA11", r.stderr)

    def test_missing_include_nonselected_warns_only(self):
        self.write("a", prof("app", "/usr/bin/app", "  /x r,\n"))
        self.write("b", prof("bad", "/usr/bin/bad",
                             "  #include <abstractions/nope>\n  /x r,\n"))
        r = self.verdict("/usr/bin/app", "/x", "read")
        self.assertVerdict(r, "WOULD-ALLOW")
        self.assertIn("AA11", r.stdout)

    def test_quoted_abs_include(self):
        absfile = self.write("outside", "  /x r,\n")
        self.write("a", prof("app", "/usr/bin/app",
                             '  #include "%s"\n  /y r,\n' % absfile))
        self.assertVerdict(self.verdict("/usr/bin/app", "/x", "read"), "WOULD-ALLOW")

    def test_quoted_rel_include_cwd_finding(self):
        self.write("a", prof("app", "/usr/bin/app",
                             '  #include "relinc"\n  /y r,\n'))
        relinc = os.path.join(self.dir, "relinc")
        with open(relinc, "w") as fh:
            fh.write("  /x r,\n")
        r = run(["/usr/bin/app", "--path", "/x", "--op", "read",
                 "--root", self.dir], cwd=self.dir)
        self.assertVerdict(r, "WOULD-ALLOW")
        self.assertIn("AA10", r.stdout)

    def test_include_cycle_fatal(self):
        self.write("a", prof("app", "/usr/bin/app",
                             "  #include <a>\n  /x r,\n"))
        r = self.verdict("/usr/bin/app", "/x", "read")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_directory_include_sorted(self):
        self.write("a", prof("app", "/usr/bin/app",
                             "  #include <sub>\n  /y r,\n"))
        self.write("sub/b", "  /xb r,\n")
        self.write("sub/a", "  /xa r,\n")
        r = self.verdict("/usr/bin/app", "/xa", "read")
        self.assertVerdict(r, "WOULD-ALLOW")
        self.assertIn("AA21", r.stdout)
        self.assertLess(r.stdout.index("sub/a"), r.stdout.index("sub/b"))

    def test_symlink_escape_skipped_unknown(self):
        outside_dir = tempfile.mkdtemp(prefix="apparmorwho-outside-")
        self.addCleanup(shutil.rmtree, outside_dir, True)
        outside = os.path.join(outside_dir, "outside")
        with open(outside, "w") as fh:
            fh.write("  /x r,\n")
        os.makedirs(os.path.join(self.dir, "sub"), exist_ok=True)
        os.symlink(outside, os.path.join(self.dir, "sub", "link"))
        self.write("a", prof("app", "/usr/bin/app",
                             "  #include <sub/link>\n  /y r,\n"))
        r = self.verdict("/usr/bin/app", "/y", "read")
        self.assertVerdict(r, "UNKNOWN", code=1)
        self.assertIn("AA22", r.stdout)


class TestVariablesAliases(Fixture):
    def test_variable_equals(self):
        content = "@{DATA} = /srv/data\n" + prof("app", "/usr/bin/app", "  @{DATA}/** r,\n")
        self.write("a", content)
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/data/f", "read"), "WOULD-ALLOW")

    def test_variable_append(self):
        content = ("@{DATA} = /srv/a\n@{DATA} += /srv/b\n" +
                   prof("app", "/usr/bin/app", "  @{DATA}/f r,\n"))
        self.write("a", content)
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/b/f", "read"), "WOULD-ALLOW")

    def test_variable_multi_value(self):
        content = ("@{DIRS} = /srv/a /srv/b\n" +
                   prof("app", "/usr/bin/app", "  @{DIRS}/f r,\n"))
        self.write("a", content)
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/a/f", "read"), "WOULD-ALLOW")
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/b/f", "read"), "WOULD-ALLOW")

    def test_variable_recursive(self):
        content = ("@{BASE} = /srv\n@{DATA} = @{BASE}/data\n" +
                   prof("app", "/usr/bin/app", "  @{DATA}/f r,\n"))
        self.write("a", content)
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/data/f", "read"), "WOULD-ALLOW")

    def test_variable_unresolved_unknown(self):
        self.write("a", prof("app", "/usr/bin/app", "  @{NOPE}/f r,\n"))
        r = self.verdict("/usr/bin/app", "/x", "read")
        self.assertVerdict(r, "UNKNOWN", code=1)
        self.assertIn("AA19", r.stdout)

    def test_variable_profile_name(self):
        self.write("a", prof("/usr/bin/pn", "/usr/bin/pn", "  @{profile_name} r,\n"))
        self.assertVerdict(self.verdict("/usr/bin/pn", "/usr/bin/pn", "read"), "WOULD-ALLOW")

    def test_in_profile_assignment_ignored(self):
        body = "  @{IN} = /srv/in\n  @{IN}/f r,\n"
        self.write("a", prof("app", "/usr/bin/app", body))
        r = self.verdict("/usr/bin/app", "/srv/in/f", "read")
        self.assertIn("AA16", r.stdout)
        self.assertVerdict(r, "UNKNOWN", code=1)

    def test_alias_rewrite(self):
        content = ("alias /old -> /new,\n" +
                   prof("app", "/usr/bin/app", "  /new/f r,\n"))
        self.write("a", content)
        r = self.verdict("/usr/bin/app", "/old/f", "read")
        self.assertVerdict(r, "WOULD-ALLOW")
        self.assertIn("AA18", r.stdout)

    def test_alias_longest_prefix(self):
        content = ("alias /old -> /new,\n alias /old/sub -> /special,\n" +
                   prof("app", "/usr/bin/app", "  /special/f r,\n"))
        self.write("a", content)
        r = self.verdict("/usr/bin/app", "/old/sub/f", "read")
        self.assertVerdict(r, "WOULD-ALLOW")
        self.assertIn("/special/f", r.stdout)


class TestGlobsExec(Fixture):
    def test_star_no_slash(self):
        self.write("a", prof("app", "/usr/bin/app", "  /srv/* r,\n"))
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/f", "read"), "WOULD-ALLOW")
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/a/b", "read"), "WOULD-DENY")

    def test_double_star_crosses(self):
        self.write("a", prof("app", "/usr/bin/app", "  /srv/** r,\n"))
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/a/b/c", "read"), "WOULD-ALLOW")

    def test_question_mark(self):
        self.write("a", prof("app", "/usr/bin/app", "  /srv/f? r,\n"))
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/f1", "read"), "WOULD-ALLOW")
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/f12", "read"), "WOULD-DENY")

    def test_class_and_negation(self):
        self.write("a", prof("app", "/usr/bin/app", "  /srv/[a-c] r,\n  /srv/[^a-c] w,\n"))
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/b", "read"), "WOULD-ALLOW")
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/z", "write"), "WOULD-ALLOW")
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/b", "write"), "WOULD-DENY")

    def test_alternation(self):
        self.write("a", prof("app", "/usr/bin/app", "  /srv/{a,b}/f r,\n"))
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/a/f", "read"), "WOULD-ALLOW")
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/b/f", "read"), "WOULD-ALLOW")
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/c/f", "read"), "WOULD-DENY")

    def test_trailing_slash_dir_semantics(self):
        self.write("a", prof("app", "/usr/bin/app", "  /srv/data/ r,\n  /srv/any/** r,\n"))
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/data/", "read"), "WOULD-ALLOW")
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/data", "read"), "WOULD-DENY")
        self.assertVerdict(self.verdict("/usr/bin/app", "/srv/any/", "read"), "WOULD-ALLOW")

    def test_exec_transition_report(self):
        self.write("a", prof("app", "/usr/bin/app", "  /usr/bin/helper ix,\n"))
        r = self.verdict("/usr/bin/app", "/usr/bin/helper", "exec")
        self.assertVerdict(r, "WOULD-ALLOW")
        self.assertIn("ix", r.stdout)
        self.assertIn("AA08", r.stdout)

    def test_exec_deny_x(self):
        self.write("a", prof("app", "/usr/bin/app", "  deny /usr/bin/bad x,\n"))
        self.assertVerdict(self.verdict("/usr/bin/app", "/usr/bin/bad", "exec"), "WOULD-DENY")

    def test_exec_target_reported(self):
        self.write("a", prof("app", "/usr/bin/app", "  /usr/bin/y Cx -> child,\n"))
        r = self.verdict("/usr/bin/app", "/usr/bin/y", "exec")
        self.assertVerdict(r, "WOULD-ALLOW")
        self.assertIn("child", r.stdout)


class TestOutput(Fixture):
    def test_list_marks(self):
        body = "  profile kid /usr/bin/kid {\n    /x r,\n  }\n  hat myhat {\n    /s r,\n  }\n"
        self.write("a", prof("par", "/usr/bin/par", body))
        self.write("b", prof("loner", None, "  /x r,\n"))
        r = self.q("--list")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("no-attachment", r.stdout)
        self.assertIn("par//kid", r.stdout)
        self.assertIn("hat myhat", r.stdout)

    def test_list_empty_exit_1(self):
        r = self.q("--list")
        self.assertEqual(r.returncode, 1)

    def test_coverage_section(self):
        self.write("a", prof("app", "/usr/bin/app", "  /x r,\n"))
        r = self.verdict("/usr/bin/app", "/x", "read")
        self.assertIn("coverage (AA12)", r.stdout)
        self.assertIn("profile files read: 1", r.stdout)
        self.assertIn("loaded state (AA14)", r.stdout)
        self.assertIn("AppArmor unavailable", r.stdout)

    def test_json_fidelity(self):
        self.write("a", prof("app", "/usr/bin/app", "  /x r,\n"))
        r = self.q("/usr/bin/app", "--path", "/x", "--op", "read", "--json")
        data = json.loads(r.stdout)
        self.assertEqual(data["verdict"], "WOULD-ALLOW")
        self.assertEqual(data["profile"]["name"], "app")
        self.assertIn("findings", data)
        self.assertIn("coverage", data)
        self.assertIn("loaded_state", data)

    def test_quiet_suppresses_findings_not_verdict(self):
        self.write("a", prof("app", "/usr/bin/app", "  deny /x r,\n", flags="(complain)"))
        r = self.q("/usr/bin/app", "--path", "/x", "--op", "read", "--quiet")
        self.assertIn("WOULD-ALLOW", r.stdout)
        self.assertNotIn("findings:", r.stdout)

    def test_version(self):
        r = run(["--version"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("1.0.0", r.stdout)

    def test_path_without_op_exit_2(self):
        self.write("a", prof("app", "/usr/bin/app", "  /x r,\n"))
        r = self.q("/usr/bin/app", "--path", "/x")
        self.assertEqual(r.returncode, 2)

    def test_no_path_reports_profile_and_contest(self):
        self.write("a", prof("glob", "/usr/bin/*", "  /x r,\n"))
        self.write("b", prof("exact", "/usr/bin/foo", "  /x r,\n"))
        r = self.q("/usr/bin/foo")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("exact", r.stdout)
        self.assertIn("attachment contest", r.stdout)

    def test_never_executes(self):
        marker = os.path.join(self.dir, "MARKER")
        payload = "$(touch %s)" % marker
        content = ("# %s\n@{EVIL} = %s\n" %
                   (payload, payload) +
                   prof("app", "/usr/bin/app",
                        "  @{EVIL} r,\n  /x r,\n"))
        self.write("a", content)
        r = self.verdict("/usr/bin/app", "/x", "read")
        self.assertVerdict(r, "WOULD-ALLOW")
        self.assertFalse(os.path.exists(marker))

    def test_no_subprocess_in_tool(self):
        with open(TOOL) as fh:
            src = fh.read()
        self.assertNotIn("import subprocess", src)
        self.assertNotIn("os.system", src)
        self.assertNotIn("Popen", src)
        self.assertNotIn("os.popen", src)
        self.assertNotIn("os.exec", src)

    def test_no_third_party_imports(self):
        import ast
        with open(TOOL) as fh:
            tree = ast.parse(fh.read())
        stdlib = {"argparse", "json", "os", "re", "shlex", "sys"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], stdlib, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], stdlib, node.module)


class TestLiveSkipped(unittest.TestCase):
    def test_aa_status_agreement(self):
        if os.path.exists("/sys/kernel/security/apparmor/profiles"):
            self.fail("AppArmor present; live agreement test not implemented for this box")
        self.skipTest("AppArmor sysfs absent on this box")

    def test_sysfs_loaded_state_agreement(self):
        if os.path.exists("/sys/kernel/security/apparmor/profiles"):
            self.fail("AppArmor present; live agreement test not implemented for this box")
        self.skipTest("AppArmor sysfs absent on this box")


if __name__ == "__main__":
    unittest.main(verbosity=2)
