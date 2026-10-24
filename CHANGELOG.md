# CHANGELOG — apparmorwho

## 1.0.0 (2026-10-24)

Initial release. Static model of AppArmor's documented profile
selection and file-rule verdict rules: which profile confines
executable X, and which file:line rule grants or denies PATH for OP
under it (on-disk policy, with a loaded-state section on every run).

AA01 attachment selection (longest literal left prefix, exact tie →
NO-ATTACH/exec denied, name-only profiles never attach, child
attachments as parent//child); AA02 xattr-conditional attachments →
SELECTION-UNKNOWN; AA03 absolute-executable requirement (exit 2);
AA04 AARE globs (*, **, ?, classes with ^ negation, {a,b}
alternation, trailing-slash directory rule, verbatim matching); AA05
max-priority wins with shadowed listing; AA06 deny beats allow within
one priority, default-deny otherwise; AA07 owner evaluated both ways
(UNKNOWN on split, owner-deny-alone → DENY); AA08 exec transitions
reported verbatim with -> target, never followed; AA09 all six modes
(enforce/complain/kill/default_allow/unconfined/prompt); AA10
CWD-dependent relative includes flagged; AA11 include failures fatal
if the profile would be selected, warning otherwise; AA12 coverage on
every run; AA13 unparseable selected lines poison to UNKNOWN (also
surfaced as warnings when non-selected); AA14 loaded state from
sysfs, "AppArmor unavailable" when absent; AA15 duplicate names
(first wins); AA16 in-body assignments/aliases ignored; AA17 unknown
flags warned; AA18 alias rewriting by longest prefix; AA19 unresolved
variables → UNKNOWN; AA20 cross-product cap → UNKNOWN; AA21 directory
includes expand sorted [hypothesized]; AA22 magic-include symlink
escape skipped (UNKNOWN if selected); AA23 non-file rule classes
counted, never evaluated; AA24 abi lines noted, not enforced.
Exit 0/1/2; --json/--quiet/--version; --list with hats/children/
no-attachment marks; --profile bypass. Zero subprocesses, stdlib only,
read-only, hermetic fixture tests.

66 tests (stdlib unittest), 64 pass + 2 skip-guarded live tests
(aa-status / sysfs agreement, skipped: no AppArmor on the build box).
Zero-subprocess, no-third-party-import, and never-executes
($(...) payloads) properties are test-asserted.

Build corrections during v1 (see "Build corrections" in
DESIGN-apparmorwho.md): include-error profiles still compete for
selection (fatal only if such a profile would win); the symlink-escape
guard scoped to magic includes; tree-wide variable resolution
(last = wins); child names use the parent name as written; hat names
via --profile report NO-PROFILE (hats are list-only).
