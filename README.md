# apparmorwho

Which AppArmor profile confines executable X — and which file:line
rule grants or denies PATH for operation OP under it?

`aa-status` lists loaded profiles and modes only. It never says which
file:line rule decides a given path, and never answers a hypothetical
("would this path be denied?") without running the program and reading
audit logs. `aa-logprof` learns from observed denials; it never answers
a static rule query over on-disk policy. grep finds rules but cannot
adjudicate them: a profile that both allows `/var/log/app/** w` and
denies `/var/log/app/*.key w`, with a `priority=100` allow elsewhere,
is decided by priority-then-deny-wins, not by which line grep printed
first. `apparmorwho` is a static model of AppArmor's documented rules
that answers both questions with file:line provenance.

## Usage

```
apparmorwho EXECUTABLE [--path PATH --op read|write|append|exec] [--root DIR]
apparmorwho --profile NAME [--path PATH --op OP] [--root DIR]
apparmorwho --list [--root DIR]
```

- `EXECUTABLE` must be an absolute path (AA03). `--path` requires
  `--op` and vice versa. Ops map to access letters: `read`→`r`,
  `write`→`w`, `append`→`a`, `exec`→the exec-transition family.
- `--root DIR` (default `/etc/apparmor.d`) is the policy tree and the
  base for `#include <magic/...>` includes. Only files directly under
  `--root` are scanned as profile files; subdirectories
  (`abstractions/`, `tunables/`, …) are reached only via includes.
- Without `--path`, the tool reports the selected profile (name,
  attachment, mode, defining file:line, hats/children, loaded state)
  and the attachment contest — the "why this profile won" section.
- `--profile NAME` bypasses attachment matching entirely (names:
  `parent//child` for children). Hats are list-only.
- Flags (who-family standard): `--json`, `--quiet` (suppresses
  findings, never the verdict), `--version`.
- Exit codes: 0 = verdict rendered (allow or deny) or `--list` with
  ≥1 profile; 1 = no profile attaches, attachment tie, selection
  UNKNOWN, verdict UNKNOWN, or empty `--list`; 2 = usage error or a
  fatal include/parse failure in the selected chain.

## Example

```
$ apparmorwho /usr/bin/myapp --path /var/log/myapp/a.key --op write
WOULD-DENY (on-disk policy)
profile myapp
  attachment: /usr/bin/myapp
  mode: enforce
  defined: /etc/apparmor.d/myapp:1
  loaded state: AppArmor unavailable
query: /var/log/myapp/a.key write (after alias rewriting)
evidence: denied by /etc/apparmor.d/myapp:3
deciding rule(s):
  /etc/apparmor.d/myapp:3 deny /var/log/myapp/*.key w
matching rules (pattern matches path):
  /etc/apparmor.d/myapp:2 /var/log/myapp/** rw [participates]
  /etc/apparmor.d/myapp:3 deny /var/log/myapp/*.key w [participates]
...
```

## How verdicts are decided

- **Attachment selection (AA01/AA02):** among attachments whose AARE
  pattern matches the executable, the longest literal left prefix
  (characters before the first `* ? [ {`) wins. An exact tie at the
  longest prefix means the exec would be denied → `NO-ATTACH (tie)`.
  Any matching xattr-conditional attachment makes selection
  `SELECTION-UNKNOWN`. Name-only profiles never attach.
- **Verdicts (AA05–AA08):** among rules whose expanded pattern matches
  the queried path (after alias rewriting) and that mention the op,
  the maximum `priority=` wins and lower-priority rules are shadowed
  (listed, never deciders); within the winning priority, deny beats
  allow; with no participating rule the profile default-denies
  (allowlists). `owner` rules are evaluated both ways (owner-holds /
  owner-not-holds): agreement is the verdict, disagreement is UNKNOWN
  — except owner-deny alone, which denies either way. `--op exec`
  treats any exec-transition token as granting exec and reports the
  transition(s) and any `-> target` verbatim, without following the
  transition (each hop is its own query).
- **Modes (AA09):** `enforce` as above; `complain` turns every verdict
  into WOULD-ALLOW (denials logged, not enforced); `kill` keeps deny
  verdicts with a "denial kills the process" note; `default_allow`
  flips the no-rule default to allow while deny rules still deny;
  `unconfined` always allows; `prompt` is always UNKNOWN.
- **Globs (AA04):** `*` (no `/`), `**` (any chars), `?`, `[abc]` /
  `[a-c]` / `[^a-c]` classes, `{a,b}` alternation. Patterns match
  verbatim: a trailing-slash pattern matches only directory queries,
  and vice versa, unless the pattern contains `**`.
- **Variables and aliases:** `@{NAME} =` / `+=` in preambles, recursive
  expansion, cross-product for multi-value variables (capped; over
  the cap is UNKNOWN if the profile is selected), `@{profile_name}`
  set to the profile name, unresolved variables in the selected
  profile → UNKNOWN. `alias OLD -> NEW,` rewrites the queried path
  by longest-prefix substitution (reported); rule patterns are never
  rewritten.
- **Includes (AA10/AA11/AA22):** `#include <magic>` resolves under
  `--root`; `#include "abs"` is absolute; `#include "rel"` resolves
  against the tool's CWD and is flagged (AA10) whenever followed.
  `if exists` makes a missing target a silent skip; a missing target
  or a cycle elsewhere is fatal if the profile would be selected
  (exit 2), a warning otherwise. A directory target expands to its
  entries in sorted order ([hypothesized], AA21). A magic include
  whose symlink resolution escapes `--root` is skipped (AA22);
  UNKNOWN if it is in the selected profile's chain.
- **Poison vs counted (AA13/AA23):** an unparseable line in the
  selected profile poisons its verdict to UNKNOWN. Recognized but
  unevaluated rule classes (capability, network, mount, dbus, signal,
  ptrace, unix, mqueue, rlimit, io_uring, userns, pivot_root, link,
  change_profile) are counted in the profile summary and never poison
  — real profiles are full of them. Every verdict covers file access
  only, and says so.

## Findings

| Code | Meaning |
|------|---------|
| AA00 | Name-only profile never attaches (info, on `--list`/selection) |
| AA01 | Attachment tie → exec denied (selection outcome, exit 1) |
| AA02 | Xattr-conditional attachment → selection UNKNOWN |
| AA03 | Non-absolute executable → exit 2 |
| AA04 | Directory queried without trailing slash (info) |
| AA05 | Shadowed lower-priority rules (info) |
| AA06 | Deciding deny/allow citation (the verdict evidence) |
| AA07 | Owner-condition UNKNOWN |
| AA08 | Exec transition report (transition + target, verbatim) |
| AA09 | Mode banner (complain / kill / default_allow / unconfined / prompt) |
| AA10 | CWD-dependent relative include followed (warning) |
| AA11 | Include failure (fatal if selected, warning otherwise) |
| AA12 | Coverage section (always present) |
| AA13 | Unparseable line → UNKNOWN if selected, warning otherwise |
| AA14 | Loaded-state section (always present, incl. unavailable) |
| AA15 | Duplicate profile name (first wins, warning) |
| AA16 | Variable assignment / alias inside profile body ignored (warning) |
| AA17 | Unknown profile flag (warning) |
| AA18 | Alias rewrite of the queried path (info) |
| AA19 | Unresolved variable in selected profile → UNKNOWN |
| AA20 | Variable cross-product cap exceeded → UNKNOWN if selected |
| AA21 | Directory-include expansion assumption (info, [hypothesized]) |
| AA22 | Symlink-escape include skipped (warning; UNKNOWN if selected) |
| AA23 | Non-file rules present but not evaluated (summary counts) |
| AA24 | `abi` line noted, not enforced (info, once per profile) |

## Limitations

- **Loaded vs on-disk — read the banner.** The kernel enforces what
  is LOADED, not what is on disk. Every run carries a loaded-state
  section (AA14) read from
  `/sys/kernel/security/apparmor/profiles` when present, and every
  verdict is labeled "on-disk policy". On a box without AppArmor the
  section reads "AppArmor unavailable" — which is the state of the
  build box, so no verdict here has ever been checked against a live
  kernel. A verdict is never a claim about what the kernel will do
  until the loaded state says the same profile, in the same mode, is
  loaded.
- **Not a validator.** The real `apparmor_parser` rejects a file with
  any error; apparmorwho degrades on purpose: unparseable
  non-selected profiles are skipped with warnings, and only the
  selected profile's unparseable lines poison verdicts (AA13). This
  keeps the tool useful on messy real trees (one broken profile must
  not blind it to the other ninety) at the cost of not being a parser
  substitute. `apparmor_parser -Q` remains the validation path, and
  any profile apparmorwho flags should be checked there before being
  trusted.
- **File access only.** Capability, network, mount, dbus, signal,
  ptrace, unix, mqueue, rlimit, io_uring, userns, pivot_root, link,
  and change_profile rules are counted, never evaluated (AA23).
  Link-rule `subset` semantics and `change_profile` transition
  following are out of scope, as are `l`/`k`/`m` verdicts (link/lock/
  mmap are future work, not silent approximations).
- **Static unknowns stay unknown.** `owner` is never resolved against
  a real uid (AA07), xattr-conditional attachments are never guessed
  (AA02), and `prompt`-mode outcomes are never predicted (AA09).
- **No live kernel on the build box.** No AppArmor is active where
  this was built, so every semantic claim is [documented],
  [docs-inferred], or [hypothesized] from the apparmor.d(5) man page
  (Ubuntu questing edition, focal cross-checked) — never [observed].
  Live-agreement tests against `aa-status` / sysfs are skip-guarded
  and skip on this box.
- **Never executes, never writes.** Pure text parsing, stdlib only,
  zero subprocesses in the tool. A planted `$(...)` payload in a
  comment, rule, or variable value is inert text (dedicated test).
  The tool never writes to `--root` and never runs anything from a
  profile.

## Pre-publish checklist

- [ ] Full test suite green under plain `python3`
      (`python3 test_apparmorwho.py`) — 64 pass + 2 skip-guarded live
      tests on a box without AppArmor.
- [ ] Dogfood: doccover + clicheck --strict clean (not yet run —
      see Build corrections in DESIGN-apparmorwho.md).
- [ ] Live agreement spot-check on a box with AppArmor loaded:
      `aa-status` / sysfs loaded-state agreement (currently skipped).
- [ ] Real-tree smoke test against a full `/etc/apparmor.d` tree
      (abstractions, tunables, local includes) — fixture trees only
      so far.
- [ ] Confirm the directory-include expansion assumption (AA21,
      [hypothesized]) against the man page or a real parser run.
- [ ] Confirm the symlink-escape guard's magic-only scope against a
      real tree (abs/rel includes are followed by design).
- [ ] Godsby's per-project publication approval (charter gate) —
      nothing is published without it.
