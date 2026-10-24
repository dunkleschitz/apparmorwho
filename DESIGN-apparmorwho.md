# apparmorwho — hazard-first design review

**Status:** BUILD APPROVED (2026-10-24).
**Question:** which AppArmor profile confines executable X — and which
file:line rule grants or denies PATH for operation OP under it?
**Shape:** `apparmorwho EXECUTABLE [--path PATH --op read|write|append|exec]`
/ `apparmorwho --profile NAME [--path PATH --op OP]`
/ `apparmorwho --list` over an AppArmor policy tree
(`--root DIR`, default `/etc/apparmor.d`).
Flags (who-family standard): `--json`, `--quiet`, `--version`.
**Pinned from:** the apparmor.d(5) man page, Ubuntu questing edition
(read 2026-10-24; the focal edition cross-checked for the stable
subset), plus the dokk.org mirror for the attachment "best match"
prose. No AppArmor is active on this box (no
`/sys/kernel/security/apparmor`, no `apparmor_parser` binary) and no
live experiments were run, so every claim below is `[documented]`
(man page), `[docs-inferred]` (follows from a documented rule), or
`[hypothesized]` (best-supported guess, flippable) — never
`[observed]`. Live-agreement tests in the build are skip-guarded
(compare against `aa-status` / `/sys/.../profiles` output only when
AppArmor is present; on this box they skip).
Claims are tagged throughout. A claim that turns out wrong must flip
the design, not get quietly absorbed.

## Thinness verdict: APPROVED, and the native tools stop at inventory

The obvious "native holder" objections, and why each stops short:

1. **`aa-status` lists loaded profiles and their modes only**
   [documented]. It never says which file:line rule decides a given
   path, and never answers a hypothetical ("would this path be
   denied?") without running the program and reading audit logs.
2. **`aa-logprof` / `aa-genprof` are log/interactive-driven**
   [documented]. They learn rules from observed denials; they never
   answer a static rule query over on-disk policy.
3. **`apparmor_parser --debug` dumps compiled policy, not provenance.**
   Even where a parser exists, the compiled DFA has no file:line
   back-pointer to the rule a human wrote, and no verdict query.
4. **grep finds rules but cannot adjudicate them.** A profile that
   both allows `/var/log/app/** w` and denies `/var/log/app/*.key w`,
   with a `priority=100` allow elsewhere, is decided by AA01–AA03
   below — not by which line grep printed first. Rule order does not
   matter [documented: "the order of rules within a given section or
   block does not matter"].

## Pinned semantics

### Profiles, names, attachments

- A profile file holds a preamble (comments, variable assignments,
  alias rules, includes, abi lines) followed by profile definitions
  [documented]. The preamble must be at the head of the file; once
  profile definitions begin, no more preamble rules are allowed, even
  in files included into the profile [documented]. Consequence: a
  variable assignment inside a profile body is invalid — v1 reports
  it as a warning finding and ignores it (it never silently applies).
- Profile head forms [documented]: bare `/path { ... }` (name =
  attachment = the path); `profile NAME { ... }` (name only, NO
  attachment — usable only via an explicit transition such as
  `px -> NAME`, never attachable by exec); `profile NAME ATTACHMENT
  { ... }` (name + attachment). **AA00:** name-only profiles never
  match an executable query; `--list` marks them `no-attachment`.
- Flags [documented]: `flags=(...)` or bare `(...)` after the head.
  Modes: `enforce` (default when no mode is given), `complain`,
  `kill`, `default_allow`, `unconfined`, `prompt`, plus `audit` and
  non-mode flags (`mediate_deleted`, `attach_disconnected`,
  `chroot_relative`, `debug`, `interruptible`, `kill.signal=`,
  `error=`). Unknown flags → warning finding, never fatal.
- Child profiles (`profile NAME { ... }` nested in a profile) and
  hats (`hat NAME { ... }` / `^NAME { ... }`) [documented]. Child
  profiles are separately selectable when they carry their own
  attachment; their full name is rendered `parent//child`
  [docs-inferred from the kernel's `//` naming as shown by
  `aa-status` output]. Hats have no attachment and are entered only
  via `change_hat` — v1 parses and lists them, never selects them
  by executable query.
- Multiple profiles per file are allowed [documented]; v1 parses all
  of them. Duplicate profile names → finding, first wins
  [docs-inferred; the real parser rejects duplicates, but v1 is a
  query tool, not a validator — see "Not a validator" below].

### Attachment selection (which profile confines EXECUTABLE)

- The kernel picks "the profile with the set of attachments that
  result in the best match" after a transition, using a "longest left
  match heuristic" for exec attachment conditionals; "if the
  heuristic can not determine a winner between multiple matches the
  exec will be denied" [documented]. **AA01:** v1 ranks matching
  attachments by longest literal left prefix (characters before the
  first AARE metacharacter `* ? [ {`); the strictly longest wins.
  An exact tie at the longest prefix → selection outcome NO-ATTACH
  (tie → exec denied [documented]), reported as a finding, exit 1
  — this is a precise outcome, not UNKNOWN: no profile confines the
  exec because the exec would fail.
- Attachments may carry xattr conditionals (`xattrs=(...)`)
  [documented]. Static evaluation cannot know xattr values, so
  **AA02:** any matching xattr-conditional candidate makes
  selection UNKNOWN (finding lists it) unless the query bypasses
  selection via `--profile`. Xattr profiles are rare; poisoning is
  preferable to a false attach.
- **AA03:** the executable query must be an absolute path (else
  exit 2). Attachment specs are absolute paths; resolving a bare
  name through the caller's PATH would answer a different process's
  question. `--profile NAME` bypasses attachment matching entirely
  (names: `parent//child` for children, hats addressable for
  `--list` display only).

### File-rule matching (AARE globs)

- Glob operators [documented]: `*` = any chars except `/`; `**` =
  any chars including `/`; `?` = one char except `/`; `[abc]` /
  `[a-c]` / `[^a-c]` = one-char classes (`^` negates, not `!`);
  `{a,b}` = alternation expanding to one rule per alternative.
- **AA04:** patterns match the queried string verbatim. A pattern
  ending in `/` matches only a directory query (queried path ending
  in `/`); a pattern without a trailing slash matches a file query.
  `**` matches both, since `.*` consumes the slash. The tool does
  NOT normalize the query: if `--path` names a directory on disk
  but is given without a trailing slash, an info finding says so
  ("queried as a file; append `/` for directory semantics").
- Variables (`@{NAME}`) expand before matching [documented]:
  assignments `@{NAME} = v1 v2...` and appends `@{NAME} += ...`
  in the preamble; values may themselves contain variables
  (recursive expansion, depth-capped, cycle → warning). A
  multi-value variable in a pattern expands to one rule per value;
  several variables in one pattern expand to the cross product
  (bounded: over a cap, the rule is dropped with a warning and the
  verdict goes UNKNOWN if the profile is selected). `@{profile_name}`
  is set to the profile name [documented]. An unresolved variable
  in the selected profile → verdict UNKNOWN (finding names the
  variable). No invented defaults: if a profile uses `@{HOME}`
  without any definition on the include chain, that is UNKNOWN, not
  a guessed `/home/*`.
- Alias rules (`alias OLD -> NEW,` in the preamble, applied after
  variable resolution [documented]) rewrite the queried path by
  longest-prefix substitution before matching; the rewrite is
  reported as a finding. Rule patterns are not rewritten.
- File-rule surface forms [documented]: qualifiers, optional
  `owner`, optional `file` keyword, then pattern+access in either
  order, optional `->` exec target, trailing comma:
  `/path r,`, `r /path,`, `file /path r,`, `owner /path r,`,
  `deny /path r,`, `priority=5 /path r,`, `/bin/x ix,`,
  `/bin/y Cx -> child,`. Access letters: `r w a l k m` plus exec
  transitions `ix ux Ux px Px cx Cx pix Pix cix Cix pux PUx cux
  CUx` and bare `x` (bare `x` is allowed only in deny rules
  [documented]; an allow rule with bare `x` is unparseable → see
  "Not a validator"). Combined letters (`rmix`) parse as a set.
- Qualifier blocks [documented] (`audit { ... }`, `deny { ... }`,
  `priority=10 { ... }`) apply their qualifiers to every rule in
  the block, including nested blocks (innermost wins on conflict;
  `allow` vs `deny` in the same chain is a parse warning).

### The verdict algorithm (the heart of the tool)

For a queried op under the selected profile, in enforce mode:

1. Collect file rules whose expanded pattern matches the queried
   path (after alias rewriting). Rules not mentioning the queried
   op at all do not participate (a rule `/x r,` neither grants nor
   denies a write query).
2. **AA05 — priority first.** Among participating rules, take the
   maximum priority (`priority=N`, default 0, range -1000..1000
   [documented]). Rules below that priority are shadowed for this
   query (listed as shadowed, never as deciders). "Higher priority
   completely overrides lower priority within the overlap"
   [documented].
3. **AA06 — deny beats allow within one priority level.** At the
   winning priority, if any participating rule is a deny for the op
   → WOULD-DENY, citing the denying rule(s). Else if any is an
   allow → WOULD-ALLOW, citing the allowing rule(s). Else (no
   participating rule) → WOULD-DENY by default: profiles are
   allowlists [documented: rules "provide a whitelist of different
   permission that are allowed"], evidence "no rule grants <op>".
   This is why the priority feature exists at all: without it there
   is no way to carve an exception out of a deny, so deny-wins is
   the only consistent reading of the pre-priority semantics, and
   the priority prose confirms the layering.
4. **AA07 — owner is evaluated both ways.** An `owner` rule applies
   only when the task's euid/fsuid equals the object's owner
   [documented] — runtime state a static tool cannot know for the
   confined process. Evaluate the verdict twice (owner-holds /
   owner-not-holds); if both agree, that is the verdict; if they
   differ, verdict UNKNOWN with an owner-condition finding. Note
   the asymmetry this yields honestly: owner-deny alone →
   WOULD-DENY either way (default-deny covers the not-holds case),
   while owner-allow alone → UNKNOWN.
5. **AA08 — exec op.** `--op exec` treats any exec-transition token
   as granting exec; the verdict names the transition(s) of the
   winning allow rule (`ix`/`px`/…), and `deny x` denies. The
   `-> target` is reported verbatim when present. No transition
   simulation: `px` vs `ix` consequences (which profile the child
   lands in) are reported, not followed — following them is a
   separate query (`apparmorwho <target>`, or `--profile`).

### Profile modes rewrite the verdict (AA09)

- `enforce` (or no mode): AA05–AA08 as written.
- `complain`: every verdict becomes WOULD-ALLOW with a complain
  banner (denials are logged, not enforced [documented]). Never a
  WOULD-DENY from a complain-mode profile.
- `kill`: deny verdicts stand, annotated "denial kills the
  process" (mode note, not a different verdict).
- `default_allow`: the default flips — no participating rule →
  WOULD-ALLOW; deny rules still deny. Bannered on every verdict.
- `unconfined`: WOULD-ALLOW always, bannered.
- `prompt`: verdict UNKNOWN (the outcome depends on an interactive
  prompt at runtime [docs-inferred]).

### Includes, tunables, and the coverage contract

- Include forms [documented]: `#include <magic/path>` (relative to
  the apparmor.d root, i.e. `--root`), `#include "abs/path"`
  (absolute), `#include "rel/path"` (relative to the parser's
  current working directory — **AA10:** v1 resolves these against
  the tool's CWD and emits a CWD-dependence finding whenever one is
  followed, because the answer then depends on where the tool was
  invoked). The leading `#` is optional (`include ...` works).
  `if exists` makes a missing target a silent skip [documented];
  without it, a missing target is a parser error.
- **AA11 — include failure handling.** A missing non-conditional
  include, an include cycle, or an unreadable file in the selected
  profile's chain → fatal for that query (exit 2). In a
  non-selected profile → warning finding, profile skipped. A
  directory as an include target expands to its entries in sorted
  order [hypothesized — the man page's "file or directory" phrasing
  for `if exists` implies directories are includable; the builder
  must flag the expansion assumption in a finding and keep it
  lexical-sorted].
- Symlink escape: an include resolving outside `--root` via a
  symlink is SKIPPED with a finding (fixture-root guard, apachewho
  precedent). If the skipped include is in the selected profile's
  chain → verdict UNKNOWN (a missing rule set can flip either
  direction). Real trees do not do this; hermetic correctness wins.
- **AA12 — coverage on every run.** Output always lists: profile
  files read, files skipped (unparseable profile files are skipped
  with warnings, never fatal to other profiles), includes followed,
  includes skipped, and warnings. A verdict over a partially-read
  selected profile is never presented as complete.
- **AA13 — unparseable lines poison selected verdicts.** A line in
  the selected profile that matches no known rule shape →
  UNKNOWN verdict (finding cites file:line), because an
  unrecognized file rule could decide the query either way.
  Recognized-but-unevaluated rule classes (capability, network,
  mount, pivot_root, unix, dbus, signal, ptrace, mqueue, rlimit,
  io_uring, userns, link, change_profile) are parsed-or-skipped
  cleanly, counted in the profile summary, and do NOT poison
  verdicts — otherwise real profiles (which are full of them)
  would make the tool useless. The output banners that the verdict
  covers file access only. This distinction is the single most
  important implementation detail: the "known class" recognizer
  must be generous (first token after qualifiers in the known set
  → skip to the terminating comma), and the file-rule parser must
  be strict.

### Loaded vs on-disk (the headline honesty banner)

- The kernel enforces what is LOADED, not what is on disk; a
  profile file is not the loaded policy (the loaded-vs-disk
  divergence is the whole reason this tool's verdicts are
  three-valued in spirit). **AA14:** every run carries a loaded-state
  section when readable: `/sys/kernel/security/apparmor/profiles`
  gives loaded names + modes (best effort, read-only). States:
  `loaded (mode matches)`, `loaded (mode differs: on-disk X,
  loaded Y)`, `not loaded`, or `AppArmor unavailable` (no sysfs
  node — the state on this box). A verdict is ALWAYS labeled
  "on-disk policy" and the banner states plainly whether the
  profile is loaded. Never claim disk == enforced.
- No subprocesses, ever: pure text parsing (apparmorwho precedent
  family rule). No invoking `apparmor_parser`, `aa-status`, or
  anything else — a planted `$(...)` payload in a profile comment
  or rule must be inert text. Dedicated never-executes test.

## Findings (AA-series; the tool's real output vocabulary)

- AA00 name-only profile never attaches (info, on `--list`/selection).
- AA01 attachment tie → exec denied (selection outcome, exit 1).
- AA02 xattr-conditional attachment → selection UNKNOWN.
- AA03 non-absolute executable → exit 2 (usage, with the reason).
- AA04 trailing-slash / directory-query info note.
- AA05 shadowed lower-priority rules (info, listed with file:line).
- AA06 deciding deny/allow citation (the verdict evidence itself).
- AA07 owner-condition UNKNOWN.
- AA08 exec transition report (transition + target, verbatim).
- AA09 mode banner (complain / kill / default_allow / unconfined /
  prompt) on every verdict from such a profile.
- AA10 CWD-dependent relative include followed (warning).
- AA11 include failure (fatal if selected, warning otherwise).
- AA12 coverage section (always present).
- AA13 unparseable line in selected profile → UNKNOWN.
- AA14 loaded-state section (always present, incl. unavailable).
- AA15 duplicate profile name (first wins, warning).
- AA16 variable assignment inside profile body ignored (warning).
- AA17 unknown profile flag (warning).
- AA18 alias rewrite of the queried path (info).
- AA19 unresolved variable in selected profile → UNKNOWN.
- AA20 variable cross-product cap exceeded → UNKNOWN if selected.
- AA21 directory-include expansion assumption (info, [hypothesized]).
- AA22 symlink-escape include skipped (warning; UNKNOWN if selected).
- AA23 link / change_profile / non-file rules present but not
  evaluated (summary counts + file-access-only banner).
- AA24 `abi` line noted, not enforced (info, once per profile).

## CLI shape (v1)

```
apparmorwho EXECUTABLE [--path PATH --op OP] [--root DIR]
apparmorwho --profile NAME [--path PATH --op OP] [--root DIR]
apparmorwho --list [--root DIR]
```

- `EXECUTABLE`: absolute path (AA03). `--path` requires `--op` and
  vice versa (exit 2 otherwise). `--op` in {read, write, append,
  exec}; `read`→`r`, `write`→`w`, `append`→`a`, `exec`→x-family.
  (`l`/`k`/`m` are not v1 ops: link/lock/mmap verdicts are future
  work, not silent approximations.)
- `--root DIR` (default `/etc/apparmor.d`): the policy tree AND the
  magic-include base. Scanning reads every regular file directly
  under `--root` as a candidate profile file; subdirectories
  (`abstractions/`, `tunables/`, `local/`, …) are reached only via
  the include chain, never scanned as profiles.
- Without `--path`: report the selected profile (name, attachment,
  mode, defining file:line, hats/children, loaded state) and the
  attachment contest (other matching profiles, if any, with their
  literal-prefix lengths — the "why this profile won" section).
- Exit codes: 0 = verdict rendered (allow or deny) or `--list`
  with ≥1 profile; 1 = no profile attaches, selection tie (AA01),
  selection UNKNOWN (AA02), verdict UNKNOWN, or `--list` empty;
  2 = usage error or fatal include/parse failure in the selected
  chain. `--json` renders the same verdict + findings + coverage
  machine-readably; `--quiet` suppresses findings, never the verdict.
- Output order (text mode): verdict line first, deciding rule(s)
  with file:line, matching-rules list, shadowed list, findings,
  coverage, loaded-state section. Verdict vocabulary (exact):
  `WOULD-ALLOW`, `WOULD-DENY`, `UNKNOWN`, plus selection outcomes
  `NO-PROFILE`, `NO-ATTACH (tie)`, `SELECTION-UNKNOWN`.

## Out of scope (bannered, never silently modeled)

- Capability / network / mount / dbus / signal / ptrace / unix /
  mqueue / rlimit / io_uring / userns / pivot_root verdicts (counted,
  not evaluated — AA23).
- Link-rule verdicts (`link ... -> ...` with `subset` semantics)
  and `change_profile` transition following (AA23/AA08).
- `owner` resolution against a real uid (AA07 covers it honestly).
- xattr-conditional attachments (AA02).
- The `file` keyword's `owner` + `audit` + `priority` interplay
  beyond the qualifier-stack rule above (builder: any qualifier
  combination not in the BNF → unparseable line, AA13).
- Validating policy (the real parser remains the validator — see
  below); evaluating profiles that fail to parse (AA13).
- Following exec transitions across profiles (`px`/`cx` chains):
  each hop is its own query.

## Not a validator (deliberate divergence, documented)

The real `apparmor_parser` rejects a file with any error; apparmorwho
degrades: unparseable non-selected profiles are skipped with
warnings, and only the selected profile's unparseable lines poison
verdicts (AA13). This keeps the tool useful on messy real trees
(one broken profile must not blind it to the other ninety) at the
cost of not being a parser substitute. The README must say this in
one paragraph, and must say that `apparmor_parser -Q` remains the
validation path.

## Hazards reviewed (why this design is safe to build)

1. **False "allowed" is the catastrophic failure.** Every
   uncertainty that could flip a verdict in either direction lands
   on UNKNOWN, never on a guessed allow: unresolved variables
   (AA19), unparseable selected lines (AA13), skipped selected
   includes (AA11/AA22), owner splits (AA07), xattr attachments
   (AA02), prompt mode (AA09). The only UNKNOWN-avoiding asymmetry
   is owner-deny-alone → DENY, which holds under both evaluations
   and is therefore sound, not a guess.
2. **Loaded ≠ on-disk.** AA14 + the on-disk banner on every
   verdict. A user who reads "WOULD-DENY" without the banner could
   conclude the system is safe; the banner prevents exactly that.
3. **Priority is new; old profiles don't use it.** Default 0 keeps
   old profiles correct, and the builder must test both directions
   of the override (high allow beats low deny; high deny beats low
   allow) — the second direction is the one a naive "deny always
   wins" implementation would get wrong.
4. **Complain/default_allow/unconfined invert naive readings.**
   AA09 handles all six modes; a builder that only special-cased
   complain would report false denies for default_allow trees.
5. **CWD-dependent includes (AA10) and symlink escape (AA22)** are
   the two ways a static answer silently depends on the
   invocation environment. Both are findings, not footnotes.
6. **Glob translation bugs are verdict bugs.** `**` vs `*`,
   `[^...]` negation, `{a,b}` expansion, and the trailing-slash
   rule (AA04) each get dedicated tests; the regex translator is
   the most-tested unit in the build.
7. **Never executes (family rule).** Pure parsing, no subprocess;
   dedicated never-executes test with `$(touch marker)` payloads
   in comments, rule patterns, and variable values.
8. **Partial answers never presented as complete (AA12).** Coverage
   on every run, including which profile files failed to parse.

## Test plan (hermetic fixture `--root` trees; stdlib-only runner)

~45–55 tests, plain `python3` (no pytest — the aptpinswho lesson):
attachment selection (exact, glob, longest-prefix, tie→NO-ATTACH,
name-only never attaches, child attachment, xattr→UNKNOWN);
verdicts (allow, deny-beats-allow, priority both directions,
default-deny, owner both-ways→UNKNOWN, owner-deny-only→DENY,
complain→ALLOW, default_allow inversion, unconfined, prompt→UNKNOWN,
kill note); includes (magic, `if exists` silent, missing fatal,
quoted-abs, quoted-rel CWD, cycle, directory [hypothesized]);
variables (=, +=, multi-value expansion, recursive, unresolved→UNKNOWN,
`@{profile_name}`, in-profile assignment ignored); aliases (query
rewrite, longest-prefix); globs (`*`, `**`, `?`, classes, negation,
alternates, trailing-slash dir semantics); exec op (transition
report, `deny x`, `-> target`); `--profile` bypass; `--list`
(incl. hats/children/no-attachment marks); coverage section;
never-executes; symlink-escape guard; JSON fidelity; exit codes
0/1/2. Skip-guarded live tests: `aa-status` agreement and
`/sys/.../profiles` loaded-state agreement, skipped on this box.

## Build order

1. AARE translator + variable expander (most-tested units first).
2. Line parser (preamble / profile / hat / qualifier-block stack,
   include chain with AA10/AA11/AA22).
3. Attachment selection (AA01/AA02/AA03).
4. Verdict engine (AA05–AA09) + renderers (text/JSON) + coverage
   (AA12) + loaded state (AA14).
5. Dogfood: doccover + clicheck --strict; bench-audit map extension;
   prepublish-check clean; README + CHANGELOG.


## Build corrections (added during v1 build, 2026-10-24)

These refine the design above; none changes a verdict on a well-formed
tree, but each pins down a case the design left ambiguous. Found by
tests, not by reasoning alone.

1. **AA11 — include-error profiles still compete for selection.**
   The first implementation excluded include-error profiles from
   attachment candidates, which turned "fatal if selected" into
   NO-PROFILE (exit 1) for a lone broken profile. Corrected: such
   profiles compete normally, and if one would win, the query exits 2
   (fatal). A non-winning include-error profile stays a warning only.
   This matches the design's "fatal if selected / warning otherwise"
   once "selected" is read as "would be selected by attachment".
2. **AA22 — symlink-escape guard scoped to magic includes.** The
   design says "an include resolving outside --root via a symlink is
   SKIPPED" without distinguishing forms. Implemented for `<magic>`
   includes only: an absolute include is explicit absolute intent and
   a relative include is CWD intent by AA10, so "outside --root" is
   only unexpected for magic includes. Abs/rel includes are followed
   as written (and still cycle-checked).
3. **Variables resolve tree-wide, not parse-order-before-use.** All
   preamble assignments from all scanned files (sorted scan order,
   include order within a file; last `=` wins, `+=` appends) are
   collected before any verdict, so a variable defined in a later
   file still resolves. The real parser is stricter; this is a
   deliberate not-a-validator leniency (same family as AA13).
4. **AA13 warnings surface for non-selected profiles too.** The
   design's coverage contract (AA12) lists warnings, but unparseable
   lines were only recorded on their profile object — invisible unless
   that profile was selected. Build fix: every unparseable line also
   emits a global AA13 warning; when the profile IS selected, the
   poison finding is deduplicated against it. Verdicts unchanged.
5. **Child full names use the parent name as written.** A child of
   `profile par /usr/bin/par` is `par//kid`, not
   `/usr/bin/par//kid` — the `//` join uses the profile NAME, not
   its attachment. (A bare-form parent `/usr/bin/par` does yield
   `/usr/bin/par//kid`, because there name and attachment coincide.)
6. **Include-problem inheritance is file-frame scoped.** A preamble
   include failure in a file marks profiles defined later in that
   file (the flag lives on the file frame and is copied at profile
   creation); a body include failure marks only that profile. This
   keeps a broken preamble from silently poisoning profiles in other
   scanned files.
7. **Hats via --profile report NO-PROFILE.** Hats are list-only per
   the design; `--profile <hat-name>` does not select a hat for a
   verdict (it is not in the profile namespace), it reports
   NO-PROFILE, exit 1.
8. **Alias trailing-comma handling.** The alias regex initially let
   `\S+` swallow the rule's trailing comma (`/new,`), producing a
   rewrite to `/new,/f`. Fixed by excluding commas from the target
   capture; aliases are now tested with and without trailing commas.
9. **Unclosed blocks poison.** A scanned file whose braces never
   balance marks its innermost profile with an AA13 EOF unparseable
   line (plus a global warning) instead of silently dropping the
   trailing rules.
10. **Left unverified (see README pre-publish checklist).** Dogfood
    (doccover + clicheck --strict) was not run in this session;
    live aa-status/sysfs agreement tests skip on this box (no
    AppArmor); no real `/etc/apparmor.d` tree was exercised (fixture
    trees only); the directory-include sorted expansion (AA21)
    remains [hypothesized] as the design states.
