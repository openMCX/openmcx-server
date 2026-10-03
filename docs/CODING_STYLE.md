# openMCX coding style

The rules for all openMCX code (openmcx-server, openmcx-client, openmcx-admin). The tools in section 7 check them; code that is refactored follows them at once, other
code as it is touched.

## 1. Names

### 1.1 No single-letter names

No variable, parameter, loop counter, receiver, lambda argument or exception is one letter. Use short words that say
what the thing is:

| Instead of | Write |
|---|---|
| `for (int i = 0; ...)` | `for (int index = 0; ...)`, or better a range loop over `member`, `packet`, ... |
| `auto r = sip_.request(...)` | `auto response = sip_.request(...)` |
| `const Json &s = status_` | `const Json &status = status_` |
| `catch (const std::exception &e)` | `catch (const std::exception &error)` |
| Go `func (s *service) ...` | `func (svc *service) ...` |
| Go `func handler(w http.ResponseWriter, r *http.Request)` | `func handler(writer http.ResponseWriter, request *http.Request)` |
| Kotlin `list.map { it.id }` | `list.map { member -> member.id }` where the lambda is not a one-word property access |
| Python `for m in members` | `for member in members` |

Abbreviations only where the specification uses them: `mcptt_id`, `csk`, `gmk`, `pck`, `sdp`, `rtp`, `srtp`, `sds`,
`fd`, `gms`, `cms`, `idms`, `kms`. Two-letter words are fine when they are words (`id`, `ok`, `to`).

### 1.2 C++ conventions (the current code's, now checked)

| Kind | Style | Example |
|---|---|---|
| Types, enums, enum values | `CamelCase` | `FloorParticipant`, `FloorParticipantState::HasPermission` |
| Functions, variables, parameters | `snake_case` | `request_floor()`, `group_id` |
| Private and protected members | `snake_case_` | `status_`, `floor_timers_` |
| Constants (`constexpr`) | `snake_case` | `mcptt_icsi`, `groups_auid` |
| Namespaces | `snake_case` | `mcx`, `mcx::mcdata` |

- Units in names: `timeout_ms`, `expires_s`, `size_bytes`.
- Booleans as questions: `is_affiliated`, `has_permission`, `should_retry`.
- States of a specification's state machine carry the specification's names (`U: has permission` becomes
  `HasPermission`); timers carry theirs (`t101`, `tfg1`).

### 1.3 Go, Kotlin, Python

Their language conventions (Go `MixedCaps`, Kotlin `camelCase`, Python `snake_case`) with the rules of 1.1.

## 2. Specification references

### 2.1 The form

- **The deepest clause, not the chapter:** `TS 24.380 clause 6.2.4.4.2`, and the steps when a function implements
  some of them: `TS 24.379 clause 10.1.1.2.1.1 steps 3 to 5`.
- **Tables, figures and annexes by their own numbers:** `TS 24.282 table 15.2.2-1`, `TS 24.380 figure 6.2.4.1-1`,
  `TS 33.180 annex B.6`, `TS 24.379 annex G.4.1`.
- **RFCs by section:** `RFC 3261 section 10.2`.
- Lower-case `clause`, `table`, `figure`, `annex`, `section`; no `§`.
- **The specification's own names** for its messages, fields, states, timers and causes: `Floor Request`, the
  `Floor Priority` field, state `U: has permission`, timer `T101`, `Warning: 121`.

### 2.2 Where

- **Every file** starts with a header: what it implements and the specifications it follows, **with their versions**:

  ```cpp
  // Floor control, participant side: the floor participant state machine of TS 24.380
  // clause 6.2.4 (on-network, basic operation) and its timers (clause 6.2.1, annex F).
  //
  // Specifications: TS 24.380 V19.3.0 (Rel-19), TS 24.379 V19.6.0 (Rel-19).
  ```

  References inside the file then need no version. `docs/SPECS.md` lists every specification the code follows with
  its pinned version.
- **Every function that implements a procedure** starts with its reference and what it does:

  ```cpp
  //------------------------------------------------------------------------------
  // TS 24.380 clause 6.2.4.4.2: in 'U: has permission', the user releases the floor: send Floor Release,
  // start T100 and enter 'U: pending Release'.
  void FloorParticipant::release_floor() {
  ```

- **Every timer, limit, code and bit** is a named constant with its reference, never a bare number:

  ```cpp
  // TS 24.380 annex F.1: T101 (Floor Request) default 0.5 s.
  constexpr std::chrono::milliseconds t101_default{500};
  ```

- **Deviations and gaps** are marked so the compliance matrix can list them:
  `// Deviation from TS 24.379 clause 10.1.1.2.1.1 step 7: ... because ...`,
  `// Not implemented: TS 24.379 clause 10.1.2.2.1.4 (...)`.
- **Log and error messages** name the procedure and the clause:
  `floor request refused: TS 24.380 clause 6.3.4.3, cause 102`.
- **Tests** are named after the clause they prove: `Clause_6_2_4_4_2_ReleaseInHasPermission`.

## 3. Layout

### 3.1 Separator

A separator line before every function, method and top-level type, the same string in every file so that a search
finds every boundary:

| Language | Separator (80 columns) |
|---|---|
| C++, Kotlin | `//------------------------------------------------------------------------------` |
| Go | `// ------------------------------------------------------------------------------` (gofmt puts a space after `//` in a doc comment) |
| Python | `# ------------------------------------------------------------------------------` (`# ` and 78 dashes) |

The function's reference comment follows the separator directly (2.2).

### 3.2 Files and functions

- One topic per file (a procedure family, a state machine, a codec, a service role), at most about 1,500 lines.
- Functions of at most about 60 lines and bounded complexity (checked); a long procedure is split along the
  specification's steps.
- C++ headers: `#pragma once`; includes grouped as own header, project (`mcx/...`), third party, standard library
  (clang-format sorts them); one namespace per module.

## 4. C++ practice

- `const` wherever possible; RAII for every resource; no raw `new` and `delete`.
- `std::optional` for a value that may be absent, **checked before use** (clang-tidy
  `bugprone-unchecked-optional-access`); `std::expected` for a result that may fail in the normal course.
- Exceptions for failures only, never for control flow; no empty `catch` without a comment saying why.
- Comments say why and which clause, not what the next line does.

## 5. Go, Kotlin and Python practice

- Go: errors wrapped with their context (`fmt.Errorf("gms provisioning: %w", err)`), every error checked,
  `context.Context` passed through, table-driven tests.
- Kotlin and Python: the same rules of sections 1 to 3 in their idioms.

## 6. Formatting

| Language | Tool | Configuration |
|---|---|---|
| C++ | clang-format 23 | `.clang-format` (LLVM base, 2-space indent, 120 columns, the current conventions) |
| Go | gofmt | (none) |
| Python | ruff format 0.16 | `ruff.toml` (120 columns) |
| Kotlin | ktlint | (with the Android clean-up) |

Formatting changes go in commits of their own, listed in `.git-blame-ignore-revs` so that `git blame` skips them.

## 7. Tools

All tools run in the `openmcx-lint:0.1` image (`docker/Dockerfile.lint`: the development image plus clang-format
and clang-tidy 23.1, golangci-lint 2.14.0 and ruff 0.16.9, pinned); nothing is installed on the host.

| Command | What it does |
|---|---|
| `tools/lint-image` | builds `openmcx-lint:0.1` (needs the golangci-lint and ruff archives in `.cache/deps`) |
| `tools/format` | formats C++, Go and Python in place |
| `tools/format --check` | lists what is not formatted; fails if anything is |
| `tools/lint [cpp\|go\|py]` | clang-tidy (`.clang-tidy`), golangci-lint (`services/.golangci.yml`), ruff and `tools/check-names.py`; findings in `artifacts/lint/`, counts on the terminal |
| `tools/lint --strict` | fails on any finding (the target once the refactoring is done) |

### 7.1 Baseline (mcxserver `main` fe4a34e, 2026-09-30)

| | Findings | Largest |
|---|---:|---|
| C++ format | 76 of 76 files | |
| Python format | 106 of 106 files | |
| Go format | 0 | |
| C++ clang-tidy | 3,889 | magic numbers 2,085; short names 1,121; signed bitwise 207; naming 148; complexity 84; unchecked `optional` 82; function size 69 |
| Go golangci-lint | 781 | short names 688; unchecked errors 33; complexity 27; function length 25 |
| Python ruff | 1,471 | |
| Python single-letter names | 2,657 | |

The refactoring steps bring these to zero, file by file; `tools/lint --strict` then guards them.
