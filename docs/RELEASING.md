# Releasing sqlite-cage

Releases are **GitHub-only** for now — not published to PyPI. Users install
from a git URL or vendor the single module. The steps below cut a tagged
GitHub release.

## Version is single-sourced

The version lives in exactly one place: `__version__` in
`src/sqlite_cage/__init__.py`. `pyproject.toml` declares
`dynamic = ["version"]` and hatchling reads it from there, so the built wheel,
`sqlite_cage.__version__`, and a vendored copy all agree. **Bump only that
constant.** Never add a second version string.

Follow [SemVer](https://semver.org): patch for fixes, minor for additive API,
major for anything that breaks a caller. A change to what the cage *denies* or
to the honesty contract is at least minor, and worth calling out in the
changelog even when technically compatible.

## Before tagging

1. Working tree clean, on `main`, up to date with `origin`.
2. CI green on `main` — the matrix suite (3.11–3.13) plus the seeded fuzz.
   Never tag a red or stale commit.
3. Locally, as a final gate:
   ```
   ruff check src tests
   pytest -q
   python -m tests.fuzz_cage 5000 <n>     # a longer fuzz than CI runs
   uv build                               # wheel + sdist build cleanly
   ```
   The wheel's version must match `__version__`:
   ```
   uv build && ls dist/            # sqlite_cage-<version>-py3-none-any.whl
   ```

## Cut the release

```bash
# 1. bump the constant
$EDITOR src/sqlite_cage/__init__.py          # __version__ = "X.Y.Z"

# 2. date the changelog: turn the top "[X.Y.Z] — unreleased" into today's date,
#    and confirm it lists every user-facing change since the last tag.
$EDITOR CHANGELOG.md

# 3. commit, tag, push
git add -A && git commit -m "Release X.Y.Z"
git tag -a vX.Y.Z -m "sqlite-cage X.Y.Z"
git push origin main --follow-tags

# 4. publish the GitHub release. NOTE: ci.yml triggers on `push: branches:
#    [main]` and pull_request only — it does NOT run on tags. So confirm the
#    green run on the *release commit* (`gh run list --limit 1`); there will
#    never be a separate run for the tag. `gh run list --commit <sha>` does
#    not match reliably — read the run title instead.
gh release create vX.Y.Z \
  --title "sqlite-cage X.Y.Z" \
  --notes-file <(sed -n '/## \[X.Y.Z\]/,/## \[/p' CHANGELOG.md | sed '$d')
```

The tag (`vX.Y.Z`) is what installers pin to; the constant (`X.Y.Z`) is what
the code reports. Keep them equal — the pre-tag build check above catches a
mismatch.

## After releasing

- **Open the next changelog section**: add a fresh `## [next] — unreleased`
  heading so subsequent changes have a home.
- **The vendored consumers do not auto-update.** Copies live at
  `newton-history-books/tools/shelfkit/cage.py` and
  `newton-graphic/server/cage.py`. Re-copy `src/sqlite_cage/__init__.py` into
  each when you want them on the new version, and run each project's own test
  suite. There is no coupling — a consumer can stay on an older cage
  indefinitely.

## Installing a release

```bash
pip install "sqlite-cage @ git+https://github.com/mhalle/sqlite-cage@vX.Y.Z"
```

Or vendor it: copy `src/sqlite_cage/__init__.py` into the project. It is
stdlib-only, so nothing else is needed.

## If PyPI is enabled later

Not done today. When it is: add a trusted-publisher workflow triggered on tag,
`uv build`, `twine check dist/*`, publish. Reserve the name first. Until then,
the git-URL install above is the supported path and this document is the whole
process.
