#!/bin/sh
# Recreate src/urllib3/_version.py from git metadata.
#
# urllib3 does not keep this file in git. Its build backend (hatch-vcs) writes
# it from the nearest git tag, so a plain checkout cannot be imported. This is
# the same derivation, kept explicit and reviewable: take the tag exactly when
# HEAD is the tagged commit, otherwise read the exact version git reports when
# the tag is omitted.
set -eu

target="src/urllib3/_version.py"
if [ -f "$target" ]; then
    exit 0
fi

# Make tags available; a shallow clone has none.
git fetch --tags --force --quiet 2>/dev/null || true
if [ "$(git rev-parse --is-shallow-repository 2>/dev/null || echo false)" = "true" ]; then
    git fetch --tags --unshallow --quiet 2>/dev/null || true
fi

describe="$(git describe --tags --always 2>/dev/null || echo unknown)"
case "$describe" in
    # HEAD is exactly on a tag: v2.8.0 -> 2.8.0
    v[0-9]*) version="${describe#v}" ;;
    # Otherwise git reports 2.8.0-41-g<sha>; keep the base version.
    [0-9]*) version="$(printf '%s' "$describe" | sed 's/-[0-9]*-g.*$//')" ;;
    *) version="0.0.0" ;;
esac

printf '__version__ = "%s"\n' "$version" > "$target"
echo "wrote $target with version $version"
