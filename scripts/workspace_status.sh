#!/bin/sh
# Emits stable workspace status keys consumed by Bazel x_defs in //src/version:version.
# STABLE_ keys force re-link only when their value changes, so day-to-day builds
# without new commits stay cache-friendly.

commit="$(git rev-parse --short=7 HEAD 2>/dev/null)"
if [ -z "$commit" ]; then
    commit="unknown"
fi

# %cs is the committer date in YYYY-MM-DD form.
commit_date="$(git show -s --format=%cs HEAD 2>/dev/null)"
if [ -z "$commit_date" ]; then
    commit_date="unknown"
fi

echo "STABLE_GIT_COMMIT ${commit}"
echo "STABLE_GIT_COMMIT_DATE ${commit_date}"
