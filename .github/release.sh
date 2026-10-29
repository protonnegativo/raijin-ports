#!/usr/bin/env bash
# release.sh [patch|minor|major] tags HEAD with the next v* version and creates its GitHub Release.
# The first release is v0.1.0. Nothing happens when HEAD already has a tag. Needs GH_TOKEN and the
# full history (fetch-depth: 0).
set -euo pipefail

bump=${1:-patch}
case "$bump" in patch | minor | major) ;; *) echo "usage: $0 [patch|minor|major]" >&2; exit 1 ;; esac

git fetch --tags --force --quiet
if [ -n "$(git tag --points-at HEAD 'v*')" ]; then
  echo "HEAD is already tagged $(git tag --points-at HEAD 'v*' | head -1)"
  exit 0
fi

latest=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -1)
if [ -z "$latest" ]; then
  tag=v0.1.0
else
  IFS=. read -r major minor patch <<<"${latest#v}"
  patch=${patch%%[-+]*}
  case "$bump" in
    major) tag=v$((major + 1)).0.0 ;;
    minor) tag=v$major.$((minor + 1)).0 ;;
    patch) tag=v$major.$minor.$((patch + 1)) ;;
  esac
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git tag -a "$tag" -m "$tag"
git push origin "$tag"
gh release create "$tag" --generate-notes --verify-tag
# Events created with GITHUB_TOKEN do not start other workflows, so start the binaries build here.
gh workflow run goreleaser.yml -f tag="$tag"
echo "released $tag"
