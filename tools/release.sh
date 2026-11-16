#!/usr/bin/env bash
# Build and sign a BitFedot release. See docs/RELEASING.md.
#   tools/release.sh            build + sign into dist/
# Needs: a clean git tree, your release key in gpg, and its public half in bitfedot/keys/bitfedot/.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

version=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' bitfedot/__init__.py)
[[ -n "$version" ]] || { echo "Cannot read the version from bitfedot/__init__.py"; exit 1; }
tag="v$version"

[[ -z "$(git status --porcelain)" ]] || { echo "Commit or stash your changes first."; exit 1; }
ls bitfedot/keys/bitfedot/*.asc >/dev/null 2>&1 || {
    echo "No release key in bitfedot/keys/bitfedot/ — installed copies could never verify this release."
    echo "See docs/RELEASING.md, 'One-time setup'."; exit 1; }

echo "== Tests"
python3 -m unittest discover tests

echo "== Tag $tag (signed)"
git rev-parse -q --verify "refs/tags/$tag" >/dev/null || git tag -s "$tag" -m "BitFedot $version"

echo "== Archive"
mkdir -p dist
archive="bitfedot-$version.tar.gz"
git archive --format=tar.gz --prefix="bitfedot-$version/" -o "dist/$archive" "$tag"
( cd dist && sha256sum "$archive" > SHA256SUMS && gpg --batch --yes --armor --detach-sign -o SHA256SUMS.asc SHA256SUMS )

echo "== Check: does the key shipped in this very release verify it?"
home=$(mktemp -d); trap 'rm -rf "$home"' EXIT
gpg --homedir "$home" --batch -q --import bitfedot/keys/bitfedot/*.asc
gpg --homedir "$home" --batch --trust-model always --verify dist/SHA256SUMS.asc dist/SHA256SUMS

cat <<DONE

Release files are in dist/:
  $archive  SHA256SUMS  SHA256SUMS.asc

Publish:
  git push origin main "$tag"
  then create the GitHub release "$tag" and attach the three files, e.g.
  gh release create "$tag" dist/$archive dist/SHA256SUMS dist/SHA256SUMS.asc --title "BitFedot $version" --notes-file CHANGELOG.md
DONE
