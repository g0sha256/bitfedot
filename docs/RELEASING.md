# Releasing BitFedot

Installed copies update themselves **only** from releases signed with a key they already carry
(`bitfedot/keys/bitfedot/`). That makes the release key the root of trust for every user: guard it.

## One-time setup: the release key

```sh
# 1. Create a signing key (ideally on a hardware token or an offline machine)
gpg --quick-generate-key "BitFedot release signing <you@example.org>" ed25519 sign 3y

# 2. Ship its public half with the app
gpg --armor --export "BitFedot release signing" > bitfedot/keys/bitfedot/release.asc
gpg --show-keys --with-fingerprint bitfedot/keys/bitfedot/release.asc     # note the fingerprint

# 3. Publish the fingerprint somewhere independent of this repository
#    (your GitHub profile, a signed post, keys.openpgp.org) so users can cross-check it.
```

Commit the key file. From the first release that contains it, self-update is live; builds without
a key only announce new versions and install nothing.

Also sign your commits and tags (`git config commit.gpgsign true`, `git config tag.gpgSign true`)
so people who install from a git checkout can verify what they run.

## Each release

1. Update `__version__` in `bitfedot/__init__.py`, `version` in `pyproject.toml`, `Version:` in
   `packaging/bitfedot.spec`, the `<release>` in the metainfo file, and `CHANGELOG.md`.
2. **Vouch for new container images.** If Mempool released a version you have checked, add the
   digests of its two images to `bitfedot/pins.py`:

   ```sh
   for part in frontend backend; do
     skopeo inspect --raw docker://docker.io/mempool/$part:vX.Y.Z | sha256sum
   done
   ```

   Look them up from two networks (or compare with someone else) before committing; a digest in
   `pins.py` is your signed statement that this content is the real release.
3. Refresh pinned keys that upstream rotated (`bitfedot/keys/README.md` says where each comes from).
4. Commit, then:

   ```sh
   tools/release.sh
   ```

   It runs the tests, creates the signed tag, builds `dist/bitfedot-<version>.tar.gz` with
   `git archive`, writes and signs `SHA256SUMS`, and checks that the key *inside the release*
   verifies it.
5. Push the tag and attach the three files from `dist/` to the GitHub release. The updater
   downloads exactly these names from `releases/download/v<version>/`.

## Rotating the release key

Add the new public key to `bitfedot/keys/bitfedot/` and publish one release signed with the **old**
key. Every copy that installs it now trusts both; sign later releases with the new key, and remove
the old file a few releases on. If the old key is lost or compromised there is no in-band
recovery — users must reinstall from a source they verify by other means. Keep a backup.

## What users rely on

| They trust | For |
|---|---|
| your release key | BitFedot's code, its pinned keys, its image digests |
| ≥ N Bitcoin Core builders (default 3) | the Bitcoin Core binary |
| each app's developer key | that app |
| Fedora's package keys | the operating system, Tor |
