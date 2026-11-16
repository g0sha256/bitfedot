# BitFedot release key(s)

Put the maintainer's public release key here as `<name>.asc` (ASCII-armored).

Every primary key in this folder may sign BitFedot releases. The self-updater
(`bitfedot/selfupdate.py`) installs a new version **only** if its `SHA256SUMS` carries a valid
signature from one of them — and while this folder holds no key, it installs nothing at all and
only tells the user that a newer version exists.

Because each release ships this folder, a release signed with the current key can introduce the
next key: that is how the key is rotated. See `docs/RELEASING.md`.
