"""Container images BitFedot vouches for — pure data.

Mempool publishes container images but does not sign them. A tag such as
`v3.3.2` is only a movable label on a registry; a *digest* is the SHA-256 of
the content itself. Listing the digest here means: this exact content was
pulled and checked by the maintainer for that release, and because BitFedot's
own releases are signed, that statement reaches you signed as well. Images are
then fetched and run **by digest**, so the registry cannot substitute anything.

Each digest is that of the multi-architecture index, as returned by

    skopeo inspect --raw docker://docker.io/mempool/backend:v3.3.2 | sha256sum
    (or the `docker-content-digest` header of the registry's manifest endpoint)

Compare them with your own lookup before trusting them. Adding a Mempool
release = adding its two digests here; see docs/RELEASING.md.
"""

IMAGE_DIGESTS = {
    # Mempool 3.3.2 — recorded 2026-11-16
    "docker.io/mempool/frontend:v3.3.2":
        "sha256:83c5d1e20cd4fad358584f5921ca547d69ab80162d0e2f3138c2d142a91dbadd",
    "docker.io/mempool/backend:v3.3.2":
        "sha256:c358a20591285f77fb11e6f2502441e6b15bc7dd8282433e09bfd948b8ab0aa8",
    # MariaDB, the version Mempool's own compose file asks for
    "docker.io/library/mariadb:10.5.21":
        "sha256:f3ec8c1d1cd3d62a21e7c6e3dee4cb33227c7df6dab5644bf2c077e21dfbc63d",
}


def pinned_ref(image: str) -> str:
    """'repo:tag' -> 'repo@sha256:…' when the image is vouched for, else ''."""
    digest = IMAGE_DIGESTS.get(image)
    return f"{image.rsplit(':', 1)[0]}@{digest}" if digest else ""


def pinned_mempool_versions() -> list:
    """Mempool versions for which both images are pinned, oldest first."""
    def has(part, v):
        return f"docker.io/mempool/{part}:v{v}" in IMAGE_DIGESTS
    versions = {k.rsplit(":v", 1)[1] for k in IMAGE_DIGESTS if k.startswith("docker.io/mempool/")}
    ok = [v for v in versions if has("frontend", v) and has("backend", v)]
    return sorted(ok, key=lambda v: tuple(int(x) for x in v.split(".") if x.isdigit()))
