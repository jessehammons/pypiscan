# pypiscan top-500 probe, 2026-11-06

What the C libraries bundled as shared libraries in the `.libs/`
directories of 500 popular PyPI wheels are, and what those wheels' SBOMs
claim. The packages are the first 500 projects on the top-pypi-packages
list (downloads over the previous 30 days) with a wheel for CPython 3.12 on
manylinux x86_64 with glibc 2.28 or older, which walked the list to rank
3252. Each project's latest release at the time is pinned.

- Wheels resolved from PyPI on 2026-10-25 (UTC); reports generated on
  2026-11-06 (UTC), episode `top500-c9`.
- Tool: pypiscan at commit 39d1d0c (its code is main's cbd6978).
- Package list sha256 `b97c851dca5b4600811e81faa72687c3d083407a89ae74a1f999507d8f1b9d6c`;
  library map sha256 `4ee69a1018b7df6d1d13211b5149843946719b9d13976a99e11ea36ad1fb81a8`.

Counts, from `atlas.md`:

- 500 packages; 475 wheels opened; 25 not downloaded, being over 100 MB.
- 48 wheels have a `.libs/` directory, with 572 files.
- 19 libraries by the library map's name; 294 file prefixes the map
  doesn't name, with 387 files.
- 22 of the 48 wheels ship an SBOM; 21 have a file tied to an auditwheel
  component. 91 other wheels ship an SBOM but no `.libs/`.

Files:

- `atlas.md`: one row per wheel with a `.libs/` directory.
- `sbom-report.md`: SBOM claims compared with what pypiscan identified.
- `library-report.md`: each `.libs/` prefix and its strings. At 2.5 MB it
  is a release asset only, not in the repository.
- `SUMMARY.md`: this file.
- `SHA256SUMS`: the sha256 of the four `.md` files.

To verify, put the five files in one directory and run
`shasum -a 256 -c SHA256SUMS` (macOS) or `sha256sum -c SHA256SUMS` (Linux).

Not included: no CVE matching, and no staleness, fingerprint or static
reports. Nothing here says whether any library is vulnerable or out of
date. Libraries compiled into extension modules aren't covered. The
release isn't signed.

Method: https://github.com/jessehammons/pypiscan#readme
