# Data

Curated inputs, edited by hand and committed so every run uses the same
pinned input.

## `smoke.csv`

The smoke list for `scan` runs with a small `--count`. It is a package list
(see `pypiscan.package_list`): columns `name` and `version`, in processing
order. Rows are ordered so that the first few exercise the most, and each
pins the package's latest final release on PyPI as of 2026-10-14. Each
row's role was confirmed from PyPI's JSON API with `pypi.select_target`,
without downloading any wheels.

| Row | Why it's here |
|---|---|
| `pillow` | Its target wheel has a `pillow.libs/` directory of auditwheel-bundled shared libraries (libjpeg, libfreetype, libharfbuzz and others). |
| `lxml` | Links zlib statically into its extension modules (zlib 1.3.2 in `lxml/etree`, roadmap 2.1). |
| `requests` | Ships only a pure-Python wheel, so it has no target: phase 01 records it as `skipped`, `no_target`. |
| `torch` | Its target wheel is about 555 MB by PyPI's reported size, over the 100 MB wheel size limit: phase 02 records it as `skipped`, `too_large`. |
| `numpy` | A second `.libs/` directory (`numpy.libs/`: OpenBLAS, libgfortran and libquadmath). |
| `grpcio` | Statically linked zlib with a four-part version (1.3.1.1, roadmap 2.1), and a target tagged `manylinux2014` / `manylinux_2_17`. |
| `cryptography` | An `abi3` target wheel that links OpenSSL statically. |

## `large.csv`

The eight large wheels of roadmap C.5, which the top-500 probe skipped as
`too_large` and which aren't NVIDIA's CUDA libraries or model data. Each
version is the one `top500-p1`'s `01-resolve.jsonl` resolved, so the
episode measures the wheels the probe skipped. Scanning them needs
`--wheel-size-limit` and `--member-size-limit` raised (see the C.5 bullet
in the README).

## `packages.csv`

The full package list for `scan` (roadmap 3.6): 100 rows, in rank order.
`scripts/top_packages.py` generates it; it is never edited by hand, and
refreshing it is its own pull request.

Rank source: the top-pypi-packages snapshot,
<https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json>, which
ranks projects by PyPI downloads over the previous 30 days. The snapshot
isn't committed. The one this list was generated from:

- `last_update`: 2026-10-01 12:40:51 (the October 2026 snapshot)
- sha256: `55fee05ed02b628f05350a51780ec436efae39ea0810df5d5419e15b850c7041`
- Downloaded on 2026-10-14 from the GitHub repository the site publishes,
  <https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json>,
  because hugovk.dev wasn't reachable from where the script ran
  (`--url` selects the source).

Selection rule, applied to each project in rank order:

1. Its versions come from the Simple API's JSON form (PEP 691 and 700), not
   the project JSON's deprecated `releases` key.
2. Its latest final release is the highest version with no pre-release or
   dev part (post-releases count), skipping releases with no unyanked
   file.
3. The project is kept if `pypi.select_target` finds a target wheel in that
   release's files, as phase 01 does. Wheel size isn't checked: the wheel
   size limit is applied when scanning, so raising it doesn't mean
   regenerating the list.
4. The walk stops once 100 projects are kept.

Result: the walk stopped at rank 469. It passed over 362 projects whose
latest final release has no target wheel, and 7 with no final release at
all (OpenTelemetry packages that publish only beta versions, such as
`opentelemetry-instrumentation`).
