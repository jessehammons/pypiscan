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
