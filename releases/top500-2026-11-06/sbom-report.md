# SBOM report

An SBOM is a claim about what a wheel bundles, not a measurement, and a
difference below is checked by hand; see "Comparing SBOMs with fingerprints"
in the README. The counts cover auditwheel's SBOMs only: other SBOMs are
listed, not compared.

## Counts

- Packages scanned in phase 09: 475; with any SBOM: 113; with an auditwheel SBOM: 22.
- auditwheel components that name a file: tied 145, not tied 1.
- `.libs/` files in scanned packages: tied 145, not tied 427.
- Tied files that agree: 16 (bare_version 2, library_string 10, version_function_machine_code 4).
- Tied files that differ: 1 (version_function_machine_code 1).
- Tied files not compared: 128 (matches disagree 2, no recognizer 14, not detected 1, not in map 73, not tracked 36, several libraries 2).

## cryptography 50.0.2

`cryptography-50.0.2-cp311-abi3-manylinux_2_28_x86_64.whl`

- `cryptography-50.0.2.dist-info/sboms/cryptography-rust.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 39 components; listed, not compared
- `cryptography-50.0.2.dist-info/sboms/sbom.json`: tools —; 1 component; listed, not compared

No .libs/ files.

## pydantic-core 2.50.1

`pydantic_core-2.50.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `pydantic_core-2.50.1.dist-info/sboms/pydantic-core.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 99 components; listed, not compared

No .libs/ files.

## numpy 2.5.4

`numpy-2.5.4-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libgfortran-83c28eba-468e71e5.so.5.0.0 | — | skip | — | — | not tracked | — |
| libquadmath-2284e583-a9307bba.so.0.0.0 | — | skip | — | — | not tracked | — |
| libscipy_openblas64_-f48b354e.so | — | openblas | 0.3.34.106.0 | library_string |  | — |

## rpds-py 2026.9.1

`rpds_py-2026.9.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `rpds_py-2026.9.1.dist-info/sboms/rpds-py.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 17 components; listed, not compared

No .libs/ files.

## pillow 13.0.0

`pillow-13.0.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

- `pillow-13.0.0.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.8.2; 2 components; compared
- `pillow-13.0.0.dist-info/sboms/pillow-13.0.0.cdx.json`: tools generate-sbom.py; 24 components; listed, not compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libXau-154567c4.so.6.0.0 | libXau 1.0.9-3.el8 (pkg:rpm/almalinux/libXau@1.0.9-3.el8) | skip | — | — | not tracked | not compared: not tracked |
| libavif-c6062d5f.so.16.4.2 | — | libavif | 1.4.2 | version_function_machine_code |  | — |
|  |  | aom | 3.14.1 | library_string |  |  |
|  |  | dav1d | 1.5.3 | version_function_machine_code |  |  |
| libbrotlicommon-53534446.so.1.2.0 | — | brotli | — | — | no recognizer | — |
| libbrotlidec-7e5462ba.so.1.2.0 | — | brotli | 1.2.0 | version_function_machine_code |  | — |
| libfreetype-57f805ba.so.6.20.6 | — | freetype | — | — | no recognizer | — |
|  |  | bzip2 | 1.0.8 | library_string |  |  |
| libharfbuzz-fb49c9fc.so.0.61450.0 | — | harfbuzz | 14.5.0 | version_function_machine_code |  | — |
| libjpeg-6dc8d115.so.62.4.0 | — | libjpeg-turbo | 3.2.0 | library_string |  | — |
| liblcms2-88eaba2f.so.2.0.19 | — | lcms2 | 2.19.0 | version_function_machine_code | ambiguous: may also be 2.19.1 | — |
| liblzma-de26b416.so.5.8.4 | — | xz | 5.8.4 | version_function_machine_code |  | — |
| libopenjp2-e530e1bf.so.2.5.4 | — | openjpeg | 2.5.4 | build_path |  | — |
| libpng16-1d1ba958.so.16.58.0 | — | libpng | 1.6.58 | library_string |  | — |
| libsharpyuv-0066295b.so.0.1.2 | — | libwebp | — | — | no recognizer | — |
| libtiff-20b7e810.so.6.3.0 | — | libtiff | 4.7.2 | library_string |  | — |
| libwebp-51b0b3f7.so.7.2.0 | — | libwebp | 1.6.0 | version_function_machine_code |  | — |
| libwebpdemux-9fe2abcc.so.2.0.17 | — | libwebp | 1.6.0 | version_function_machine_code |  | — |
| libwebpmux-8fb1c9f6.so.3.1.2 | — | libwebp | 1.6.0 | version_function_machine_code |  | — |
| libxcb-9065bb12.so.1.1.0 | — | skip | — | — | not tracked | — |
| libzstd-40ad5e7e.so.1.5.7 | — | zstd | 1.5.7 | build_path |  | — |

## jiter 0.18.0

`jiter-0.18.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `jiter-0.18.0.dist-info/sboms/jiter-python.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 38 components; listed, not compared

No .libs/ files.

## watchfiles 1.3.0

`watchfiles-1.3.0-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `watchfiles-1.3.0.dist-info/sboms/watchfiles_rust_notify.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 26 components; listed, not compared

No .libs/ files.

## ruff 0.17.2

`ruff-0.17.2-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `ruff-0.17.2.dist-info/sboms/ruff.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 334 components; listed, not compared

No .libs/ files.

## scipy 1.18.1

`scipy-1.18.1-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

- `scipy-1.18.1.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.7.0; 3 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libgfortran-040039e1-0352e75f.so.5.0.0 | — | skip | — | — | not tracked | — |
| libgfortran-83c28eba.so.5.0.0 | libgfortran 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libgfortran@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |
| libquadmath-2284e583.so.0.0.0 | libquadmath 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libquadmath@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |
| libquadmath-96973f99-934c22de.so.0.0.0 | — | skip | — | — | not tracked | — |
| libscipy_openblas-5f890258.so | — | openblas | 0.3.31.dev | library_string |  | — |

## psycopg2-binary 2.9.13

`psycopg2_binary-2.9.13-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl`

- `psycopg2_binary-2.9.13.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.7.0; 10 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libcom_err-2abe824b.so.2.1 | libcom_err 1.42.9-19.el7 (pkg:rpm/centos/libcom_err@1.42.9-19.el7) | skip | — | — | not tracked | not compared: not tracked |
| libcrypt-bc2db45e.so.1 | — | skip | — | — | not tracked | — |
| libcrypto-fb8d5b21.so.3 | — | openssl | 3.5.8 | library_string |  | — |
| libgssapi_krb5-497db0c6.so.2.2 | krb5-libs 1.15.1-55.el7_9 (pkg:rpm/centos/krb5-libs@1.15.1-55.el7_9) | krb5 | — | — | no recognizer | not compared: no recognizer |
| libk5crypto-b1f99d5c.so.3.1 | krb5-libs 1.15.1-55.el7_9 (pkg:rpm/centos/krb5-libs@1.15.1-55.el7_9) | krb5 | — | — | no recognizer | not compared: no recognizer |
| libkeyutils-dfe70bd6.so.1.5 | keyutils-libs 1.5.8-3.el7 (pkg:rpm/centos/keyutils-libs@1.5.8-3.el7) | skip | — | — | not tracked | not compared: not tracked |
| libkrb5-fcafa220.so.3.3 | krb5-libs 1.15.1-55.el7_9 (pkg:rpm/centos/krb5-libs@1.15.1-55.el7_9) | krb5 | 1.15.1 | library_string |  | agrees |
| libkrb5support-d0bcff84.so.0.1 | krb5-libs 1.15.1-55.el7_9 (pkg:rpm/centos/krb5-libs@1.15.1-55.el7_9) | krb5 | — | — | no recognizer | not compared: no recognizer |
| liblber-2f335fb0.so.2.0.200 | — | openldap | — | — | no recognizer | — |
| libldap-d3931cbf.so.2.0.200 | — | openldap | — | — | no recognizer | — |
| libpcre-9513aab5.so.1.2.0 | pcre 8.32-17.el7 (pkg:rpm/centos/pcre@8.32-17.el7) | skip | — | — | not tracked | not compared: not tracked |
| libpq-a17e3caa.so.5.17 | — | postgresql | 17.11 | version_function_machine_code |  | — |
| libsasl2-84219a89.so.3.0.0 | cyrus-sasl-lib 2.1.26-24.el7_9 (pkg:rpm/centos/cyrus-sasl-lib@2.1.26-24.el7_9) | cyrus-sasl | 2.1.26 | bare_version | needs another source | agrees |
| libselinux-0922c95c.so.1 | libselinux 2.5-15.el7 (pkg:rpm/centos/libselinux@2.5-15.el7) | skip | — | — | not tracked | not compared: not tracked |
| libssl-8bd944e8.so.3 | — | openssl | — | — | no recognizer | — |

## hf-xet 1.7.0

`hf_xet-1.7.0-cp38-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl`

- `hf_xet-1.7.0.dist-info/sboms/hf_xet.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 230 components; listed, not compared

No .libs/ files.

## scikit-learn 1.9.1

`scikit_learn-1.9.1-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

- `scikit_learn-1.9.1.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.7.0; 2 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libgomp-e985bcbb.so.1.0.0 | libgomp 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libgomp@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |

## orjson 3.13.0

`orjson-3.13.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `orjson-3.13.0.dist-info/sboms/orjson.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 20 components; listed, not compared

No .libs/ files.

## tokenizers 0.23.3

`tokenizers-0.23.3-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `tokenizers-0.23.3.dist-info/sboms/tokenizers-python.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 127 components; listed, not compared

No .libs/ files.

## google-crc32c 1.9.0

`google_crc32c-1.9.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libcrc32c-7ebc40c5.so.1.1.0 | — | skip | — | — | not tracked | — |

## uv 0.13.5

`uv-0.13.5-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `uv-0.13.5.dist-info/sboms/uv.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 566 components; listed, not compared

No .libs/ files.

## psycopg-binary 3.3.6

`psycopg_binary-3.3.6-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl`

- `psycopg_binary-3.3.6.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.7.0; 10 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libcom_err-2abe824b.so.2.1 | libcom_err 1.42.9-19.el7 (pkg:rpm/centos/libcom_err@1.42.9-19.el7) | skip | — | — | not tracked | not compared: not tracked |
| libcrypt-bc2db45e.so.1 | — | skip | — | — | not tracked | — |
| libcrypto-2d1629ee.so.3 | — | openssl | 3.5.8 | library_string |  | — |
| libgssapi_krb5-497db0c6.so.2.2 | krb5-libs 1.15.1-55.el7_9 (pkg:rpm/centos/krb5-libs@1.15.1-55.el7_9) | krb5 | — | — | no recognizer | not compared: no recognizer |
| libk5crypto-b1f99d5c.so.3.1 | krb5-libs 1.15.1-55.el7_9 (pkg:rpm/centos/krb5-libs@1.15.1-55.el7_9) | krb5 | — | — | no recognizer | not compared: no recognizer |
| libkeyutils-dfe70bd6.so.1.5 | keyutils-libs 1.5.8-3.el7 (pkg:rpm/centos/keyutils-libs@1.5.8-3.el7) | skip | — | — | not tracked | not compared: not tracked |
| libkrb5-fcafa220.so.3.3 | krb5-libs 1.15.1-55.el7_9 (pkg:rpm/centos/krb5-libs@1.15.1-55.el7_9) | krb5 | 1.15.1 | library_string |  | agrees |
| libkrb5support-d0bcff84.so.0.1 | krb5-libs 1.15.1-55.el7_9 (pkg:rpm/centos/krb5-libs@1.15.1-55.el7_9) | krb5 | — | — | no recognizer | not compared: no recognizer |
| liblber-a44a5afb.so.2.0.200 | — | openldap | — | — | no recognizer | — |
| libldap-7c3a4b12.so.2.0.200 | — | openldap | — | — | no recognizer | — |
| libpcre-9513aab5.so.1.2.0 | pcre 8.32-17.el7 (pkg:rpm/centos/pcre@8.32-17.el7) | skip | — | — | not tracked | not compared: not tracked |
| libpq-e9b5c9ac.so.5.18 | — | postgresql | 18.6 | version_function_machine_code |  | — |
| libsasl2-84219a89.so.3.0.0 | cyrus-sasl-lib 2.1.26-24.el7_9 (pkg:rpm/centos/cyrus-sasl-lib@2.1.26-24.el7_9) | cyrus-sasl | 2.1.26 | bare_version | needs another source | agrees |
| libselinux-0922c95c.so.1 | libselinux 2.5-15.el7 (pkg:rpm/centos/libselinux@2.5-15.el7) | skip | — | — | not tracked | not compared: not tracked |
| libssl-8bd944e8.so.3 | — | openssl | — | — | no recognizer | — |

## pyzmq 27.2.0

`pyzmq-27.2.0-cp312-abi3-manylinux_2_26_x86_64.manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libsodium-1c6bac97.so.26.4.0 | — | libsodium | 1.0.22 | bare_version | needs another source | — |
| libzmq-82f916e6.so.5.2.5 | — | libzmq | 4.3.5 | version_function_machine_code |  | — |

## ast-serialize 0.13.1

`ast_serialize-0.13.1-cp39-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `ast_serialize-0.13.1.dist-info/sboms/mypy_parser.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 96 components; listed, not compared

No .libs/ files.

## safetensors 0.8.0

`safetensors-0.8.0-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `safetensors-0.8.0.dist-info/sboms/safetensors-python.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 34 components; listed, not compared

No .libs/ files.

## uuid-utils 1.1.0

`uuid_utils-1.1.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `uuid_utils-1.1.0.dist-info/sboms/uuid-utils.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 36 components; listed, not compared

No .libs/ files.

## torch 2.14.1

skipped at 02-fetch: too_large

## shapely 2.2.0

`shapely-2.2.0-cp312-cp312-manylinux_2_24_x86_64.manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libgeos-d1e818bb.so.3.14.1 | — | geos | — | — | no recognizer | — |
| libgeos_c-ac38a227.so.1.20.5 | — | geos | 3.14.1 | library_string |  | — |

## pendulum 3.3.0

`pendulum-3.3.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `pendulum-3.3.0.dist-info/sboms/_pendulum.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 13 components; listed, not compared

No .libs/ files.

## hypothesis 6.170.9

`hypothesis-6.170.9-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `hypothesis-6.170.9.dist-info/sboms/hypothesis-native.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 13 components; listed, not compared

No .libs/ files.

## numba 0.68.0

`numba-0.68.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

- `numba-0.68.0.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.8.2; 2 components; compared

No .libs/ files.

auditwheel components tied to no file:

| name | version | purl | bom-ref |
|---|---|---|---|
| libgomp | 8.5.0-28.el8_10.alma.1 | pkg:rpm/almalinux/libgomp@8.5.0-28.el8_10.alma.1 | pkg:rpm/almalinux/libgomp@8.5.0-28.el8_10.alma.1#c61017c9a24eb6e1e1a3cdc9becd004a6419cbda3d54b4848b98f240a4829571 |

## polars-runtime-32 2.0.0

`polars_runtime_32-2.0.0-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `polars_runtime_32-2.0.0.dist-info/sboms/polars-runtime-32.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 359 components; listed, not compared

No .libs/ files.

## triton 3.8.0

skipped at 02-fetch: too_large

## ormsgpack 1.13.0

`ormsgpack-1.13.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `ormsgpack-1.13.0.dist-info/sboms/ormsgpack.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 29 components; listed, not compared

No .libs/ files.

## confluent-kafka 2.16.0

`confluent_kafka-2.16.0-cp312-cp312-manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| librdkafka-0cb94173.so.1 | — | — | — | — | not in map | — |

## ty 0.0.91

`ty-0.0.91-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `ty-0.0.91.dist-info/sboms/ty.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 306 components; listed, not compared

No .libs/ files.

## ijson 3.6.0

`ijson-3.6.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libyajl-9393e5bd.so.2.1.1 | — | — | — | — | not in map | — |

## temporalio 1.34.0

`temporalio-1.34.0-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `temporalio-1.34.0.dist-info/sboms/temporal-sdk-bridge.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 342 components; listed, not compared

No .libs/ files.

## pymssql 2.4.5

`pymssql-2.4.5-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

- `pymssql-2.4.5.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.8.2; 11 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libcom_err-730ca923.so.2.1 | libcom_err 1.45.6-7.el8_10 (pkg:rpm/almalinux/libcom_err@1.45.6-7.el8_10) | skip | — | — | not tracked | not compared: not tracked |
| libcrypto-a324fe28.so.1.1.1k | openssl-libs 1.1.1k-17.el8_6 (pkg:rpm/almalinux/openssl-libs@1.1.1k-17.el8_6) | openssl | 1.1.1k | library_string |  | agrees |
| libgssapi_krb5-abc338f9.so.2.2 | krb5-libs 1.18.2-34.el8_10 (pkg:rpm/almalinux/krb5-libs@1.18.2-34.el8_10) | krb5 | — | — | no recognizer | not compared: no recognizer |
| libk5crypto-b242bd1e.so.3.1 | krb5-libs 1.18.2-34.el8_10 (pkg:rpm/almalinux/krb5-libs@1.18.2-34.el8_10) | krb5 | — | — | no recognizer | not compared: no recognizer |
| libkeyutils-2777d33d.so.1.6 | keyutils-libs 1.5.10-9.el8 (pkg:rpm/almalinux/keyutils-libs@1.5.10-9.el8) | skip | — | — | not tracked | not compared: not tracked |
| libkrb5-d4b313c5.so.3.3 | krb5-libs 1.18.2-34.el8_10 (pkg:rpm/almalinux/krb5-libs@1.18.2-34.el8_10) | krb5 | 1.18.2 | library_string |  | agrees |
| libkrb5support-7177f7df.so.0.1 | krb5-libs 1.18.2-34.el8_10 (pkg:rpm/almalinux/krb5-libs@1.18.2-34.el8_10) | krb5 | — | — | no recognizer | not compared: no recognizer |
| libpcre2-8-516f4c9d.so.0.7.1 | pcre2 10.32-3.el8_6 (pkg:rpm/almalinux/pcre2@10.32-3.el8_6) | — | — | — | not in map | not compared: not in map |
| libselinux-81bdf592.so.1 | libselinux 2.9-11.el8_10 (pkg:rpm/almalinux/libselinux@2.9-11.el8_10) | skip | — | — | not tracked | not compared: not tracked |
| libssl-8248cfc9.so.1.1.1k | openssl-libs 1.1.1k-17.el8_6 (pkg:rpm/almalinux/openssl-libs@1.1.1k-17.el8_6) | openssl | — | — | no recognizer | not compared: no recognizer |

## opencv-python-headless 5.0.0.93

`opencv_python_headless-5.0.0.93-cp37-abi3-manylinux_2_28_x86_64.whl`

- `opencv_python_headless-5.0.0.93.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.7.0; 7 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libaom-a0d22147.so.3.14.1 | — | — | — | — | not in map | — |
| libavcodec-c4204469.so.62.28.101 | — | — | — | — | not in map | — |
| libavformat-4762a711.so.62.12.101 | — | — | — | — | not in map | — |
| libavif-43e630fc.so.16.4.2 | — | libavif | 1.4.2 | version_function_machine_code |  | — |
|  |  | aom | — | — | not detected |  |
|  |  | dav1d | — | — | not detected |  |
| libavutil-befbbc48.so.60.26.101 | — | — | — | — | not in map | — |
| libcrypto-5409cd36.so.1.1.1k | openssl-libs 1.1.1k-15.el8_6 (pkg:rpm/almalinux/openssl-libs@1.1.1k-15.el8_6) | openssl | 1.1.1k | library_string |  | agrees |
| libdrm-b0291a67.so.2.4.0 | libdrm 2.4.115-2.el8 (pkg:rpm/almalinux/libdrm@2.4.115-2.el8) | — | — | — | not in map | not compared: not in map |
| libgfortran-83c28eba.so.5.0.0 | libgfortran 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libgfortran@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |
| libopenblasp-r0-59ffcd50.3.15.so | openblas-threads 0.3.15-6.el8 (pkg:rpm/almalinux/openblas-threads@0.3.15-6.el8) | — | — | — | not in map | not compared: not in map |
| libpng16-529cb57a.so.16.58.0 | — | libpng | 1.6.58 | library_string | conflict | — |
| libquadmath-2284e583.so.0.0.0 | libquadmath 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libquadmath@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |
| libssl-81259c47.so.1.1.1k | openssl-libs 1.1.1k-15.el8_6 (pkg:rpm/almalinux/openssl-libs@1.1.1k-15.el8_6) | openssl | — | — | no recognizer | not compared: no recognizer |
| libswresample-2dfded3b.so.6.3.101 | — | — | — | — | not in map | — |
| libswscale-fe215b0b.so.9.5.101 | — | — | — | — | not in map | — |
| libvpx-4fb239ff.so.11.0.1 | — | — | — | — | not in map | — |

## nh3 0.3.7

`nh3-0.3.7-cp38-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `nh3-0.3.7.dist-info/sboms/nh3.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 78 components; listed, not compared

No .libs/ files.

## cramjam 2.14.0

`cramjam-2.14.0-cp312-cp312-manylinux_2_28_x86_64.whl`

- `cramjam-2.14.0.dist-info/sboms/cramjam-python.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 40 components; listed, not compared

No .libs/ files.

## opencv-python 5.0.0.93

`opencv_python-5.0.0.93-cp37-abi3-manylinux_2_28_x86_64.whl`

- `opencv_python-5.0.0.93.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.7.0; 25 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libQt5Core-9088e21b.so.5.15.19 | — | — | — | — | not in map | — |
| libQt5Gui-afbd4980.so.5.15.19 | — | — | — | — | not in map | — |
| libQt5Test-2553f470.so.5.15.19 | — | — | — | — | not in map | — |
| libQt5Widgets-5be2f68b.so.5.15.19 | — | — | — | — | not in map | — |
| libQt5XcbQpa-bb93e554.so.5.15.19 | — | — | — | — | not in map | — |
| libX11-xcb-b482bfde.so.1.0.0 | libX11-xcb 1.6.8-9.el8_10 (pkg:rpm/almalinux/libX11-xcb@1.6.8-9.el8_10) | — | — | — | not in map | not compared: not in map |
| libXau-154567c4.so.6.0.0 | libXau 1.0.9-3.el8 (pkg:rpm/almalinux/libXau@1.0.9-3.el8) | skip | — | — | not tracked | not compared: not tracked |
| libaom-a0d22147.so.3.14.1 | — | — | — | — | not in map | — |
| libavcodec-c4204469.so.62.28.101 | — | — | — | — | not in map | — |
| libavdevice-f388f22c.so.62.3.101 | — | — | — | — | not in map | — |
| libavfilter-8d3f2f4f.so.11.14.101 | — | — | — | — | not in map | — |
| libavformat-4762a711.so.62.12.101 | — | — | — | — | not in map | — |
| libavif-43e630fc.so.16.4.2 | — | libavif | 1.4.2 | version_function_machine_code |  | — |
|  |  | aom | — | — | not detected |  |
|  |  | dav1d | — | — | not detected |  |
| libavutil-befbbc48.so.60.26.101 | — | — | — | — | not in map | — |
| libcrypto-5409cd36.so.1.1.1k | openssl-libs 1.1.1k-15.el8_6 (pkg:rpm/almalinux/openssl-libs@1.1.1k-15.el8_6) | openssl | 1.1.1k | library_string |  | agrees |
| libdrm-b0291a67.so.2.4.0 | libdrm 2.4.115-2.el8 (pkg:rpm/almalinux/libdrm@2.4.115-2.el8) | — | — | — | not in map | not compared: not in map |
| libgfortran-83c28eba.so.5.0.0 | libgfortran 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libgfortran@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |
| libopenblasp-r0-59ffcd50.3.15.so | openblas-threads 0.3.15-6.el8 (pkg:rpm/almalinux/openblas-threads@0.3.15-6.el8) | — | — | — | not in map | not compared: not in map |
| libpcre2-16-bca4e6b3.so.0.7.1 | pcre2-utf16 10.32-3.el8_6 (pkg:rpm/almalinux/pcre2-utf16@10.32-3.el8_6) | — | — | — | not in map | not compared: not in map |
| libpng16-529cb57a.so.16.58.0 | — | libpng | 1.6.58 | library_string | conflict | — |
| libquadmath-2284e583.so.0.0.0 | libquadmath 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libquadmath@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |
| libssl-81259c47.so.1.1.1k | openssl-libs 1.1.1k-15.el8_6 (pkg:rpm/almalinux/openssl-libs@1.1.1k-15.el8_6) | openssl | — | — | no recognizer | not compared: no recognizer |
| libswresample-2dfded3b.so.6.3.101 | — | — | — | — | not in map | — |
| libswscale-fe215b0b.so.9.5.101 | — | — | — | — | not in map | — |
| libvpx-4fb239ff.so.11.0.1 | — | — | — | — | not in map | — |
| libxcb-icccm-9453e4f7.so.4.0.0 | xcb-util-wm 0.4.1-12.el8 (pkg:rpm/almalinux/xcb-util-wm@0.4.1-12.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-image-c881c1c3.so.0.0.0 | xcb-util-image 0.4.0-9.el8 (pkg:rpm/almalinux/xcb-util-image@0.4.0-9.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-keysyms-28f5419b.so.1.0.0 | xcb-util-keysyms 0.4.0-7.el8 (pkg:rpm/almalinux/xcb-util-keysyms@0.4.0-7.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-randr-562554c2.so.0.1.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-render-161c0eb5.so.0.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-render-util-f04ad2c5.so.0.0.0 | xcb-util-renderutil 0.3.9-10.el8 (pkg:rpm/almalinux/xcb-util-renderutil@0.3.9-10.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-shape-7716c890.so.0.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-shm-0be6dfbf.so.0.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-sync-e532c63b.so.1.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-util-9255dd30.so.1.0.0 | xcb-util 0.4.0-10.el8 (pkg:rpm/almalinux/xcb-util@0.4.0-10.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-xfixes-6de855b8.so.0.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-xinerama-fe4b410c.so.0.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-xkb-fd53f741.so.1.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxkbcommon-de59cad2.so.0.0.0 | libxkbcommon 0.9.1-1.el8 (pkg:rpm/almalinux/libxkbcommon@0.9.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxkbcommon-x11-27b61ed0.so.0.0.0 | libxkbcommon-x11 0.9.1-1.el8 (pkg:rpm/almalinux/libxkbcommon-x11@0.9.1-1.el8) | — | — | — | not in map | not compared: not in map |

## rignore 0.8.1

`rignore-0.8.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `rignore-0.8.1.dist-info/sboms/rignore.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 28 components; listed, not compared

No .libs/ files.

## xgboost 3.4.1

`xgboost-3.4.1-py3-none-manylinux_2_28_x86_64.whl`

- `xgboost-3.4.1.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.8.0; 2 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libgomp-e985bcbb.so.1.0.0 | libgomp 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libgomp@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |

## claude-agent-sdk 0.2.174

skipped at 02-fetch: too_large

## fastar 0.12.0

`fastar-0.12.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `fastar-0.12.0.dist-info/sboms/fastar.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 34 components; listed, not compared

No .libs/ files.

## av 19.0.2

`av-19.0.2-cp312-abi3-manylinux_2_28_x86_64.whl`

- `av-19.0.2.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.8.2; 7 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libSvtAv1Enc-cc8e453e.so.4.2.0 | — | — | — | — | not in map | — |
| libXau-154567c4.so.6.0.0 | libXau 1.0.9-3.el8 (pkg:rpm/almalinux/libXau@1.0.9-3.el8) | skip | — | — | not tracked | not compared: not tracked |
| libasound-c7818c60.so.2.0.0 | — | — | — | — | not in map | — |
| libavcodec-d61378e8.so.63.1.102 | — | — | — | — | not in map | — |
| libavdevice-c9c4901c.so.63.1.102 | — | — | — | — | not in map | — |
| libavfilter-6a4661f8.so.12.1.102 | — | — | — | — | not in map | — |
| libavformat-7f5186bf.so.63.1.102 | — | — | — | — | not in map | — |
| libavutil-8f0ab4ee.so.61.1.102 | — | — | — | — | not in map | — |
| libdav1d-0fe430b9.so.7.0.0 | — | — | — | — | not in map | — |
| libdrm-b0291a67.so.2.4.0 | libdrm 2.4.115-2.el8 (pkg:rpm/almalinux/libdrm@2.4.115-2.el8) | — | — | — | not in map | not compared: not in map |
| libgmp-8c6c054f.so.10.5.0 | — | — | — | — | not in map | — |
| libgnutls-e2125fb5.so.30.42.0 | — | — | — | — | not in map | — |
| libhogweed-e2118ea2.so.7.0 | — | — | — | — | not in map | — |
| libnettle-6eb03162.so.9.0 | — | — | — | — | not in map | — |
| libopus-114e2b1a.so.0.11.1 | — | — | — | — | not in map | — |
| libsharpyuv-48a062bd.so.0.1.2 | — | libwebp | — | — | no recognizer | — |
| libswresample-d0a74e06.so.7.1.102 | — | — | — | — | not in map | — |
| libswscale-cd7831fd.so.10.1.102 | — | — | — | — | not in map | — |
| libunistring-09f6121d.so.5.2.1 | — | — | — | — | not in map | — |
| libvmaf-258f7447.so.3.2.0 | — | — | — | — | not in map | — |
| libvpl-e4e9cae8.so.2.16 | — | — | — | — | not in map | — |
| libvpx-e67815b1.so.12.1.0 | — | — | — | — | not in map | — |
| libwebp-0c5118d0.so.7.2.0 | — | libwebp | 1.6.0 | version_function_machine_code |  | — |
| libwebpmux-e1880640.so.3.1.2 | — | libwebp | 1.6.0 | version_function_machine_code |  | — |
| libx264-d6533a8d.so.165 | — | — | — | — | not in map | — |
| libx265-eebb7db1.so.217 | — | — | — | — | not in map | — |
| libxcb-5ddf6756.so.1.1.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | skip | — | — | not tracked | not compared: not tracked |
| libxcb-shape-7716c890.so.0.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-shm-0be6dfbf.so.0.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-xfixes-6de855b8.so.0.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |

## nvidia-nccl-cu13 2.32.3

skipped at 02-fetch: too_large

## nvidia-nccl-cu12 2.32.3

skipped at 02-fetch: too_large

## nvidia-cudnn-cu13 9.27.0.42

skipped at 02-fetch: too_large

## h5py 3.16.0

`h5py-3.16.0-cp312-cp312-manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libaec-a27cf049.so.0.1.4 | — | — | — | — | not in map | — |
| libhdf5-9e18f0c6.so.320.0.0 | — | — | — | — | not in map | — |
| libhdf5_hl-69da89c9.so.320.0.0 | — | — | — | — | not in map | — |
| libsz-c6be10dd.so.2.0.1 | — | — | — | — | not in map | — |

## nvidia-cublas 13.8.1.7

skipped at 02-fetch: too_large

## nvidia-cusparselt-cu13 0.10.0

skipped at 02-fetch: too_large

## nvidia-nvshmem-cu13 3.8.0

skipped at 02-fetch: too_large

## nvidia-cufft 12.4.0.43

skipped at 02-fetch: too_large

## nvidia-cusolver 12.3.5.3

skipped at 02-fetch: too_large

## nvidia-cusparse 12.8.6.72

skipped at 02-fetch: too_large

## grimp 3.17

`grimp-3.17-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `grimp-3.17.dist-info/sboms/_rustgrimp.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 105 components; listed, not compared

No .libs/ files.

## pyproj 3.8.0

`pyproj-3.8.0-cp312-cp312-manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libcurl-27c1359b.so.4.8.0 | — | — | — | — | not in map | — |
| libnghttp2-d2324274.so.14.29.5 | — | — | — | — | not in map | — |
| libproj-bde9a34c.so.25.9.8.1 | — | — | — | — | not in map | — |
| libsqlite3-59ea7a87.so.3.53.4 | — | — | — | — | not in map | — |
| libtiff-7452557f.so.6.3.0 | — | libtiff | 4.7.2 | library_string |  | — |

## py-spy 0.4.2

`py_spy-0.4.2-py2.py3-none-manylinux_2_5_x86_64.manylinux1_x86_64.whl`

- `py_spy-0.4.2.dist-info/sboms/py-spy.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 114 components; listed, not compared

No .libs/ files.

## pybase64 1.5.1

`pybase64-1.5.1-cp312-cp312-manylinux1_x86_64.manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_5_x86_64.whl`

- `pybase64-1.5.1.dist-info/sboms/pybase64.cdx.json`: tools —; 1 component; listed, not compared

No .libs/ files.

## pillow-heif 1.8.1

`pillow_heif-1.8.1-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libde265-91206b2b.so.0.2.3 | — | — | — | — | not in map | — |
| libheif-e72ea93c.so.1.23.6 | — | — | — | — | not in map | — |
| libx265-4883ecb5.so.217 | — | — | — | — | not in map | — |

## magika 1.0.3

`magika-1.0.3-py3-none-manylinux_2_28_x86_64.whl`

- `magika-1.0.3.dist-info/sboms/magika-cli.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 96 components; listed, not compared

No .libs/ files.

## prek 0.5.7

`prek-0.5.7-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `prek-0.5.7.dist-info/sboms/prek.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 270 components; listed, not compared

No .libs/ files.

## torchvision 0.29.1

`torchvision-0.29.1-cp312-cp312-manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libcudart.faf08d9a.so.13 | — | — | — | — | not in map | — |
| libjpeg.67fb65bd.so.8 | — | libjpeg-turbo | 3.1.3 | library_string |  | — |
| libnvjpeg.36e11081.so.13 | — | — | — | — | not in map | — |
| libpng16.1d0d8f4e.so.16 | — | libpng | 1.6.56 | library_string | conflict | — |
| libsharpyuv.64944e6b.so.0 | — | libwebp | — | — | no recognizer | — |
| libwebp.bab959f1.so.7 | — | libwebp | 1.6.0 | version_function_machine_code |  | — |
| libz.915b4635.so.1 | — | — | — | — | not in map | — |

## maturin 1.15.0

`maturin-1.15.0-py3-none-manylinux_2_12_x86_64.manylinux2010_x86_64.musllinux_1_1_x86_64.whl`

- `maturin-1.15.0.dist-info/sboms/maturin.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 329 components; listed, not compared

No .libs/ files.

## uv-build 0.13.5

`uv_build-0.13.5-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `uv_build-0.13.5.dist-info/sboms/uv-build.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 243 components; listed, not compared

No .libs/ files.

## nvidia-cudnn-cu12 9.27.0.42

skipped at 02-fetch: too_large

## nvidia-cublas-cu12 12.9.2.10

skipped at 02-fetch: too_large

## deptry 0.25.1

`deptry-0.25.1-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `deptry-0.25.1.dist-info/sboms/deptryrs.cyclonedx.json`: tools cargo-cyclonedx 0.5.7; 93 components; listed, not compared

No .libs/ files.

## blake3 1.0.11

`blake3-1.0.11-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `blake3-1.0.11.dist-info/sboms/blake3.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 29 components; listed, not compared

No .libs/ files.

## nvidia-cusparse-cu12 12.5.10.65

skipped at 02-fetch: too_large

## nvidia-cusolver-cu12 11.7.5.82

skipped at 02-fetch: too_large

## nvidia-cufft-cu12 11.4.1.4

skipped at 02-fetch: too_large

## onnx 1.23.2

`onnx-1.23.2-cp312-abi3-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

- `onnx-1.23.2.dist-info/sboms/sbom.cdx.json`: tools —; 3 components; listed, not compared

No .libs/ files.

## pyogrio 0.13.0

`pyogrio-0.13.0-cp311-abi3-manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libgdal-253d08a6.so.38.3.12.4 | — | — | — | — | not in map | — |

## faiss-cpu 1.15.1

`faiss_cpu-1.15.1-cp310-abi3-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

- `faiss_cpu-1.15.1.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.6.0; 5 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libgfortran-83c28eba.so.5.0.0 | libgfortran 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libgfortran@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |
| libgomp-e985bcbb.so.1.0.0 | libgomp 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libgomp@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |
| libopenblaso-r0-d77a1985.3.15.so | openblas-openmp 0.3.15-6.el8 (pkg:rpm/almalinux/openblas-openmp@0.3.15-6.el8) | — | — | — | not in map | not compared: not in map |
| libquadmath-2284e583.so.0.0.0 | libquadmath 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libquadmath@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |

## tensorflow 2.21.0

skipped at 02-fetch: too_large

## ctranslate2 4.8.3

`ctranslate2-4.8.3-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libctranslate2-bdb19cbc.so.4.8.3 | — | — | — | — | not in map | — |
| libgomp-e985bcbb.so.1.0.0 | — | skip | — | — | not tracked | — |

## nvidia-cusparselt-cu12 0.8.1

skipped at 02-fetch: too_large

## cachebox 6.2.8

`cachebox-6.2.8-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `cachebox-6.2.8.dist-info/sboms/cachebox.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 25 components; listed, not compared

No .libs/ files.

## obstore 0.12.0

`obstore-0.12.0-cp311-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `obstore-0.12.0.dist-info/sboms/obstore.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 239 components; listed, not compared

No .libs/ files.

## memray 1.20.0

`memray-1.20.0-cp312-cp312-manylinux_2_26_x86_64.manylinux_2_28_x86_64.whl`

- `memray-1.20.0.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.7.0; 6 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libcrypto-a324fe28.so.1.1.1k | openssl-libs 1.1.1k-17.el8_6 (pkg:rpm/almalinux/openssl-libs@1.1.1k-17.el8_6) | openssl | 1.1.1k | library_string |  | agrees |
| libcurl-a1b79ec8.so.4.8.0 | — | — | — | — | not in map | — |
| libdebuginfod-0-69198410.191.so | — | — | — | — | not in map | — |
| libelf-0-c45a655c.191.so | — | — | — | — | not in map | — |
| liblz4-c23f16fe.so.1.8.3 | lz4-libs 1.8.3-5.el8_10 (pkg:rpm/almalinux/lz4-libs@1.8.3-5.el8_10) | — | — | — | not in map | not compared: not in map |
| liblzma-51a76f52.so.5.2.4 | xz-libs 5.2.4-4.el8_6 (pkg:rpm/almalinux/xz-libs@5.2.4-4.el8_6) | xz | 5.2.4 | version_function_machine_code |  | agrees |
| libssl-8248cfc9.so.1.1.1k | openssl-libs 1.1.1k-17.el8_6 (pkg:rpm/almalinux/openssl-libs@1.1.1k-17.el8_6) | openssl | — | — | no recognizer | not compared: no recognizer |
| libunwind-7e4e9a3c.so.8.0.1 | libunwind 1.3.1-3.el8 (pkg:rpm/almalinux/libunwind@1.3.1-3.el8) | — | — | — | not in map | not compared: not in map |
| libzstd-f1e133c0.so.1.5.6 | — | zstd | 1.5.6 | build_path |  | — |

## granian 2.8.5

`granian-2.8.5-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `granian-2.8.5.dist-info/sboms/granian.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 145 components; listed, not compared

No .libs/ files.

## pikepdf 10.17.0

`pikepdf-10.17.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

- `pikepdf-10.17.0.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.8.2; 2 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libjpeg-e87d2658.so.62.2.0 | libjpeg-turbo 1.5.3-14.el8_10 (pkg:rpm/almalinux/libjpeg-turbo@1.5.3-14.el8_10) | libjpeg-turbo | 1.5.3 | library_string |  | agrees |
| libqpdf-781b0270.so.30.4.2 | — | — | — | — | not in map | — |

## deltalake 1.6.6

`deltalake-1.6.6-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `deltalake-1.6.6.dist-info/sboms/deltalake-python.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 649 components; listed, not compared

No .libs/ files.

## primp 2.0.1

`primp-2.0.1-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `primp-2.0.1.dist-info/sboms/primp-python.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 237 components; listed, not compared

No .libs/ files.

## jellyfish 1.3.0

`jellyfish-1.3.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `jellyfish-1.3.0.dist-info/sboms/jellyfish.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 24 components; listed, not compared

No .libs/ files.

## python-bidi 0.6.12

`python_bidi-0.6.12-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `python_bidi-0.6.12.dist-info/sboms/python-bidi.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 14 components; listed, not compared

No .libs/ files.

## opencv-contrib-python 5.0.0.93

`opencv_contrib_python-5.0.0.93-cp37-abi3-manylinux_2_28_x86_64.whl`

- `opencv_contrib_python-5.0.0.93.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.7.0; 25 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libQt5Core-9088e21b.so.5.15.19 | — | — | — | — | not in map | — |
| libQt5Gui-afbd4980.so.5.15.19 | — | — | — | — | not in map | — |
| libQt5Test-2553f470.so.5.15.19 | — | — | — | — | not in map | — |
| libQt5Widgets-5be2f68b.so.5.15.19 | — | — | — | — | not in map | — |
| libQt5XcbQpa-bb93e554.so.5.15.19 | — | — | — | — | not in map | — |
| libX11-xcb-b482bfde.so.1.0.0 | libX11-xcb 1.6.8-9.el8_10 (pkg:rpm/almalinux/libX11-xcb@1.6.8-9.el8_10) | — | — | — | not in map | not compared: not in map |
| libXau-154567c4.so.6.0.0 | libXau 1.0.9-3.el8 (pkg:rpm/almalinux/libXau@1.0.9-3.el8) | skip | — | — | not tracked | not compared: not tracked |
| libaom-a0d22147.so.3.14.1 | — | — | — | — | not in map | — |
| libavcodec-c4204469.so.62.28.101 | — | — | — | — | not in map | — |
| libavdevice-f388f22c.so.62.3.101 | — | — | — | — | not in map | — |
| libavfilter-8d3f2f4f.so.11.14.101 | — | — | — | — | not in map | — |
| libavformat-4762a711.so.62.12.101 | — | — | — | — | not in map | — |
| libavif-43e630fc.so.16.4.2 | — | libavif | 1.4.2 | version_function_machine_code |  | — |
|  |  | aom | — | — | not detected |  |
|  |  | dav1d | — | — | not detected |  |
| libavutil-befbbc48.so.60.26.101 | — | — | — | — | not in map | — |
| libcrypto-5409cd36.so.1.1.1k | openssl-libs 1.1.1k-15.el8_6 (pkg:rpm/almalinux/openssl-libs@1.1.1k-15.el8_6) | openssl | 1.1.1k | library_string |  | agrees |
| libdrm-b0291a67.so.2.4.0 | libdrm 2.4.115-2.el8 (pkg:rpm/almalinux/libdrm@2.4.115-2.el8) | — | — | — | not in map | not compared: not in map |
| libgfortran-83c28eba.so.5.0.0 | libgfortran 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libgfortran@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |
| libopenblasp-r0-59ffcd50.3.15.so | openblas-threads 0.3.15-6.el8 (pkg:rpm/almalinux/openblas-threads@0.3.15-6.el8) | — | — | — | not in map | not compared: not in map |
| libpcre2-16-bca4e6b3.so.0.7.1 | pcre2-utf16 10.32-3.el8_6 (pkg:rpm/almalinux/pcre2-utf16@10.32-3.el8_6) | — | — | — | not in map | not compared: not in map |
| libpng16-529cb57a.so.16.58.0 | — | libpng | 1.6.58 | library_string | conflict | — |
| libquadmath-2284e583.so.0.0.0 | libquadmath 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libquadmath@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |
| libssl-81259c47.so.1.1.1k | openssl-libs 1.1.1k-15.el8_6 (pkg:rpm/almalinux/openssl-libs@1.1.1k-15.el8_6) | openssl | — | — | no recognizer | not compared: no recognizer |
| libswresample-2dfded3b.so.6.3.101 | — | — | — | — | not in map | — |
| libswscale-fe215b0b.so.9.5.101 | — | — | — | — | not in map | — |
| libvpx-4fb239ff.so.11.0.1 | — | — | — | — | not in map | — |
| libxcb-icccm-9453e4f7.so.4.0.0 | xcb-util-wm 0.4.1-12.el8 (pkg:rpm/almalinux/xcb-util-wm@0.4.1-12.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-image-c881c1c3.so.0.0.0 | xcb-util-image 0.4.0-9.el8 (pkg:rpm/almalinux/xcb-util-image@0.4.0-9.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-keysyms-28f5419b.so.1.0.0 | xcb-util-keysyms 0.4.0-7.el8 (pkg:rpm/almalinux/xcb-util-keysyms@0.4.0-7.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-randr-562554c2.so.0.1.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-render-161c0eb5.so.0.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-render-util-f04ad2c5.so.0.0.0 | xcb-util-renderutil 0.3.9-10.el8 (pkg:rpm/almalinux/xcb-util-renderutil@0.3.9-10.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-shape-7716c890.so.0.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-shm-0be6dfbf.so.0.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-sync-e532c63b.so.1.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-util-9255dd30.so.1.0.0 | xcb-util 0.4.0-10.el8 (pkg:rpm/almalinux/xcb-util@0.4.0-10.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-xfixes-6de855b8.so.0.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-xinerama-fe4b410c.so.0.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-xkb-fd53f741.so.1.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxkbcommon-de59cad2.so.0.0.0 | libxkbcommon 0.9.1-1.el8 (pkg:rpm/almalinux/libxkbcommon@0.9.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxkbcommon-x11-27b61ed0.so.0.0.0 | libxkbcommon-x11 0.9.1-1.el8 (pkg:rpm/almalinux/libxkbcommon-x11@0.9.1-1.el8) | — | — | — | not in map | not compared: not in map |

## rtree 1.4.1

`rtree-1.4.1-py3-none-manylinux_2_24_x86_64.manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libspatialindex-e5350069.so | — | — | — | — | not in map | — |

## lancedb 0.40.0

`lancedb-0.40.0-cp310-abi3-manylinux_2_28_x86_64.whl`

- `lancedb-0.40.0.dist-info/sboms/lancedb-python.cyclonedx.json`: tools cargo-cyclonedx 0.5.7; 687 components; listed, not compared

No .libs/ files.

## pyrefly 1.4.0

`pyrefly-1.4.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `pyrefly-1.4.0.dist-info/sboms/pyrefly.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 345 components; listed, not compared

No .libs/ files.

## burner-redis 0.1.7

`burner_redis-0.1.7-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `burner_redis-0.1.7.dist-info/sboms/burner-redis.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 67 components; listed, not compared

No .libs/ files.

## arro3-core 0.9.1

`arro3_core-0.9.1-cp311-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `arro3_core-0.9.1.dist-info/sboms/arro3-core.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 73 components; listed, not compared

No .libs/ files.

## scs 3.3.1

`scs-3.3.1-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

- `scs-3.3.1.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.7.0; 4 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libgfortran-83c28eba.so.5.0.0 | libgfortran 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libgfortran@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |
| libopenblas-r0-11edc3fa.3.15.so | openblas 0.3.15-6.el8 (pkg:rpm/almalinux/openblas@0.3.15-6.el8) | — | — | — | not in map | not compared: not in map |
| libquadmath-2284e583.so.0.0.0 | libquadmath 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libquadmath@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |

## python-calamine 0.9.0

`python_calamine-0.9.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `python_calamine-0.9.0.dist-info/sboms/python-calamine.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 43 components; listed, not compared

No .libs/ files.

## chromadb 1.5.9

`chromadb-1.5.9-cp39-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `chromadb-1.5.9.dist-info/sboms/chromadb_rust_bindings.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 767 components; listed, not compared

No .libs/ files.

## firecrawl-anydoc 0.2.4

`firecrawl_anydoc-0.2.4-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `firecrawl_anydoc-0.2.4.dist-info/sboms/anydoc-python.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 113 components; listed, not compared

No .libs/ files.

## ortools 9.15.6755

`ortools-9.15.6755-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libabsl_base-d77f85c8.so.2508.0.0 | — | — | — | — | not in map | — |
| libabsl_int128-26416f56.so.2508.0.0 | — | — | — | — | not in map | — |
| libabsl_log_severity-7f1a233c.so.2508.0.0 | — | — | — | — | not in map | — |
| libabsl_raw_logging_internal-7d65179c.so.2508.0.0 | — | — | — | — | not in map | — |
| libabsl_spinlock_wait-56d4a2c9.so.2508.0.0 | — | — | — | — | not in map | — |
| libabsl_string_view-6e5bb04d.so.2508.0.0 | — | — | — | — | not in map | — |
| libabsl_strings-8527cde2.so.2508.0.0 | — | — | — | — | not in map | — |
| libabsl_strings_internal-37f21a89.so.2508.0.0 | — | — | — | — | not in map | — |
| libabsl_throw_delegate-7938bcdc.so.2508.0.0 | — | — | — | — | not in map | — |

## whenever 0.11.0

`whenever-0.11.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `whenever-0.11.0.dist-info/sboms/whenever.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 15 components; listed, not compared

No .libs/ files.

## jsonschema-rs 0.60.1

`jsonschema_rs-0.60.1-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `jsonschema_rs-0.60.1.dist-info/sboms/jsonschema-py.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 205 components; listed, not compared

No .libs/ files.

## rustworkx 0.18.1

`rustworkx-0.18.1-cp310-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl`

- `rustworkx-0.18.1.dist-info/sboms/rustworkx.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 124 components; listed, not compared

No .libs/ files.

## pulp 4.2.0

`pulp-4.2.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `pulp-4.2.0.dist-info/sboms/pulp-rust-core.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 16 components; listed, not compared

No .libs/ files.

## lmnr-claude-code-proxy 0.2.0

`lmnr_claude_code_proxy-0.2.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `lmnr_claude_code_proxy-0.2.0.dist-info/sboms/cc-proxy.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 134 components; listed, not compared

No .libs/ files.

## pyqwest 0.12.0

`pyqwest-0.12.0-cp311-abi3-manylinux_2_28_x86_64.whl`

- `pyqwest-0.12.0.dist-info/sboms/pyqwest.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 207 components; listed, not compared

No .libs/ files.

## nvidia-nvshmem-cu12 3.8.0

skipped at 02-fetch: too_large

## nemo-relay 0.10.4

`nemo_relay-0.10.4-cp311-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `nemo_relay-0.10.4.dist-info/sboms/nemo-relay-python.cyclonedx.json`: tools cargo-cyclonedx 0.5.7; 421 components; listed, not compared

No .libs/ files.

## rasterio 1.5.2

`rasterio-1.5.2-cp312-cp312-manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libLerc-17aa7e54.so.4 | — | — | — | — | not in map | — |
| libaec-20f18167.so.0.1.7 | — | — | — | — | not in map | — |
| libblosc-2bdcfb88.so.1.21.6 | — | — | — | — | not in map | — |
| libcrypto-3e935f69.so.3 | — | openssl | 3.6.2 | library_string |  | — |
| libcurl-1b090cdb.so.4.8.0 | — | — | — | — | not in map | — |
| libdeflate-61867c2b.so.0 | — | — | — | — | not in map | — |
| libgdal-61394b7a.so.38.3.12.2 | — | — | — | — | not in map | — |
| libgeos-3ec8fbdb.so.3.14.1 | — | geos | — | — | no recognizer | — |
| libgeos_c-0be36666.so.1.20.5 | — | geos | 3.14.1 | library_string |  | — |
| libgif-27d51287.so.7.2.0 | — | — | — | — | not in map | — |
| libhdf5-307ef779.so.320.2.0 | — | — | — | — | not in map | — |
| libhdf5_hl-1f0804b7.so.320.0.3 | — | — | — | — | not in map | — |
| libjpeg-845ffad7.so.8.3.2 | — | libjpeg-turbo | 3.1.4 | library_string |  | — |
| libjson-c-11896cf8.so.5.4.0 | — | — | — | — | not in map | — |
| liblzma-0493143e.so.5.8.3 | — | xz | 5.8.3 | version_function_machine_code |  | — |
| libnetcdf-120a7e99.so.22 | — | — | — | — | not in map | — |
| libnghttp2-3f1aa529.so.14.29.4 | — | — | — | — | not in map | — |
| libopenjp2-41d0985a.so.2.5.4 | — | openjpeg | 2.5.4 | bare_version | needs another source | — |
| libpcre2-8-f7de90d5.so.0.15.0 | — | — | — | — | not in map | — |
| libpng16-7033bb8d.so.16.58.0 | — | libpng | 1.6.58 | library_string | conflict | — |
| libproj-00dfde79.so.25.9.8.1 | — | — | — | — | not in map | — |
| libsharpyuv-83be2868.so.0.1.2 | — | libwebp | — | — | no recognizer | — |
| libsqlite3-92e655b6.so.3.53.1 | — | — | — | — | not in map | — |
| libssl-2559e99e.so.3 | — | openssl | — | — | no recognizer | — |
| libsz-9fbed1a9.so.2.0.1 | — | — | — | — | not in map | — |
| libtiff-cb5bec6f.so.6.2.0 | — | libtiff | 4.7.1 | library_string |  | — |
| libwebp-4aaa3d40.so.7.2.0 | — | libwebp | 1.6.0 | version_function_machine_code |  | — |
| libzstd-9a32f660.so.1.5.7 | — | zstd | 1.5.7 | bare_version | needs another source | — |

## py-rust-stemmers 0.1.8

`py_rust_stemmers-0.1.8-cp312-cp312-manylinux_2_28_x86_64.whl`

- `py_rust_stemmers-0.1.8.dist-info/sboms/py_rust_stemmers.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 23 components; listed, not compared

No .libs/ files.

## pi-heif 1.4.0

`pi_heif-1.4.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libde265-90fb0ce1.so.0.2.0 | — | — | — | — | not in map | — |
| libheif-7a3e919c.so.1.23.0 | — | — | — | — | not in map | — |

## mistral-vibe 3.0.2

`mistral_vibe-3.0.2-cp312-abi3-manylinux_2_28_x86_64.whl`

- `mistral_vibe-3.0.2.dist-info/sboms/mistralai-unified-harness.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 330 components; listed, not compared

No .libs/ files.

## rdkit 2026.9.1

`rdkit-2026.9.1-cp312-cp312-manylinux_2_28_x86_64.whl`

- `rdkit-2026.9.1.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.8.2; 12 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libRDKitAbbreviations-6f2bc2cd.so.1 | — | — | — | — | not in map | — |
| libRDKitAlignment-e2fcdd9b.so.1 | — | — | — | — | not in map | — |
| libRDKitAvalonLib-71e78682.so.1 | — | — | — | — | not in map | — |
| libRDKitCIPLabeler-087b6600.so.1 | — | — | — | — | not in map | — |
| libRDKitCatalogs-2b3a3d18.so.1 | — | — | — | — | not in map | — |
| libRDKitChemDraw-9362a080.so.1 | — | — | — | — | not in map | — |
| libRDKitChemReactions-5e1777f3.so.1 | — | — | — | — | not in map | — |
| libRDKitChemTransforms-3847470e.so.1 | — | — | — | — | not in map | — |
| libRDKitChemicalFeatures-fdd25861.so.1 | — | — | — | — | not in map | — |
| libRDKitDataStructs-4c7ea332.so.1 | — | — | — | — | not in map | — |
| libRDKitDepictor-5451f8b2.so.1 | — | — | — | — | not in map | — |
| libRDKitDeprotect-774935fa.so.1 | — | — | — | — | not in map | — |
| libRDKitDescriptors-230c58dc.so.1 | — | — | — | — | not in map | — |
| libRDKitDetermineBonds-14101fb2.so.1 | — | — | — | — | not in map | — |
| libRDKitDistGeomHelpers-aa8658c4.so.1 | — | — | — | — | not in map | — |
| libRDKitDistGeometry-71545758.so.1 | — | — | — | — | not in map | — |
| libRDKitEHTLib-11dcb938.so.1 | — | — | — | — | not in map | — |
| libRDKitEigenSolvers-fc179911.so.1 | — | — | — | — | not in map | — |
| libRDKitEnumerateStereoisomers-500a09ef.so.1 | — | — | — | — | not in map | — |
| libRDKitFMCS-46b108be.so.1 | — | — | — | — | not in map | — |
| libRDKitFileParsers-bf2ffb58.so.1 | — | — | — | — | not in map | — |
| libRDKitFilterCatalog-d382e2a5.so.1 | — | — | — | — | not in map | — |
| libRDKitFingerprints-467bf19d.so.1 | — | — | — | — | not in map | — |
| libRDKitForceField-eb7ef510.so.1 | — | — | — | — | not in map | — |
| libRDKitForceFieldHelpers-85e5c410.so.1 | — | — | — | — | not in map | — |
| libRDKitFragCatalog-a70ee0a5.so.1 | — | — | — | — | not in map | — |
| libRDKitFreeSASALib-64d98149.so.1 | — | — | — | — | not in map | — |
| libRDKitGaussianShape-79668b1d.so.1 | — | — | — | — | not in map | — |
| libRDKitGeneralizedSubstruct-247548fb.so.1 | — | — | — | — | not in map | — |
| libRDKitGenericGroups-ca17d611.so.1 | — | — | — | — | not in map | — |
| libRDKitGraphMol-5c0144ed.so.1 | — | — | — | — | not in map | — |
| libRDKitInchi-00bb88cd.so.1 | — | — | — | — | not in map | — |
| libRDKitInfoTheory-fb34b174.so.1 | — | — | — | — | not in map | — |
| libRDKitMMPA-bd81df47.so.1 | — | — | — | — | not in map | — |
| libRDKitMarvinParser-e0bb84d9.so.1 | — | — | — | — | not in map | — |
| libRDKitMolAlign-ffdeffa9.so.1 | — | — | — | — | not in map | — |
| libRDKitMolCatalog-f4f79c57.so.1 | — | — | — | — | not in map | — |
| libRDKitMolChemicalFeatures-af01dce3.so.1 | — | — | — | — | not in map | — |
| libRDKitMolDraw2D-e43ba70b.so.1 | — | — | — | — | not in map | — |
| libRDKitMolEnumerator-bb9e680e.so.1 | — | — | — | — | not in map | — |
| libRDKitMolHash-6aad279f.so.1 | — | — | — | — | not in map | — |
| libRDKitMolInteractionFields-7d9a6e63.so.1 | — | — | — | — | not in map | — |
| libRDKitMolInterchange-2be3f5a9.so.1 | — | — | — | — | not in map | — |
| libRDKitMolProcessing-1811061b.so.1 | — | — | — | — | not in map | — |
| libRDKitMolStandardize-5e239f04.so.1 | — | — | — | — | not in map | — |
| libRDKitMolTransforms-022ea63c.so.1 | — | — | — | — | not in map | — |
| libRDKitO3AAlign-a474b959.so.1 | — | — | — | — | not in map | — |
| libRDKitOptimizer-8fa5089a.so.1 | — | — | — | — | not in map | — |
| libRDKitPartialCharges-c55f854b.so.1 | — | — | — | — | not in map | — |
| libRDKitPubChemShape-f21cba49.so.1 | — | — | — | — | not in map | — |
| libRDKitRDBoost-957ee757.so.1 | — | — | — | — | not in map | — |
| libRDKitRDChemDrawLib-d1869e58.so.1 | — | — | — | — | not in map | — |
| libRDKitRDChemDrawReactionLib-942ecd23.so.1 | — | — | — | — | not in map | — |
| libRDKitRDGeneral-3390a997.so.1 | — | — | — | — | not in map | — |
| libRDKitRDGeometryLib-b5097433.so.1 | — | — | — | — | not in map | — |
| libRDKitRDInchiLib-ea0a7d47.so.1 | — | — | — | — | not in map | — |
| libRDKitRDStreams-aa761236.so.1 | — | — | — | — | not in map | — |
| libRDKitRGroupDecomposition-4c2e579c.so.1 | — | — | — | — | not in map | — |
| libRDKitRascalMCES-abf3d9de.so.1 | — | — | — | — | not in map | — |
| libRDKitReducedGraphs-3bc20028.so.1 | — | — | — | — | not in map | — |
| libRDKitRingDecomposerLib-7fbea144.so.1 | — | — | — | — | not in map | — |
| libRDKitSLNParse-a10d8fa6.so.1 | — | — | — | — | not in map | — |
| libRDKitScaffoldNetwork-72fb675d.so.1 | — | — | — | — | not in map | — |
| libRDKitShapeHelpers-e2a5238c.so.1 | — | — | — | — | not in map | — |
| libRDKitSimDivPickers-12b66c92.so.1 | — | — | — | — | not in map | — |
| libRDKitSmilesParse-b10f859c.so.1 | — | — | — | — | not in map | — |
| libRDKitSubgraphs-d9673d9f.so.1 | — | — | — | — | not in map | — |
| libRDKitSubstructLibrary-beb8c797.so.1 | — | — | — | — | not in map | — |
| libRDKitSubstructMatch-adf20f28.so.1 | — | — | — | — | not in map | — |
| libRDKitSynthonSpaceSearch-69aa7370.so.1 | — | — | — | — | not in map | — |
| libRDKitTautomerQuery-d7e9d1cc.so.1 | — | — | — | — | not in map | — |
| libRDKitTrajectory-2222dfff.so.1 | — | — | — | — | not in map | — |
| libRDKitavalon_clib-53e44630.so.1 | — | — | — | — | not in map | — |
| libRDKitcoordgen-d640a7e4.so.1 | — | — | — | — | not in map | — |
| libRDKitfreesasa_clib-aaafe0f2.so.1 | — | — | — | — | not in map | — |
| libRDKitga-ce8817f6.so.1 | — | — | — | — | not in map | — |
| libRDKithc-945c619f.so.1 | — | — | — | — | not in map | — |
| libRDKitmaeparser-9b225162.so.1 | — | — | — | — | not in map | — |
| libRDKitpubchem_align3d-2be66702.so.1 | — | — | — | — | not in map | — |
| libXau-154567c4.so.6.0.0 | libXau 1.0.9-3.el8 (pkg:rpm/almalinux/libXau@1.0.9-3.el8) | skip | — | — | not tracked | not compared: not tracked |
| libboost_iostreams-a6655417.so.1.85.0 | — | — | — | — | not in map | — |
| libboost_numpy312-67106888.so.1.85.0 | — | — | — | — | not in map | — |
| libboost_python312-ed6a74e7.so.1.85.0 | — | — | — | — | not in map | — |
| libboost_random-3da82ab7.so.1.85.0 | — | — | — | — | not in map | — |
| libboost_regex-698c79a6.so.1.85.0 | — | — | — | — | not in map | — |
| libboost_serialization-bb58c08f.so.1.85.0 | — | — | — | — | not in map | — |
| libboost_wserialization-f1b355ed.so.1.85.0 | — | — | — | — | not in map | — |
| libbz2-a1e77c99.so.1.0.6 | bzip2-libs 1.0.6-28.el8_10 (pkg:rpm/almalinux/bzip2-libs@1.0.6-28.el8_10) | — | — | — | not in map | not compared: not in map |
| libcairo-dfbea965.so.2.11512.0 | cairo 1.15.12-6.el8 (pkg:rpm/almalinux/cairo@1.15.12-6.el8) | — | — | — | not in map | not compared: not in map |
| libfontconfig-dcb2ce6c.so.1.12.0 | fontconfig 2.13.1-4.el8 (pkg:rpm/almalinux/fontconfig@2.13.1-4.el8) | — | — | — | not in map | not compared: not in map |
| libfreetype-2f3b32b6.so.6.16.1 | freetype 2.9.1-10.el8_10 (pkg:rpm/almalinux/freetype@2.9.1-10.el8_10) | freetype | — | — | no recognizer | not compared: several libraries |
|  |  | bzip2 | — | — | not detected |  |
| libpixman-1-06469c37.so.0.38.4 | pixman 0.38.4-4.el8 (pkg:rpm/almalinux/pixman@0.38.4-4.el8) | — | — | — | not in map | not compared: not in map |
| libpng16-ebd1fa42.so.16.34.0 | libpng 1.6.34-11.el8_10 (pkg:rpm/almalinux/libpng@1.6.34-11.el8_10) | libpng | — | — | matches disagree; needs another source | not compared: matches disagree |
| libuuid-52ee839c.so.1.3.0 | libuuid 2.32.1-48.el8_10 (pkg:rpm/almalinux/libuuid@2.32.1-48.el8_10) | — | — | — | not in map | not compared: not in map |
| libxcb-5ddf6756.so.1.1.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | skip | — | — | not tracked | not compared: not tracked |
| libxcb-render-161c0eb5.so.0.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libxcb-shm-0be6dfbf.so.0.0.0 | libxcb 1.13.1-1.el8 (pkg:rpm/almalinux/libxcb@1.13.1-1.el8) | — | — | — | not in map | not compared: not in map |

## pygit2 1.20.1

`pygit2-1.20.1-cp312-cp312-manylinux_2_26_x86_64.manylinux_2_28_x86_64.whl`

- `pygit2-1.20.1.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.6.0; 2 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libcrypto-c81d5cc4.so.3 | — | openssl | 3.5.7 | library_string |  | — |
| libgit2-e74e15ce.so.1.9.7 | — | — | — | — | not in map | — |
| libpcre-0dd207b5.so.1.2.10 | pcre 8.42-6.el8 (pkg:rpm/almalinux/pcre@8.42-6.el8) | skip | — | — | not tracked | not compared: not tracked |
| libssh2-2a4d1765.so.1.0.1 | — | — | — | — | not in map | — |
| libssl-b2177676.so.3 | — | openssl | — | — | no recognizer | — |

## html-to-markdown 3.18.6

`html_to_markdown-3.18.6-cp310-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl`

- `html_to_markdown-3.18.6.dist-info/sboms/html-to-markdown-py.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 198 components; listed, not compared

No .libs/ files.

## tach 0.35.3

`tach-0.35.3-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `tach-0.35.3.dist-info/sboms/tach.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 280 components; listed, not compared

No .libs/ files.

## zizmor 1.31.1

`zizmor-1.31.1-py3-none-manylinux_2_28_x86_64.whl`

- `zizmor-1.31.1.dist-info/sboms/zizmor.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 328 components; listed, not compared

No .libs/ files.

## prophet 1.5.0

`prophet-1.5.0-py3-none-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libtbb-5ed6ca76.so.2 | — | — | — | — | not in map | — |

## pycurl 7.48.0

`pycurl-7.48.0-cp312-cp312-manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libbrotlicommon-779a354d.so.1.2.0 | — | brotli | — | — | no recognizer | — |
| libbrotlidec-d7d1c77e.so.1.2.0 | — | brotli | 1.2.0 | version_function_machine_code |  | — |
| libcom_err-04a6d4a9.so.3.0 | — | skip | — | — | not tracked | — |
| libcrypto-9e1a983b.so.3 | — | openssl | 3.6.4 | library_string |  | — |
| libcurl-1f5c7cda.so.4.8.0 | — | — | — | — | not in map | — |
| libgssapi_krb5-a4ee9013.so.2.2 | — | krb5 | — | — | no recognizer | — |
| libidn2-4b35c59c.so.0.4.0 | — | — | — | — | not in map | — |
| libk5crypto-b981dde7.so.3.1 | — | krb5 | — | — | no recognizer | — |
| libkrb5-d2bd9c2b.so.3.3 | — | krb5 | 1.22.2 | library_string |  | — |
| libkrb5support-4c5795d1.so.0.1 | — | krb5 | — | — | no recognizer | — |
| libnghttp2-3dab5618.so.14.29.5 | — | — | — | — | not in map | — |
| libnghttp3-d4b9d539.so.9.9.0 | — | — | — | — | not in map | — |
| libngtcp2-23491f47.so.16.11.0 | — | — | — | — | not in map | — |
| libngtcp2_crypto_ossl-741c35a5.so.0.3.1 | — | — | — | — | not in map | — |
| libpsl-8d3f0618.so.5.3.5 | — | — | — | — | not in map | — |
| libsfparse-e1f35c00.so | — | — | — | — | not in map | — |
| libssh2-c5c93677.so.1.0.1 | — | — | — | — | not in map | — |
| libssl-e79d478f.so.3 | — | openssl | — | — | no recognizer | — |
| libunistring-dfbe0280.so.5.1.0 | — | — | — | — | not in map | — |

## pinecone 10.2.0

`pinecone-10.2.0-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `pinecone-10.2.0.dist-info/sboms/pinecone-grpc.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 111 components; listed, not compared

No .libs/ files.

## ua-parser-rs 0.1.5

`ua_parser_rs-0.1.5-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `ua_parser_rs-0.1.5.dist-info/sboms/ua-parser-rs.cyclonedx.json`: tools cargo-cyclonedx 0.5.7; 31 components; listed, not compared

No .libs/ files.

## cassandra-driver 3.30.1

`cassandra_driver-3.30.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libev-aeeccda2.so.4.0.0 | — | — | — | — | not in map | — |

## pyiceberg-core 0.10.1

`pyiceberg_core-0.10.1-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `pyiceberg_core-0.10.1.dist-info/sboms/pyiceberg_core_rust.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 542 components; listed, not compared

No .libs/ files.

## statsig-python-core 0.23.2

`statsig_python_core-0.23.2-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `statsig_python_core-0.23.2.dist-info/sboms/statsig-pyo3.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 392 components; listed, not compared

No .libs/ files.

## tzfpy 2.1.1

`tzfpy-2.1.1-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `tzfpy-2.1.1.dist-info/sboms/tzfpy.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 27 components; listed, not compared

No .libs/ files.

## mitmproxy-rs 0.12.15

`mitmproxy_rs-0.12.15-cp312-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `mitmproxy_rs-0.12.15.dist-info/sboms/mitmproxy_rs.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 337 components; listed, not compared

No .libs/ files.

## regress 2026.9.1

`regress-2026.9.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `regress-2026.9.1.dist-info/sboms/regress-py.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 15 components; listed, not compared

No .libs/ files.

## protobuf-py-ext 0.7.0

`protobuf_py_ext-0.7.0-cp311-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `protobuf_py_ext-0.7.0.dist-info/sboms/protobuf-py-ext.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 52 components; listed, not compared

No .libs/ files.

## simsimd 6.5.16

`simsimd-6.5.16-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl`

- `simsimd-6.5.16.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.6.0; 2 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libgomp-e985bcbb.so.1.0.0 | libgomp 8.5.0-28.el8_10.alma.1 (pkg:rpm/almalinux/libgomp@8.5.0-28.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |

## pydantic-monty-runtime 1.3.0

`pydantic_monty_runtime-1.3.0-py3-none-manylinux_2_28_x86_64.whl`

- `pydantic_monty_runtime-1.3.0.dist-info/sboms/monty-runtime.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 324 components; listed, not compared

No .libs/ files.

## vtk 9.7.1

skipped at 02-fetch: too_large

## torchcodec 0.17.0

`torchcodec-0.17.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libavif-e4168294.so.16.4.2 | — | libavif | 1.4.2 | version_function_machine_code |  | — |
|  |  | aom | — | — | not detected |  |
|  |  | dav1d | 1.5.3 | version_function_machine_code |  |  |
| libjpeg-944920e9.so.8.3.2 | — | libjpeg-turbo | 3.1.3 | library_string |  | — |
| libnvjpeg-1a359ba7.so.13.0.1.86 | — | — | — | — | not in map | — |
| libpng16-37856f38.so.16.58.0 | — | libpng | 1.6.58 | library_string | conflict | — |
| libsharpyuv-ec3ccc1d.so.0.1.2 | — | libwebp | — | — | no recognizer | — |
| libwebp-71252730.so.7.2.0 | — | libwebp | 1.6.0 | version_function_machine_code |  | — |
| libwebpdemux-f71da224.so.2.0.17 | — | libwebp | 1.6.0 | version_function_machine_code |  | — |

## fiona 1.10.1

`fiona-1.10.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libsqlite3-fiona-83998bda.so.0.8.6 | — | — | — | — | not in map | — |
| libcrypto-fiona-2769ca46.so.1.1 | — | — | — | — | not in map | — |
| libjson-c-fiona-b8129721.so.5.1.0 | — | — | — | — | not in map | — |
| libgdal-fiona-e8f6bdb0.so.35.3.9.2 | — | — | — | — | not in map | — |
| liblzma-fiona-c949e524.so.5.2.2 | — | — | — | — | not in map | — |
| libnghttp2-fiona-e183d352.so.14.21.1 | — | — | — | — | not in map | — |
| libgeos_c-fiona-3b303efa.so.1.17.2 | — | — | — | — | not in map | — |
| libcurl-fiona-1d984654.so.4.8.0 | — | — | — | — | not in map | — |
| libgeos-fiona-d914d573.so.3.11.2 | — | — | — | — | not in map | — |
| libjpeg-fiona-320f4797.so.9.6.0 | — | — | — | — | not in map | — |
| libssl-fiona-6c758070.so.1.1 | — | — | — | — | not in map | — |
| libpng16-fiona-8ebcc106.so.16.35.0 | — | — | — | — | not in map | — |
| libproj-fiona-3ec30893.so.25.9.4.1 | — | — | — | — | not in map | — |
| libtiff-fiona-c967de8d.so.5.7.0 | — | — | — | — | not in map | — |
| libpcre2-8-fiona-221be7d6.so.0.13.0 | — | — | — | — | not in map | — |

## netcdf4 1.7.5.1.post1

`netcdf4-1.7.5.1.post1-cp311-abi3-manylinux_2_28_x86_64.whl`

- `netcdf4-1.7.5.1.post1.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.8.2; 2 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libaec-258f12cf.so.0.1.4 | — | — | — | — | not in map | — |
| libblosc-a3c021bc.so.1.21.6 | — | — | — | — | not in map | — |
| libbz2-a1e77c99.so.1.0.6 | bzip2-libs 1.0.6-28.el8_10 (pkg:rpm/almalinux/bzip2-libs@1.0.6-28.el8_10) | — | — | — | not in map | not compared: not in map |
| libcrypto-5d63cd29.so.3 | — | openssl | 3.5.1 | library_string |  | — |
| libcurl-7f1692d5.so.4.8.0 | — | — | — | — | not in map | — |
| libhdf5-34cf00cd.so.320.2.0 | — | — | — | — | not in map | — |
| libhdf5_hl-d4b518f2.so.320.0.3 | — | — | — | — | not in map | — |
| libnetcdf-3622e713.so.22 | — | — | — | — | not in map | — |
| libssl-a140065d.so.3 | — | openssl | — | — | no recognizer | — |
| libsz-494d9daa.so.2.0.1 | — | — | — | — | not in map | — |
| libzstd-3084d8a0.so.1.5.7 | — | zstd | 1.5.7 | bare_version | needs another source | — |

## openlineage-sql 1.54.0

`openlineage_sql-1.54.0-cp310-abi3-manylinux_2_28_x86_64.whl`

- `openlineage_sql-1.54.0.dist-info/sboms/openlineage_sql_python.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 31 components; listed, not compared

No .libs/ files.

## fastexcel 0.21.0

`fastexcel-0.21.0-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `fastexcel-0.21.0.dist-info/sboms/fastexcel.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 123 components; listed, not compared

No .libs/ files.

## ast-grep-cli 0.51.0

`ast_grep_cli-0.51.0-py3-none-manylinux_2_28_x86_64.whl`

- `ast_grep_cli-0.51.0.dist-info/sboms/ast-grep.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 227 components; listed, not compared

No .libs/ files.

## css-inline 0.23.0

`css_inline-0.23.0-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `css_inline-0.23.0.dist-info/sboms/css-inline-python.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 157 components; listed, not compared

No .libs/ files.

## lingua-language-detector 2.2.0

skipped at 02-fetch: too_large

## toons 0.9.0

`toons-0.9.0-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `toons-0.9.0.dist-info/sboms/toons.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 13 components; listed, not compared

No .libs/ files.

## pydantic-monty-client 1.3.0

`pydantic_monty_client-1.3.0-cp312-cp312-manylinux_2_28_x86_64.whl`

- `pydantic_monty_client-1.3.0.dist-info/sboms/pydantic-monty-client.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 356 components; listed, not compared

No .libs/ files.

## igraph 1.0.0

`igraph-1.0.0-cp39-abi3-manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libgomp-e985bcbb.so.1.0.0 | — | skip | — | — | not tracked | — |
| liblzma-51a76f52.so.5.2.4 | — | xz | 5.2.4 | version_function_machine_code |  | — |
| libxml2-39f609e7.so.2.9.7 | — | — | — | — | not in map | — |

## loro 1.17.1

`loro-1.17.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `loro-1.17.1.dist-info/sboms/loro_py.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 128 components; listed, not compared

No .libs/ files.

## tibs 2.0.2

`tibs-2.0.2-cp311-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `tibs-2.0.2.dist-info/sboms/tibs.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 43 components; listed, not compared

No .libs/ files.

## pycrdt 0.14.10

`pycrdt-0.14.10-cp311-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `pycrdt-0.14.10.dist-info/sboms/pycrdt.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 42 components; listed, not compared

No .libs/ files.

## chroma-hnswlib 0.7.6

`chroma_hnswlib-0.7.6-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libgomp-a34b3233.so.1.0.0 | — | skip | — | — | not tracked | — |

## resvg-py 0.5.0

`resvg_py-0.5.0-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `resvg_py-0.5.0.dist-info/sboms/resvg_py.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 74 components; listed, not compared

No .libs/ files.

## pygame 2.6.1

`pygame-2.6.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libSDL2_ttf-2-e6bdbc24.0.so.0.2000.1 | — | — | — | — | not in map | — |
| liblz4-af1653fb.so.1.8.3 | — | — | — | — | not in map | — |
| libmpg123-fad61782.so.0.47.0 | — | — | — | — | not in map | — |
| libharfbuzz-f991c6ff.so.0.50100.0 | — | harfbuzz | 5.1.0 | version_function_machine_code |  | — |
| libpulsecommon-14-80414fd3.2.so | — | — | — | — | not in map | — |
| libsharpyuv-5ed6246f.so.0.0.1 | — | libwebp | — | — | no recognizer | — |
| libfluidsynth-3137fad6.so.3.1.1 | — | — | — | — | not in map | — |
| libpng16-bb793e21.so.16.37.0 | — | libpng | 1.6.37 | library_string | conflict | — |
| libgpg-error-3f09c3c7.so.0.10.0 | — | — | — | — | not in map | — |
| libsystemd-7fd64813.so.0.6.0 | — | — | — | — | not in map | — |
| libbz2-a273e504.so.1.0.6 | — | — | — | — | not in map | — |
| libtiff-23a934bd.so.5.8.0 | — | libtiff | 4.4.0 | library_string |  | — |
| libelf-0-3d9de92a.176.so | — | — | — | — | not in map | — |
| libopus-56ba99ed.so.0.8.0 | — | — | — | — | not in map | — |
| libSDL2_image-2-6bbdaa8d.0.so.0.2.3 | — | — | — | — | not in map | — |
| libpcre-9513aab5.so.1.2.0 | — | skip | — | — | not tracked | — |
| libgomp-a34b3233.so.1.0.0 | — | skip | — | — | not tracked | — |
| libpulse-simple-4ba3beb5.so.0.1.1 | — | — | — | — | not in map | — |
| libjpeg-4617cdcb.so.62.3.0 | — | libjpeg-turbo | 2.1.4 | library_string |  | — |
| libportmidi-6df3607d.so.2.0.3 | — | — | — | — | not in map | — |
| libpulse-5b5d1e90.so.0.23.0 | — | — | — | — | not in map | — |
| libselinux-0922c95c.so.1 | — | skip | — | — | not tracked | — |
| libasound-d80805e8.so.2.0.0 | — | — | — | — | not in map | — |
| libdw-0-780627ce.176.so | — | — | — | — | not in map | — |
| libbrotlicommon-f54d67a1.so.1.0.9 | — | brotli | — | — | no recognizer | — |
| libFLAC-c5c6b3bc.so.8.3.0 | — | — | — | — | not in map | — |
| libvorbisenc-bb396c4a.so.2.0.12 | — | — | — | — | not in map | — |
| libfreetype-402bc0e3.so.6.18.3 | — | freetype | — | — | no recognizer | — |
|  |  | bzip2 | — | — | not detected |  |
| libcap-79733b59.so.2.22 | — | — | — | — | not in map | — |
| libopusfile-df4005ff.so.0.4.5 | — | — | — | — | not in map | — |
| libsndfile-2f719936.so.1.0.34 | — | — | — | — | not in map | — |
| libSDL2-2-1667c208.0.so.0.2800.4 | — | — | — | — | not in map | — |
| libvorbis-ac399090.so.0.4.9 | — | — | — | — | not in map | — |
| libdbus-1-5d678da9.so.3.14.14 | — | — | — | — | not in map | — |
| libvorbisfile-8aced0b7.so.3.3.8 | — | — | — | — | not in map | — |
| libSDL2_mixer-2-673d03d7.0.so.0.600.3 | — | — | — | — | not in map | — |
| libattr-4f2a9577.so.1.1.0 | — | — | — | — | not in map | — |
| liblzma-004595ca.so.5.2.2 | — | xz | 5.2.2 | version_function_machine_code |  | — |
| libogg-3f4a1572.so.0.8.5 | — | — | — | — | not in map | — |
| libbrotlidec-ffc423df.so.1.0.9 | — | brotli | 1.0.9 | version_function_machine_code |  | — |
| libwebp-3bee5bfa.so.7.1.8 | — | libwebp | 1.3.2 | version_function_machine_code |  | — |
| libgcrypt-18957bae.so.11.8.2 | — | — | — | — | not in map | — |

## vllm 0.32.0

skipped at 02-fetch: too_large

## onnxruntime-gpu 1.31.0

skipped at 02-fetch: too_large

## kornia-rs 0.2.0

`kornia_rs-0.2.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `kornia_rs-0.2.0.dist-info/sboms/kornia-py.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 278 components; listed, not compared

No .libs/ files.

## impit 0.15.1

`impit-0.15.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `impit-0.15.1.dist-info/sboms/impit-python.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 252 components; listed, not compared

No .libs/ files.

## pillow-avif-plugin 1.6.0

`pillow_avif_plugin-1.6.0-cp312-cp312-manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libavif-e62bed49.so.16.4.2 | — | libavif | 1.4.2 | version_function_machine_code |  | — |
|  |  | aom | 3.14.1 | library_string |  |  |
|  |  | dav1d | 1.5.3 | version_function_machine_code |  |  |

## qh3 2.0.4

`qh3-2.0.4-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `qh3-2.0.4.dist-info/sboms/qh3.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 166 components; listed, not compared

No .libs/ files.

## oai-statsig-python-core 0.37.0

`oai_statsig_python_core-0.37.0-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `oai_statsig_python_core-0.37.0.dist-info/sboms/statsig-pyo3.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 374 components; listed, not compared

No .libs/ files.

## tantivy 0.27.0

`tantivy-0.27.0-cp311-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `tantivy-0.27.0.dist-info/sboms/tantivy.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 139 components; listed, not compared

No .libs/ files.

## chdb-core 26.9.0

skipped at 02-fetch: too_large

## kernels 0.17.2

`kernels-0.17.2-cp38-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `kernels-0.17.2.dist-info/sboms/kernels-python.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 90 components; listed, not compared

No .libs/ files.

## tables 3.11.1

`tables-3.11.1-cp311-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl`

- `tables-3.11.1.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.6.0; 2 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libblosc2-a12ec544.so.7 | — | — | — | — | not in map | — |
| libbz2-a1e77c99.so.1.0.6 | bzip2-libs 1.0.6-28.el8_10 (pkg:rpm/almalinux/bzip2-libs@1.0.6-28.el8_10) | — | — | — | not in map | not compared: not in map |
| libhdf5-b93485fa.so.310.5.1 | — | — | — | — | not in map | — |

## connectorx 0.4.6

`connectorx-0.4.6-cp312-cp312-manylinux_2_28_x86_64.whl`

- `connectorx-0.4.6.dist-info/sboms/auditwheel.cdx.json`: tools maturin 1.15.0; 3 components; listed, not compared
- `connectorx-0.4.6.dist-info/sboms/connectorx-python.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 698 components; listed, not compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libcom_err-718799e4.so.3 | — | skip | — | — | not tracked | — |
| libcrypto-2a0563c8.so.3 | — | openssl | 3.5.5 | library_string |  | — |
| libgssapi_krb5-744d7fed.so.2 | — | krb5 | — | — | no recognizer | — |
| libk5crypto-22a3d436.so.3 | — | krb5 | — | — | no recognizer | — |
| libkeyutils-2777d33d.so.1 | — | skip | — | — | not tracked | — |
| libkrb5-b940c9ab.so.3 | — | krb5 | 1.22.2 | library_string |  | — |
| libkrb5support-79e678bc.so.0 | — | krb5 | — | — | no recognizer | — |

## hogql-parser 1.3.88

`hogql_parser-1.3.88-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

No SBOM files.

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libantlr4-runtime-213309cc.so.4.13.1 | — | — | — | — | not in map | — |

## hogql-parser-rs 1.3.112

`hogql_parser_rs-1.3.112-cp312-abi3-manylinux_2_28_x86_64.whl`

- `hogql_parser_rs-1.3.112.dist-info/sboms/hogql_parser_rs.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 18 components; listed, not compared

No .libs/ files.

## pixelhog 1.3.1

`pixelhog-1.3.1-cp312-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `pixelhog-1.3.1.dist-info/sboms/pixelhog-python.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 44 components; listed, not compared

No .libs/ files.

## deltalite 0.1.15

`deltalite-0.1.15-cp312-abi3-manylinux_2_28_x86_64.whl`

- `deltalite-0.1.15.dist-info/sboms/deltalite-python.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 402 components; listed, not compared

No .libs/ files.

## solders 0.29.0

`solders-0.29.0-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `solders-0.29.0.dist-info/sboms/solders.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 439 components; listed, not compared

No .libs/ files.

## rust-just 1.59.0

`rust_just-1.59.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`

- `rust_just-1.59.0.dist-info/sboms/just.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 97 components; listed, not compared

No .libs/ files.

## cadquery-ocp 8.0.1.1.0

`cadquery_ocp-8.0.1.1.0-cp312-cp312-manylinux_2_28_x86_64.whl`

- `cadquery_ocp-8.0.1.1.0.dist-info/sboms/auditwheel.cdx.json`: tools auditwheel 6.8.2; 25 components; compared

| file | component | library | version | basis | note | comparison |
|---|---|---|---|---|---|---|
| libHalf-5862efe9.so.12.0.0 | ilmbase 2.2.0-13.el8 (pkg:rpm/almalinux/ilmbase@2.2.0-13.el8) | — | — | — | not in map | not compared: not in map |
| libIex-2_2-8dec6053.so.12.0.0 | ilmbase 2.2.0-13.el8 (pkg:rpm/almalinux/ilmbase@2.2.0-13.el8) | — | — | — | not in map | not compared: not in map |
| libIexMath-2_2-78da3f71.so.12.0.0 | ilmbase 2.2.0-13.el8 (pkg:rpm/almalinux/ilmbase@2.2.0-13.el8) | — | — | — | not in map | not compared: not in map |
| libIlmImf-2_2-b6a9e6d2.so.22.0.0 | OpenEXR-libs 2.2.0-12.el8_10.1 (pkg:rpm/almalinux/OpenEXR-libs@2.2.0-12.el8_10.1) | — | — | — | not in map | not compared: not in map |
| libIlmThread-2_2-df9f9db2.so.12.0.0 | ilmbase 2.2.0-13.el8 (pkg:rpm/almalinux/ilmbase@2.2.0-13.el8) | — | — | — | not in map | not compared: not in map |
| libImath-2_2-e63a2f25.so.12.0.0 | ilmbase 2.2.0-13.el8 (pkg:rpm/almalinux/ilmbase@2.2.0-13.el8) | — | — | — | not in map | not compared: not in map |
| libTKBO-7e3d8ce0.so.8.0.1 | — | — | — | — | not in map | — |
| libTKBRep-6da95aa3.so.8.0.1 | — | — | — | — | not in map | — |
| libTKBin-b5794680.so.8.0.1 | — | — | — | — | not in map | — |
| libTKBinL-29dbe5a0.so.8.0.1 | — | — | — | — | not in map | — |
| libTKBinTObj-02137f0e.so.8.0.1 | — | — | — | — | not in map | — |
| libTKBinXCAF-a6f5ecdd.so.8.0.1 | — | — | — | — | not in map | — |
| libTKBool-d0b588ae.so.8.0.1 | — | — | — | — | not in map | — |
| libTKCAF-91c56915.so.8.0.1 | — | — | — | — | not in map | — |
| libTKCDF-efdf2e90.so.8.0.1 | — | — | — | — | not in map | — |
| libTKDE-a81b0fcb.so.8.0.1 | — | — | — | — | not in map | — |
| libTKDECascade-37837275.so.8.0.1 | — | — | — | — | not in map | — |
| libTKDEGLTF-981a1651.so.8.0.1 | — | — | — | — | not in map | — |
| libTKDEIGES-5ffd095a.so.8.0.1 | — | — | — | — | not in map | — |
| libTKDEOBJ-ae27eefb.so.8.0.1 | — | — | — | — | not in map | — |
| libTKDEPLY-90ebb982.so.8.0.1 | — | — | — | — | not in map | — |
| libTKDESTEP-d86a398d.so.8.0.1 | — | — | — | — | not in map | — |
| libTKDESTL-c80d4d57.so.8.0.1 | — | — | — | — | not in map | — |
| libTKDEVRML-22ed132b.so.8.0.1 | — | — | — | — | not in map | — |
| libTKExpress-e59880f8.so.8.0.1 | — | — | — | — | not in map | — |
| libTKFeat-25898fc6.so.8.0.1 | — | — | — | — | not in map | — |
| libTKFillet-4009f035.so.8.0.1 | — | — | — | — | not in map | — |
| libTKG2d-3cc06106.so.8.0.1 | — | — | — | — | not in map | — |
| libTKG3d-6e7f31a9.so.8.0.1 | — | — | — | — | not in map | — |
| libTKGeomAlgo-92c8e470.so.8.0.1 | — | — | — | — | not in map | — |
| libTKGeomBase-c01ccccb.so.8.0.1 | — | — | — | — | not in map | — |
| libTKHLR-72102384.so.8.0.1 | — | — | — | — | not in map | — |
| libTKHelix-095081c7.so.8.0.1 | — | — | — | — | not in map | — |
| libTKIVtk-8e5b2874.so.8.0.1 | — | — | — | — | not in map | — |
| libTKLCAF-a8583cfe.so.8.0.1 | — | — | — | — | not in map | — |
| libTKMath-75bf3d53.so.8.0.1 | — | — | — | — | not in map | — |
| libTKMesh-cad1aa38.so.8.0.1 | — | — | — | — | not in map | — |
| libTKMeshVS-c8ca36a4.so.8.0.1 | — | — | — | — | not in map | — |
| libTKOffset-0cc8e253.so.8.0.1 | — | — | — | — | not in map | — |
| libTKOpenGl-d7fcc1de.so.8.0.1 | — | — | — | — | not in map | — |
| libTKPrim-33683fd2.so.8.0.1 | — | — | — | — | not in map | — |
| libTKRWMesh-80eced57.so.8.0.1 | — | — | — | — | not in map | — |
| libTKService-ce937e62.so.8.0.1 | — | — | — | — | not in map | — |
| libTKShHealing-4d055e25.so.8.0.1 | — | — | — | — | not in map | — |
| libTKStd-0c10c9e1.so.8.0.1 | — | — | — | — | not in map | — |
| libTKStdL-33ff7077.so.8.0.1 | — | — | — | — | not in map | — |
| libTKTObj-2b5196fc.so.8.0.1 | — | — | — | — | not in map | — |
| libTKTopAlgo-18265c89.so.8.0.1 | — | — | — | — | not in map | — |
| libTKV3d-92e92ec9.so.8.0.1 | — | — | — | — | not in map | — |
| libTKVCAF-0e39e127.so.8.0.1 | — | — | — | — | not in map | — |
| libTKXCAF-8b68a406.so.8.0.1 | — | — | — | — | not in map | — |
| libTKXMesh-7a7147e4.so.8.0.1 | — | — | — | — | not in map | — |
| libTKXSBase-75e88183.so.8.0.1 | — | — | — | — | not in map | — |
| libTKXml-fc2e52d6.so.8.0.1 | — | — | — | — | not in map | — |
| libTKXmlL-3b32ee94.so.8.0.1 | — | — | — | — | not in map | — |
| libTKXmlTObj-38b35f12.so.8.0.1 | — | — | — | — | not in map | — |
| libTKXmlXCAF-8a556a20.so.8.0.1 | — | — | — | — | not in map | — |
| libTKernel-b8621df7.so.8.0.1 | — | — | — | — | not in map | — |
| libbz2-a1e77c99.so.1.0.6 | bzip2-libs 1.0.6-28.el8_10 (pkg:rpm/almalinux/bzip2-libs@1.0.6-28.el8_10) | — | — | — | not in map | not compared: not in map |
| libfmt-8375f6bf.so.6.2.1 | fmt 6.2.1-1.el8 (pkg:rpm/almalinux/fmt@6.2.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libfontconfig-dcb2ce6c.so.1.12.0 | fontconfig 2.13.1-4.el8 (pkg:rpm/almalinux/fontconfig@2.13.1-4.el8) | — | — | — | not in map | not compared: not in map |
| libfreeimage-3-69ba4c2d.17.0.so | freeimage 3.17.0-5.el8 (pkg:rpm/almalinux/freeimage@3.17.0-5.el8) | — | — | — | not in map | not compared: not in map |
| libfreetype-2f3b32b6.so.6.16.1 | freetype 2.9.1-10.el8_10 (pkg:rpm/almalinux/freetype@2.9.1-10.el8_10) | freetype | — | — | no recognizer | not compared: several libraries |
|  |  | bzip2 | — | — | not detected |  |
| libgomp-6a29c32d.so.1.0.0 | libgomp 8.5.0-29.el8_10.alma.1 (pkg:rpm/almalinux/libgomp@8.5.0-29.el8_10.alma.1) | skip | — | — | not tracked | not compared: not tracked |
| libjasper-61dc4fbf.so.4.0.0 | jasper-libs 2.0.14-6.el8_10 (pkg:rpm/almalinux/jasper-libs@2.0.14-6.el8_10) | — | — | — | not in map | not compared: not in map |
| libjpeg-e87d2658.so.62.2.0 | libjpeg-turbo 1.5.3-14.el8_10 (pkg:rpm/almalinux/libjpeg-turbo@1.5.3-14.el8_10) | libjpeg-turbo | 1.5.3 | library_string |  | agrees |
| libjpegxr-d3532616.so.0.0.0 | jxrlib 1.1-1.el8 (pkg:rpm/almalinux/jxrlib@1.1-1.el8) | — | — | — | not in map | not compared: not in map |
| libjxrglue-9249a84a.so.0.0.0 | jxrlib 1.1-1.el8 (pkg:rpm/almalinux/jxrlib@1.1-1.el8) | — | — | — | not in map | not compared: not in map |
| liblcms2-2a3d7c52.so.2.0.8 | lcms2 2.9-2.el8 (pkg:rpm/almalinux/lcms2@2.9-2.el8) | lcms2 | 2.9.0 | version_function_machine_code |  | differs |
| liblzma-51a76f52.so.5.2.4 | xz-libs 5.2.4-4.el8_6 (pkg:rpm/almalinux/xz-libs@5.2.4-4.el8_6) | xz | 5.2.4 | version_function_machine_code |  | agrees |
| libopenjp2-88dcb7ba.so.2.4.0 | openjpeg2 2.4.0-5.el8 (pkg:rpm/almalinux/openjpeg2@2.4.0-5.el8) | openjpeg | — | — | not detected | not compared: not detected |
| libpng16-ebd1fa42.so.16.34.0 | libpng 1.6.34-11.el8_10 (pkg:rpm/almalinux/libpng@1.6.34-11.el8_10) | libpng | — | — | matches disagree; needs another source | not compared: matches disagree |
| libraw-37b1f733.so.19.0.2 | LibRaw 0.19.5-6.el8_10 (pkg:rpm/almalinux/LibRaw@0.19.5-6.el8_10) | — | — | — | not in map | not compared: not in map |
| libtiff-92a88e40.so.5.3.0 | — | libtiff | 4.0.9 | library_string |  | — |
| libuuid-52ee839c.so.1.3.0 | libuuid 2.32.1-48.el8_10 (pkg:rpm/almalinux/libuuid@2.32.1-48.el8_10) | — | — | — | not in map | not compared: not in map |
| libwebp-78a6964e.so.7.0.2 | libwebp 1.0.0-11.el8_10 (pkg:rpm/almalinux/libwebp@1.0.0-11.el8_10) | libwebp | 1.0.0 | version_function_machine_code |  | agrees |
| libwebpmux-489e612a.so.3.0.2 | libwebp 1.0.0-11.el8_10 (pkg:rpm/almalinux/libwebp@1.0.0-11.el8_10) | libwebp | 1.0.0 | version_function_machine_code |  | agrees |

## daft 0.7.26

`daft-0.7.26-cp310-abi3-manylinux_2_24_x86_64.whl`

- `daft-0.7.26.dist-info/sboms/daft.cyclonedx.json`: tools cargo-cyclonedx 0.5.9; 720 components; listed, not compared

No .libs/ files.
