import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from pypiscan.nvd import (
    PAUSE_SECONDS,
    NvdError,
    Pacer,
    candidates,
    scope,
)
from pypiscan.pypi import PyPIError
from pypiscan.scan import Library, Result, cves_phase

# NVD's answer to cves/2.0?cveId=CVE-2023-4863, recorded on 2026-10-18.
RECORDED = Path(__file__).with_name("nvd") / "CVE-2023-4863.json"
API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WEBP = "webmproject:libwebp"


def url(name: str, start: int = 0) -> str:
    return (
        f"{API}?virtualMatchString=cpe:2.3:a:{name}"
        f"&resultsPerPage=2000&startIndex={start}"
    )


class Client:
    """Serves each URL's body, or raises PyPIError for a missing one."""

    def __init__(self, pages: dict[str, bytes]) -> None:
        self.pages = pages
        self.requested: list[str] = []

    def stream(self, url: str) -> Iterator[bytes]:
        self.requested.append(url)
        if url not in self.pages:
            raise PyPIError(f"{url}: HTTP 404")
        body = self.pages[url]
        yield body[:7]
        yield body[7:]


def page(
    *cves: dict[str, object], total: int | None = None, stamp: str = "T1"
) -> bytes:
    return json.dumps(
        {
            "resultsPerPage": len(cves),
            "startIndex": 0,
            "totalResults": len(cves) if total is None else total,
            "timestamp": stamp,
            "vulnerabilities": [{"cve": c} for c in cves],
        }
    ).encode()


def metric(version: str, score: object, label: str, source: str = "s") -> object:
    data = {"version": version, "baseScore": score, "baseSeverity": label}
    return {"source": source, "type": "Primary", "cvssData": data}


def match(name: str, **fields: str) -> dict[str, object]:
    entry: dict[str, object] = {
        "vulnerable": True,
        "criteria": f"cpe:2.3:a:{name}:*:*:*:*:*:*:*:*",
    }
    return entry | fields


def cve(
    cve_id: str,
    published: str = "2023-01-01T00:00:00.000",
    metrics: dict[str, object] | None = None,
    matches: list[dict[str, object]] | None = None,
    **fields: object,
) -> dict[str, object]:
    return {
        "id": cve_id,
        "published": published,
        "lastModified": "2026-01-01T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {"lang": "es", "value": "uno"},
            {"lang": "en", "value": "one"},
        ],
        "metrics": {"cvssMetricV31": [metric("3.1", 9.8, "CRITICAL")]}
        if metrics is None
        else metrics,
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": matches or []}]}],
        "references": [],
    } | fields


def listed(data: dict[str, object]) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], data["candidates"])


def run(
    pages: dict[str, bytes], names: list[str]
) -> tuple[dict[str, object], Client, list[float]]:
    client = Client(pages)
    slept: list[float] = []
    return candidates(client, names, Pacer(slept.append)), client, slept


def test_recorded_cve_2023_4863() -> None:
    data, client, slept = run({url(WEBP): RECORDED.read_bytes()}, [WEBP])
    assert client.requested == [url(WEBP)]
    assert slept == []
    [found] = listed(data)
    del data["candidates"]
    assert data == {
        "cpe": [WEBP],
        "nvd_timestamp": "2026-10-18T02:56:09.472",
        "total": {WEBP: 1},
    }
    description = found.pop("description")
    assert description.startswith("Heap buffer overflow in libwebp in Google Chrome")
    assert found == {
        "id": "CVE-2023-4863",
        "status": "Analyzed",
        "published": "2023-09-12T15:15:24.327",
        "last_modified": "2026-06-17T06:38:46.547",
        "cpe": [WEBP],
        "scope": "in",
        "scores": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "version": "3.1",
                "score": 8.8,
                "label": "HIGH",
            },
            {
                "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                "type": "Secondary",
                "version": "3.1",
                "score": 8.8,
                "label": "HIGH",
            },
        ],
        "kev": "2023-09-13",
        # Only the libwebp entry, not Chrome's, Debian's or Fedora's.
        "ranges": [
            {
                "vulnerable": True,
                "criteria": "cpe:2.3:a:webmproject:libwebp:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "1.3.2",
                "matchCriteriaId": "2804DDE4-B0A4-4B7F-A318-F491B6316B34",
            }
        ],
        "affected": json.loads(RECORDED.read_text())["vulnerabilities"][0]["cve"][
            "affected"
        ],
        # Each tagged Patch twice, under two sources, and listed once.
        "patches": [
            "https://github.com/webmproject/libwebp/commit/"
            "902bc9190331343b2017211debcec8d2ab87e17a",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4863",
        ],
    }


def test_pages_until_it_has_total_results_waiting_between_requests() -> None:
    one, two, three = cve("CVE-2024-0001"), cve("CVE-2024-0002"), cve("CVE-2024-0003")
    pages = {
        url("a:a"): page(one, two, total=3, stamp="first"),
        url("a:a", 2): page(three, total=3, stamp="second"),
        url("b:b"): page(),
    }
    data, client, slept = run(pages, ["a:a", "b:b"])
    assert client.requested == [url("a:a"), url("a:a", 2), url("b:b")]
    # Not before the first request, and before every other.
    assert slept == [PAUSE_SECONDS, PAUSE_SECONDS]
    assert data["nvd_timestamp"] == "first"
    assert data["total"] == {"a:a": 3, "b:b": 0}
    ids = [c["id"] for c in listed(data)]
    assert ids == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]


def test_pacer_is_shared_across_libraries() -> None:
    slept: list[float] = []
    client = Client({url("a:a"): page(), url("b:b"): page()})
    phase = cves_phase(client, slept.append)
    assert phase.name == "11-cves" and not phase.skip_not_ok
    assert phase.run(Library("a", "r", "v{version}", "a:a"), {}).status == "ok"
    assert slept == []
    assert phase.run(Library("b", "r", "v{version}", "b:b"), {}).status == "ok"
    assert slept == [PAUSE_SECONDS]


@pytest.mark.parametrize(
    ("pages", "message"),
    [
        (
            {
                url("a:a"): page(cve("CVE-2024-0001"), total=2),
                url("a:a", 1): page(cve("CVE-2024-0002"), total=3),
            },
            "a:a startIndex 1: totalResults went from 2 to 3",
        ),
        (
            {
                url("a:a"): page(cve("CVE-2024-0001"), total=2),
                url("a:a", 1): page(cve("CVE-2024-0001"), total=2),
            },
            "a:a: 1 distinct CVEs, but totalResults is 2",
        ),
        (
            {url("a:a"): page(cve("CVE-2024-0001"), total=2), url("a:a", 1): page()},
            "a:a startIndex 1: totalResults went from 2 to 0",
        ),
        (
            {
                url("a:a"): page(cve("CVE-2024-0001"), total=2),
                url("a:a", 1): page(total=2),
            },
            "a:a: 1 distinct CVEs, but totalResults is 2",
        ),
        ({}, f"{url('a:a')}: HTTP 404"),
        ({url("a:a"): b"<html>busy</html>"}, f"{url('a:a')}: response is not JSON"),
        ({url("a:a"): b"[]"}, f"{url('a:a')}: response is list, expected an object"),
    ],
    ids=[
        "total-changes",
        "fewer-distinct",
        "empty-page-total-changes",
        "empty-page",
        "http-error",
        "not-json",
        "not-an-object",
    ],
)
def test_partial_answers_are_errors(pages: dict[str, bytes], message: str) -> None:
    with pytest.raises(NvdError) as raised:
        run(pages, ["a:a"])
    assert str(raised.value) == message


def wrong(**fields: object) -> bytes:
    return page(cve("CVE-2024-0001") | fields)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (
            json.dumps({"totalResults": True, "timestamp": "t"}).encode(),
            "a:a startIndex 0: totalResults is bool, expected an integer",
        ),
        (
            json.dumps({"totalResults": 1, "timestamp": 5}).encode(),
            "a:a startIndex 0: timestamp is int, expected a string",
        ),
        (
            json.dumps(
                {"totalResults": 1, "timestamp": "t", "vulnerabilities": [{}]}
            ).encode(),
            "a:a startIndex 0: vulnerabilities[0].cve is NoneType, expected an object",
        ),
        (
            wrong(published=20230101),
            "CVE-2024-0001.published is int, expected a string",
        ),
        (
            wrong(published="2023-01-01T00:00:00.000Z"),
            "CVE-2024-0001.published '2023-01-01T00:00:00.000Z' isn't a time",
        ),
        (
            wrong(metrics={"cvssMetricV31": [metric("3.1", "9.8", "CRITICAL")]}),
            "CVE-2024-0001.metrics.cvssMetricV31[0].cvssData.baseScore is str, "
            "expected a number",
        ),
        (
            wrong(metrics={"cvssMetricV40": [metric("4.0", True, "CRITICAL")]}),
            "CVE-2024-0001.metrics.cvssMetricV40[0].cvssData.baseScore is bool, "
            "expected a number",
        ),
        (
            wrong(metrics={"cvssMetricV30": {}}),
            "CVE-2024-0001.metrics.cvssMetricV30 is dict, expected a list",
        ),
        (
            wrong(configurations=[{"nodes": [{"cpeMatch": [{"criteria": 1}]}]}]),
            "CVE-2024-0001.configurations[0].nodes[0].cpeMatch[0].criteria is int, "
            "expected a string",
        ),
        (
            wrong(references=[{"url": "https://x", "tags": "Patch"}]),
            "CVE-2024-0001.references[0].tags is str, expected a list",
        ),
        (
            wrong(cisaExploitAdd=1),
            "CVE-2024-0001.cisaExploitAdd is int, expected a string",
        ),
        (wrong(affected={}), "CVE-2024-0001.affected is dict, expected a list"),
        (
            wrong(descriptions=None),
            "CVE-2024-0001.descriptions is NoneType, expected a list",
        ),
        # Only ASCII digits: \d would match fullwidth ones too.
        (
            page(cve("CVE-\uff12\uff10\uff12\uff14-0001")),
            "cve.id 'CVE-\uff12\uff10\uff12\uff14-0001' isn't a CVE ID",
        ),
    ],
)
def test_a_field_of_the_wrong_type_is_an_error(body: bytes, message: str) -> None:
    with pytest.raises(NvdError) as raised:
        run({url("a:a"): body}, ["a:a"])
    assert str(raised.value) == message


def test_unknown_keys_are_ignored() -> None:
    record = cve(
        "CVE-2024-0001",
        metrics={"cvssMetricV5": [{"what": 1}], "ssvcV203": [{}]},
        weaknesses="anything",
    )
    data, _, _ = run({url("a:a"): page(record)}, ["a:a"])
    [found] = listed(data)
    assert (found["scope"], found["scores"]) == ("unscored", [])


def test_keeps_cves_published_from_2020_to_the_millisecond() -> None:
    late = cve("CVE-2019-9999", published="2019-12-31T23:59:59.999")
    first = cve("CVE-2020-0001", published="2020-01-01T00:00:00.000")
    data, _, _ = run({url("a:a"): page(late, first)}, ["a:a"])
    assert [c["id"] for c in listed(data)] == ["CVE-2020-0001"]
    # The total is before the date filter.
    assert data["total"] == {"a:a": 2}


def test_candidates_are_ordered_by_published_then_id() -> None:
    cves = [
        cve("CVE-2024-0003", published="2024-02-01T00:00:00.000"),
        cve("CVE-2024-0002", published="2024-01-01T00:00:00.000"),
        cve("CVE-2023-9999", published="2024-01-01T00:00:00.000"),
    ]
    data, _, _ = run({url("a:a"): page(*cves)}, ["a:a"])
    ids = [c["id"] for c in listed(data)]
    assert ids == ["CVE-2023-9999", "CVE-2024-0002", "CVE-2024-0003"]


@pytest.mark.parametrize(
    ("metrics", "expected"),
    [
        ({"cvssMetricV31": [metric("3.1", 7.5, "HIGH")]}, "in"),
        ({"cvssMetricV30": [metric("3.0", 9.1, "CRITICAL")]}, "in"),
        ({"cvssMetricV40": [metric("4.0", 8.7, "HIGH")]}, "in"),
        # A label that doesn't fit its score can't hide a candidate.
        ({"cvssMetricV31": [metric("3.1", 7.0, "MEDIUM")]}, "in"),
        ({"cvssMetricV31": [metric("3.1", 7, "LOW")]}, "in"),
        ({"cvssMetricV31": [metric("3.1", 5.0, "HIGH")]}, "in"),
        ({"cvssMetricV31": [metric("3.1", 6.9, "MEDIUM")]}, "out"),
        # One score is enough, whichever source gave it.
        (
            {
                "cvssMetricV31": [metric("3.1", 4.5, "MEDIUM", "nvd@nist.gov")],
                "cvssMetricV40": [metric("4.0", 8.2, "HIGH", "cna")],
            },
            "in",
        ),
        (
            {
                "cvssMetricV30": [metric("3.0", 0.0, "NONE")],
                "cvssMetricV31": [metric("3.1", 3.9, "LOW")],
            },
            "out",
        ),
        # CVSS v2 isn't read.
        ({"cvssMetricV2": [metric("2.0", 10.0, "HIGH")]}, "unscored"),
        ({}, "unscored"),
    ],
)
def test_scope(metrics: dict[str, object], expected: str) -> None:
    data, _, _ = run({url("a:a"): page(cve("CVE-2024-0001", metrics=metrics))}, ["a:a"])
    [found] = listed(data)
    assert found["scope"] == expected
    assert scope(found["scores"]) == expected


def test_a_cve_two_names_return_is_one_candidate() -> None:
    record = cve(
        "CVE-2024-0001",
        matches=[
            match("mit:kerberos_5", versionEndExcluding="1.21"),
            match("mit:krb5-appl"),
            {"vulnerable": False, "criteria": "cpe:2.3:o:mit:kerberos:*:*:*:*:*:*:*:*"},
            match("mit:kerberos"),
        ],
    )
    names = ["mit:kerberos_5", "mit:kerberos"]
    pages = {url(names[0]): page(record), url(names[1]): page(record)}
    data, _, _ = run(pages, names)
    [found] = listed(data)
    assert found["cpe"] == names
    # Only entries naming one of the library's names, in NVD's order.
    assert found["ranges"] == [
        match("mit:kerberos_5", versionEndExcluding="1.21"),
        match("mit:kerberos"),
    ]


def test_a_candidate_with_no_range_is_kept() -> None:
    record = cve("CVE-2024-0001", matches=[match("google:chrome")])
    del record["configurations"]
    other = cve("CVE-2024-0002", matches=[match("google:chrome")])
    data, _, _ = run({url("a:a"): page(record, other)}, ["a:a"])
    first, second = listed(data)
    assert (first["ranges"], second["ranges"]) == ([], [])


def test_patches_are_listed_once_in_order() -> None:
    references = [
        {"url": "https://a", "source": "x", "tags": ["Patch"]},
        {"url": "https://b", "source": "x", "tags": ["Third Party Advisory"]},
        {"url": "https://c", "source": "x"},
        {"url": "https://d", "source": "x", "tags": ["Exploit", "Patch"]},
        {"url": "https://a", "source": "y", "tags": ["Patch"]},
    ]
    record = cve("CVE-2024-0001", references=references)
    data, _, _ = run({url("a:a"): page(record)}, ["a:a"])
    [found] = listed(data)
    assert found["patches"] == ["https://a", "https://d"]
    assert (found["kev"], found["affected"]) == (None, None)


def test_no_english_description_is_null() -> None:
    record = cve("CVE-2024-0001", descriptions=[{"lang": "es", "value": "uno"}])
    data, _, _ = run({url("a:a"): page(record)}, ["a:a"])
    assert listed(data)[0]["description"] is None


def test_names_are_quoted_in_the_url() -> None:
    client = Client({})
    with pytest.raises(NvdError):
        candidates(client, ["a+b:c~d"], Pacer(lambda _: None))
    assert client.requested == [
        f"{API}?virtualMatchString=cpe:2.3:a:a%2Bb:c~d&resultsPerPage=2000&startIndex=0"
    ]


def phase_run(pages: dict[str, bytes], cpe: str) -> Result:
    phase = cves_phase(Client(pages), lambda _: None)
    return phase.run(Library("lib", "r", "v{version}", cpe), {})


def test_phase_11_skips_a_library_whose_cpe_is_none() -> None:
    assert phase_run({}, "none") == Result("skipped", "no_cpe", {"cpe": []})


def test_phase_11_error_has_no_candidates() -> None:
    pages = {url("a:a"): page(cve("CVE-2024-0001"))}
    result = phase_run(pages, "a:a b:b")
    assert result == Result("error", f"{url('b:b')}: HTTP 404", {"cpe": ["a:a", "b:b"]})


def test_phase_11_ok_line() -> None:
    result = phase_run({url("a:a"): page(cve("CVE-2024-0001"))}, "a:a")
    assert result.status == "ok"
    assert set(result.data) == {"cpe", "nvd_timestamp", "total", "candidates"}
