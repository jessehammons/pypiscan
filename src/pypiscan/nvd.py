"""Candidate CVEs for a library from NVD's CVE API, by its CPE names.

See README "Candidates from NVD". ``candidates`` asks the API for every CVE
matching each of a library's CPE names, pages until it has ``totalResults``
of them, and keeps those NVD published on or after 2020-01-01. Fields it
uses are type-checked exactly, and one of the wrong type raises
``NvdError`` naming it; keys it doesn't use are ignored. Ranges, patch
links and ``affected`` lists are recorded verbatim, as claims.
"""

import json
import re
import urllib.parse
from collections.abc import Callable
from datetime import UTC, datetime
from typing import cast

from pypiscan.pypi import HttpClient, PyPIError

NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# The most the API allows per page.
RESULTS_PER_PAGE = 2000
# The pace NVD's documentation sets for clients without an API key.
PAUSE_SECONDS = 6
EARLIEST = datetime(2020, 1, 1, tzinfo=UTC)
CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
# NVD's times have no zone suffix and are UTC.
NVD_TIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?"
)
# The metrics scope is read from; any other metric key is ignored.
CVSS_METRICS = ("cvssMetricV30", "cvssMetricV31", "cvssMetricV40")
IN_SCOPE_LABELS = ("HIGH", "CRITICAL")
# Scores are compared in tenths, so 7.0 is 70.
IN_SCOPE_TENTHS = 70

type Json = dict[str, object]


class NvdError(Exception):
    """NVD couldn't be read, or its response doesn't make sense."""


class Pacer:
    """Waits ``PAUSE_SECONDS`` before each request but the first."""

    def __init__(self, sleep: Callable[[float], None]) -> None:
        self._sleep = sleep
        self._first = True

    def __call__(self) -> None:
        if not self._first:
            self._sleep(PAUSE_SECONDS)
        self._first = False


def _wrong(value: object, field: str, expected: str) -> NvdError:
    return NvdError(f"{field} is {type(value).__name__}, expected {expected}")


def _obj(value: object, field: str) -> Json:
    if type(value) is not dict:
        raise _wrong(value, field, "an object")
    return cast(Json, value)


def _list(value: object, field: str, optional: bool = False) -> list[object]:
    """A list; with ``optional``, a missing or null one is empty."""
    if optional and value is None:
        return []
    if type(value) is not list:
        raise _wrong(value, field, "a list")
    return cast(list[object], value)


def _str(value: object, field: str, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if type(value) is not str:
        raise _wrong(value, field, "a string")
    return value


def _text(value: object, field: str) -> str:
    return cast(str, _str(value, field))


def _int(value: object, field: str) -> int:
    # Exactly int: a bool is an int too.
    if type(value) is not int:
        raise _wrong(value, field, "an integer")
    return value


def tenths(value: object, field: str) -> int:
    """A CVSS score in tenths."""
    if type(value) not in (int, float):
        raise _wrong(value, field, "a number")
    return round(cast(float, value) * 10)


def _time(value: object, field: str) -> datetime:
    text = _text(value, field)
    if not NVD_TIME.fullmatch(text):
        raise NvdError(f"{field} {text!r} isn't a time")
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


def _page(client: HttpClient, name: str, start: int) -> Json:
    query = urllib.parse.urlencode(
        {
            "virtualMatchString": f"cpe:2.3:a:{name}",
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start,
        },
        safe=":",
        quote_via=urllib.parse.quote,
    )
    url = f"{NVD_CVES}?{query}"
    try:
        body = b"".join(client.stream(url))
    except PyPIError as exc:
        raise NvdError(str(exc)) from exc
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise NvdError(f"{url}: response is not JSON") from exc
    return _obj(data, f"{url}: response")


def query(client: HttpClient, name: str, pace: Pacer) -> tuple[str, int, list[Json]]:
    """Every CVE NVD matches to the CPE name ``name``: the first page's
    timestamp and ``totalResults``, and each vulnerability's ``cve``."""
    found: list[Json] = []
    first: tuple[str, int] | None = None
    while first is None or len(found) < first[1]:
        pace()
        where = f"{name} startIndex {len(found)}"
        page = _page(client, name, len(found))
        total = _int(page.get("totalResults"), f"{where}: totalResults")
        stamp = _text(page.get("timestamp"), f"{where}: timestamp")
        items = _list(page.get("vulnerabilities"), f"{where}: vulnerabilities")
        if first is None:
            first = stamp, total
        elif total != first[1]:
            raise NvdError(f"{where}: totalResults went from {first[1]} to {total}")
        for i, item in enumerate(items):
            field = f"{where}: vulnerabilities[{i}]"
            found.append(_obj(_obj(item, field).get("cve"), f"{field}.cve"))
        if not items:
            break
    ids = {_text(cve.get("id"), f"{name}: cve.id") for cve in found}
    if len(ids) < first[1]:
        raise NvdError(
            f"{name}: {len(ids)} distinct CVEs, but totalResults is {first[1]}"
        )
    return first[0], first[1], found


def _scores(metrics: Json, field: str) -> list[Json]:
    scores: list[Json] = []
    for key in CVSS_METRICS:
        entries = _list(metrics.get(key), f"{field}.{key}", optional=True)
        for i, entry in enumerate(entries):
            where = f"{field}.{key}[{i}]"
            entry = _obj(entry, where)
            data = _obj(entry.get("cvssData"), f"{where}.cvssData")
            score = data.get("baseScore")
            tenths(score, f"{where}.cvssData.baseScore")
            scores.append(
                {
                    "source": _text(entry.get("source"), f"{where}.source"),
                    "type": _text(entry.get("type"), f"{where}.type"),
                    "version": _text(data.get("version"), f"{where}.cvssData.version"),
                    "score": score,
                    "label": _text(
                        data.get("baseSeverity"), f"{where}.cvssData.baseSeverity"
                    ),
                }
            )
    return scores


def scope(scores: list[Json]) -> str:
    """``in`` when any score is labeled HIGH or CRITICAL or is 7.0 or more,
    ``out`` when there are scores and none is, ``unscored`` without any."""
    if not scores:
        return "unscored"
    for s in scores:
        if s["label"] in IN_SCOPE_LABELS or tenths(s["score"], "") >= IN_SCOPE_TENTHS:
            return "in"
    return "out"


def _description(cve: Json, field: str) -> str | None:
    """NVD's English description, or None."""
    for i, entry in enumerate(_list(cve.get("descriptions"), f"{field}.descriptions")):
        where = f"{field}.descriptions[{i}]"
        entry = _obj(entry, where)
        if _text(entry.get("lang"), f"{where}.lang") == "en":
            return _text(entry.get("value"), f"{where}.value")
    return None


def _ranges(cve: Json, field: str, names: list[str]) -> list[object]:
    """Every ``cpeMatch`` entry, verbatim, whose criteria name one of
    ``names``."""
    ranges: list[object] = []
    configurations = cve.get("configurations")
    for i, item in enumerate(
        _list(configurations, f"{field}.configurations", optional=True)
    ):
        where = f"{field}.configurations[{i}]"
        for j, node in enumerate(_list(_obj(item, where).get("nodes"), where)):
            at = f"{where}.nodes[{j}].cpeMatch"
            for k, match in enumerate(_list(_obj(node, at).get("cpeMatch"), at)):
                match = _obj(match, f"{at}[{k}]")
                criteria = _text(match.get("criteria"), f"{at}[{k}].criteria")
                parts = criteria.split(":")
                if parts[:3] == ["cpe", "2.3", "a"] and ":".join(parts[3:5]) in names:
                    ranges.append(match)
    return ranges


def _patches(cve: Json, field: str) -> list[str]:
    """The URLs of references tagged Patch, each once, in NVD's order."""
    patches: list[str] = []
    for i, reference in enumerate(_list(cve.get("references"), f"{field}.references")):
        where = f"{field}.references[{i}]"
        reference = _obj(reference, where)
        url = _text(reference.get("url"), f"{where}.url")
        tags = _list(reference.get("tags"), f"{where}.tags", optional=True)
        for j, tag in enumerate(tags):
            _text(tag, f"{where}.tags[{j}]")
        if "Patch" in tags and url not in patches:
            patches.append(url)
    return patches


def candidate(cve: Json, names: list[str]) -> Json:
    """A candidate from a ``cve`` object, for a library with CPE ``names``;
    ``candidates`` fills in its ``cpe``."""
    cve_id = _text(cve.get("id"), "cve.id")
    if not CVE_ID.fullmatch(cve_id):
        raise NvdError(f"cve.id {cve_id!r} isn't a CVE ID")
    scores = _scores(_obj(cve.get("metrics"), f"{cve_id}.metrics"), f"{cve_id}.metrics")
    affected = cve.get("affected")
    if affected is not None:
        _list(affected, f"{cve_id}.affected")
    return {
        "id": cve_id,
        "status": _text(cve.get("vulnStatus"), f"{cve_id}.vulnStatus"),
        "published": _text(cve.get("published"), f"{cve_id}.published"),
        "last_modified": _text(cve.get("lastModified"), f"{cve_id}.lastModified"),
        "cpe": [],
        "scope": scope(scores),
        "scores": scores,
        "kev": _str(cve.get("cisaExploitAdd"), f"{cve_id}.cisaExploitAdd", True),
        "description": _description(cve, cve_id),
        "ranges": _ranges(cve, cve_id, names),
        "affected": affected,
        "patches": _patches(cve, cve_id),
    }


def candidates(client: HttpClient, names: list[str], pace: Pacer) -> Json:
    """A library's line data: the names queried, the first response's
    timestamp, each name's ``totalResults``, and the candidates published
    from 2020-01-01 on, ordered by ``published`` and then ``id``."""
    timestamp: str | None = None
    total: dict[str, int] = {}
    found: dict[str, Json] = {}
    times: dict[str, datetime] = {}
    for name in names:
        stamp, total[name], cves = query(client, name, pace)
        timestamp = timestamp or stamp
        for cve in cves:
            entry = candidate(cve, names)
            cve_id = cast(str, entry["id"])
            times[cve_id] = _time(entry["published"], f"{cve_id}.published")
            if times[cve_id] >= EARLIEST:
                entry = found.setdefault(cve_id, entry)
                cast(list[str], entry["cpe"]).append(name)
    ordered = [found[i] for i in sorted(found, key=lambda i: (times[i], i))]
    return {
        "cpe": names,
        "nvd_timestamp": timestamp,
        "total": total,
        "candidates": ordered,
    }
