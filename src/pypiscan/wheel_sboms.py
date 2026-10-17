"""List the SBOM files in a wheel's ``.dist-info/sboms/`` directory.

See README "SBOMs in wheels". A file's format comes from its content, never
its name. For a CycloneDX JSON file, its tools and every component, nested
ones included, are kept verbatim: nothing is interpreted, normalized or
inferred. Only the fields that are read have their types checked, and a
wrong type leaves ``tools``, ``subject`` and ``components`` all ``null``.
"""

import hashlib
import json
import zipfile
import zlib
from pathlib import Path
from typing import Literal, TypedDict, cast

from pypiscan.wheel_inspect import WheelError

SCHEMA_VERSION = 1
FIELDS = ("bom-ref", "type", "name", "version", "purl", "scope")

type Format = Literal["cyclonedx-json", "spdx-json", "other"]
type Object = dict[str, object]

Subject = TypedDict(
    "Subject",
    {
        "bom-ref": str | None,
        "type": str | None,
        "name": str | None,
        "version": str | None,
        "purl": str | None,
        "scope": str | None,
    },
)


class Component(Subject):
    parent: int | None


class Tool(TypedDict):
    name: str | None
    version: str | None


class SbomRecord(TypedDict):
    schema_version: int
    wheel: str
    path: str
    size: int
    sha256: str | None
    format: Format | None
    spec_version: str | None
    tools: list[Tool] | None
    components: list[Component] | None
    subject: Subject | None
    error: str | None


class WrongType(Exception):
    """A field that is read has the wrong JSON type; ``args[0]`` is its path."""


def is_sbom(path: str) -> bool:
    """Whether a zip member is a file under a top-level
    ``*.dist-info/sboms/`` directory, at any depth below it."""
    parts = path.split("/")
    return len(parts) > 2 and parts[0].endswith(".dist-info") and parts[1] == "sboms"


def _object(value: object, path: str) -> Object:
    if not isinstance(value, dict):
        raise WrongType(path)
    return cast(Object, value)


def _objects(value: object, path: str) -> list[tuple[Object, str]]:
    """Each item of a list of objects, with its path."""
    if not isinstance(value, list):
        raise WrongType(path)
    items = cast(list[object], value)
    return [
        (_object(item, f"{path}[{i}]"), f"{path}[{i}]") for i, item in enumerate(items)
    ]


def _string(obj: Object, key: str, path: str) -> str | None:
    """``obj[key]`` if it's a string, ``None`` if it's absent; ``path`` is
    ``obj``'s, empty for the document."""
    if key not in obj:
        return None
    value = obj[key]
    if not isinstance(value, str):
        raise WrongType(f"{path}.{key}" if path else key)
    return value


def _subject(obj: Object, path: str) -> Subject:
    return cast(Subject, {key: _string(obj, key, path) for key in FIELDS})


def _tools(metadata: Object) -> list[Tool]:
    if "tools" not in metadata:
        return []
    value = metadata["tools"]
    if not isinstance(value, dict):
        tools = _objects(value, "metadata.tools")
    else:
        holder = cast(Object, value)
        tools = [
            tool
            for key in ("components", "services")
            if key in holder
            for tool in _objects(holder[key], f"metadata.tools.{key}")
        ]
    return [
        {"name": _string(tool, "name", path), "version": _string(tool, "version", path)}
        for tool, path in tools
    ]


def _components(doc: Object) -> list[Component]:
    """Every component in pre-order, flattened with an explicit stack so
    deep nesting can't exhaust Python's recursion limit."""
    found: list[Component] = []
    # (component, its path, its parent's index), popped in document order.
    stack: list[tuple[Object, str, int | None]] = []
    if "components" in doc:
        top = _objects(doc["components"], "components")
        stack = [(obj, path, None) for obj, path in reversed(top)]
    while stack:
        obj, path, parent = stack.pop()
        index = len(found)
        found.append(cast(Component, {**_subject(obj, path), "parent": parent}))
        if "components" in obj:
            nested = _objects(obj["components"], f"{path}.components")
            stack += [(child, at, index) for child, at in reversed(nested)]
    return found


def _read(data: bytes, record: SbomRecord) -> None:
    """Fill in the fields of ``record`` that come from the file's contents."""
    try:
        doc: object = json.loads(data)
    # ValueError covers UnicodeDecodeError; json raises RecursionError for
    # nesting deeper than it can parse.
    except (ValueError, RecursionError):
        record["format"] = "other"
        record["error"] = "not_json"
        return
    if not isinstance(doc, dict):
        record["format"] = "other"
        return
    doc = cast(Object, doc)
    if doc.get("bomFormat") != "CycloneDX":
        record["format"] = "spdx-json" if "spdxVersion" in doc else "other"
        return
    record["format"] = "cyclonedx-json"
    try:
        record["spec_version"] = _string(doc, "specVersion", "")
        metadata = _object(doc.get("metadata", {}), "metadata")
        tools = _tools(metadata)
        subject = None
        if "component" in metadata:
            component = _object(metadata["component"], "metadata.component")
            subject = _subject(component, "metadata.component")
        components = _components(doc)
    except WrongType as exc:
        record["error"] = f"wrong_type: {exc.args[0]}"
        return
    record["tools"] = tools
    record["components"] = components
    record["subject"] = subject


def _record(wheel: Path, path: str, size: int, data: bytes | None) -> SbomRecord:
    record: SbomRecord = {
        "schema_version": SCHEMA_VERSION,
        "wheel": wheel.name,
        "path": path,
        "size": size,
        "sha256": None,
        "format": None,
        "spec_version": None,
        "tools": None,
        "components": None,
        "subject": None,
        "error": "too_large",
    }
    if data is not None:
        record["sha256"] = hashlib.sha256(data).hexdigest()
        record["error"] = None
        _read(data, record)
    return record


def sboms_wheel(wheel: Path, max_member_size: int | None = None) -> list[SbomRecord]:
    """Return one record per SBOM file in ``wheel``, in archive order.

    Raises ``WheelError`` if ``wheel`` can't be read. When
    ``max_member_size`` is set, a file whose declared uncompressed size
    exceeds it isn't read, and its record's error is ``too_large``.
    """
    if not wheel.is_file():
        raise WheelError(f"{wheel}: no such file")
    records: list[SbomRecord] = []
    try:
        with zipfile.ZipFile(wheel) as zf:
            for info in zf.infolist():
                if info.is_dir() or not is_sbom(info.filename):
                    continue
                if max_member_size is not None and info.file_size > max_member_size:
                    records.append(_record(wheel, info.filename, info.file_size, None))
                    continue
                data = zf.read(info)
                records.append(_record(wheel, info.filename, len(data), data))
    # As in wheel_inspect.iter_elf_members.
    except (zipfile.BadZipFile, zlib.error, EOFError) as exc:
        raise WheelError(f"{wheel}: not a valid zip file ({exc})") from exc
    except OSError as exc:
        raise WheelError(f"{wheel}: {exc}") from exc
    return records
