"""Library detectors for ``fingerprint``. Add a library by adding a module."""

from pypiscan.detectors.zlib import ZLIB
from pypiscan.fingerprint import Detector

DETECTORS: tuple[Detector, ...] = (ZLIB,)
# The libraries a hand-written detector names, which a library map row with
# static_lib_detection "detector" can name.
DETECTOR_LIBRARIES = frozenset(p.library for d in DETECTORS for p in d.patterns)
