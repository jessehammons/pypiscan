"""Library detectors for ``fingerprint``. Add a library by adding a module."""

from pypiscan.detectors.zlib import ZLIB
from pypiscan.fingerprint import Detector

DETECTORS: tuple[Detector, ...] = (ZLIB,)
