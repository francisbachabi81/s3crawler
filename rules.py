# rules.py
# Centralized rules and helpers for the S3 malformed file checker.

import os
import re

# -----------------------------
# Global constraints & limits
# -----------------------------
SCAN_FOLDERS = {"IMAGERY", "TACTICAL", "VIDEO"}
PAST_DAYS_WINDOW = 60  # 2 months

# Only hyphen is allowed inside mission name and description text.
DISALLOW_SPACE_PATTERN = re.compile(r"\s")

# System-generated derivatives we should ignore for naming validation
SYSTEM_DERIVATIVE_MARKERS = (
    ".mdata",
    ".kml.ext_",
    "_imageperimeter.kml",
)

# -----------------------------
# Per-folder product types
# -----------------------------
IMAGERY_PRODUCT_TYPES = {"EOimage", "HSimage", "IRimage"}
TACTICAL_PRODUCT_TYPES = {
    "PERIM", "HeatPerimeter", "HOTSPOT", "IsolatedHeat", "IntenseHeat",
    "ScatteredHeat", "Structures", "Infrastructure", "WaterSources",
    "Route", "DETECTION", "UnburnedArea", "AttendedCampfire",
    "AFL", "RETARDANT", "LIFESAFETY", "ALLHAZARD"
}
VIDEO_PRODUCT_TYPES = {"VIDEOCLIP", "Video"}

# -----------------------------
# Valid input extensions
# -----------------------------
IMAGERY_VALID_INPUT_EXTS = {".tif",".tiff", ".png"}
IMAGERY_SYSTEM_KMZ_EXT = ".kmz"

TACTICAL_VALID_INPUT_EXTS = {".kml", ".kmz"}
TACTICAL_SYSTEM_PRODUCT = "DPS"

VIDEO_VALID_INPUT_EXTS = {".ts", ".mp4", ".kml"}

# -----------------------------
# Size limits
# -----------------------------
IMAGERY_KMZ_MAX_MB = 50
VIDEO_MP4_MAX_MB = 200

# -----------------------------
# Regex components
# -----------------------------
MISSION_TOKEN = r"(?P<mission>[A-Za-z0-9-]+)"
DATETIME_A = r"(?P<dtA>\d{12}Z)"
DATE = r"(?P<date>\d{8})"
TIME_Z = r"(?P<time>\d{4,6}Z)"
SERIAL = r"(?P<serial>\d+)"
DESC = r"(?P<desc>[A-Za-z0-9-]+)"


def product_alt(options):
    return "(" + "|".join(sorted(map(re.escape, options), key=len, reverse=True)) + ")"


# -----------------------------
# Folder regex patterns
# -----------------------------
def imagery_patterns():
    pt = product_alt(IMAGERY_PRODUCT_TYPES)
    optA = re.compile(
        rf"^[A-Za-z0-9-]+(?:-[A-Za-z0-9-]+)*_{DATETIME_A}_{pt}_{SERIAL}(?:_{DESC})?\.(tif|tiff|png|kmz)$",
        re.IGNORECASE,
    )
    optB = re.compile(
        rf"^{DATE}_{TIME_Z}_[A-Za-z0-9-]+(?:-[A-Za-z0-9-]+)*_{pt}(?:_{DESC})?\.(tif|tiff|png|kmz)$",
        re.IGNORECASE,
    )
    return optA, optB


def tactical_patterns():
    pt = product_alt(TACTICAL_PRODUCT_TYPES)
    optA = re.compile(
        rf"^[A-Za-z0-9-]+(?:-[A-Za-z0-9-]+)*_{DATETIME_A}_{pt}_{SERIAL}(?:_{DESC})?\.(kml|kmz)$",
        re.IGNORECASE,
    )
    optB = re.compile(
        rf"^{DATE}_{TIME_Z}_[A-Za-z0-9-]+(?:-[A-Za-z0-9-]+)*_{pt}(?:_{DESC})?\.(kml|kmz)$",
        re.IGNORECASE,
    )
    return optA, optB


def video_patterns():
    pt = product_alt(VIDEO_PRODUCT_TYPES)
    optA = re.compile(
        rf"^[A-Za-z0-9-]+(?:-[A-Za-z0-9-]+)*_{DATETIME_A}_{pt}_{SERIAL}(?:_{DESC})?\.(ts|mp4|kml)$",
        re.IGNORECASE,
    )
    optB = re.compile(
        rf"^{DATE}_{TIME_Z}_[A-Za-z0-9-]+(?:-[A-Za-z0-9-]+)*_{pt}(?:_{DESC})?\.(ts|mp4|kml)$",
        re.IGNORECASE,
    )
    return optA, optB



# -----------------------------
# Helpers
# -----------------------------
def is_system_derivative(name_lower: str) -> bool:
    """True if file is a system-generated derivative that should be ignored."""
    # Known markers
    if any(mark in name_lower for mark in SYSTEM_DERIVATIVE_MARKERS):
        return True

    # KMZ/KML extent outputs with coordinate suffixes
    if re.search(r"\.(kmz|kml)\.ext_[\-\d\._]+$", name_lower):
        return True

    # Generic extent coordinate suffix
    if re.search(r"\.ext_[\-\d\._]+$", name_lower):
        return True

    return False


def hyphen_only_okay(s: str) -> bool:
    """Return True if token uses only [A-Za-z0-9-]."""
    if "_" in s or DISALLOW_SPACE_PATTERN.search(s):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9-]+", s or ""))
