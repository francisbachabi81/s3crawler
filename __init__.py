# function_app/__init__.py
# Azure Function (HTTP trigger) that scans S3 buckets for malformed remote-sensing filenames
# per your ORG1 ICD & customer workflow and returns a JSON payload with findings.
#
# Requires your existing rules.py to be deployable alongside this file.

import json
import os
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

import azure.functions as func
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from rules import (
    # Config / constants you already maintain
    SCAN_FOLDERS, PAST_DAYS_WINDOW,
    IMAGERY_PRODUCT_TYPES, TACTICAL_PRODUCT_TYPES, VIDEO_PRODUCT_TYPES,  # not used directly here but kept for parity
    IMAGERY_VALID_INPUT_EXTS, IMAGERY_SYSTEM_KMZ_EXT,
    TACTICAL_VALID_INPUT_EXTS,
    VIDEO_VALID_INPUT_EXTS,  # may be used by your patterns; here we validate explicit ext list in code
    IMAGERY_KMZ_MAX_MB, VIDEO_MP4_MAX_MB,
    # Pattern factories & helpers you already have
    imagery_patterns, tactical_patterns, video_patterns,
    is_system_derivative, hyphen_only_okay,
)

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
logger = logging.getLogger("s3-naming-checker")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

logger.info("=== Azure Function cold start: S3 Malformed File Checker ===")

# ------------------------------------------------------------------------------
# AWS Client (uses Function App settings / Key Vault refs)
# ------------------------------------------------------------------------------
def _make_s3_client():
    try:
        return boto3.client(
            "s3",
            aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
            region_name=os.environ.get("AWS_REGION", "us-west-2"),
            config=BotoConfig(retries={"max_attempts": 10, "mode": "standard"}),
        )
    except KeyError as ke:
        logger.error("Missing required environment variable: %s", ke)
        raise

s3 = _make_s3_client()

# ------------------------------------------------------------------------------
# Regex precompile (delegated to your rules module)
# ------------------------------------------------------------------------------
IMAGERY_A, IMAGERY_B = imagery_patterns()
TACTICAL_A, TACTICAL_B = tactical_patterns()
VIDEO_A,   VIDEO_B     = video_patterns()

# ------------------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------------------
def _within_window(last_modified_dt, days: int) -> bool:
    """Limit scanning to recent 'days' window."""
    if last_modified_dt.tzinfo is None:
        last_modified_dt = last_modified_dt.replace(tzinfo=timezone.utc)
    return last_modified_dt >= datetime.now(timezone.utc) - timedelta(days=days)

def _mb(size_bytes: int) -> float:
    return size_bytes / (1024.0 * 1024.0)

# ------------------------------------------------------------------------------
# Validators (from your original script; unchanged logic)
# ------------------------------------------------------------------------------
def validate_imagery(file_name: str, all_names_lower: set, size_bytes: int):
    name_lower = file_name.lower()

    # Ignore system derivatives early (.kml, .kml.ext_, .kmz.ext_, .mdata, etc.)
    if is_system_derivative(name_lower):
        return True, "system-generated derivative; naming ignored."

    # Ignore .kml files under IMAGERY – system outputs
    if name_lower.endswith(".kml"):
        return True, "system-generated KML in IMAGERY; naming ignored."

    # Handle .png.aux.xml companion (this is valid, not a raw XML)
    if name_lower.endswith(".png.aux.xml"):
        return True, "PNG auxiliary metadata file (.png.aux.xml); valid companion."

    base, ext = os.path.splitext(name_lower)

    # KMZ outputs (system-generated, size-check only)
    if name_lower.endswith(IMAGERY_SYSTEM_KMZ_EXT):
        if _mb(size_bytes) > IMAGERY_KMZ_MAX_MB:
            return False, f"system-generated KMZ exceeds {IMAGERY_KMZ_MAX_MB} MB."
        return True, "system-generated KMZ within size limit."

    # Validate only actual user-upload inputs (.tif, .tiff, or .png)
    if ext not in IMAGERY_VALID_INPUT_EXTS:
        return False, f"unexpected file type '{ext}' in IMAGERY (only .tif/.tiff or .png + .aux.xml)."

    # Hyphen-only mission rule
    tokens = file_name.split("_")
    if len(tokens) >= 1 and not hyphen_only_okay(tokens[0]):
        return False, "mission name contains invalid characters (only letters/digits/hyphens)."

    matchedA = bool(IMAGERY_A.match(file_name))
    matchedB = bool(IMAGERY_B.match(file_name))
    if not (matchedA or matchedB):
        return False, "does not match IMAGERY Option A/B naming pattern."

    # PNG companion rule
    if ext == ".png":
        # Ignore PNG generated from TIF/TIFF
        tiff_candidates = [
            f"{os.path.splitext(file_name)[0]}.tif".lower(),
            f"{os.path.splitext(file_name)[0]}.tiff".lower()
        ]
        if any(t in all_names_lower for t in tiff_candidates):
            return True, "system-generated PNG from TIF/TIFF; naming ignored."

        # Must have matching .png.aux.xml with same base
        aux_candidate = f"{os.path.splitext(file_name)[0]}.png.aux.xml".lower()
        if aux_candidate not in all_names_lower:
            return False, "PNG missing matching .png.aux.xml companion with same mission and timestamp."

        return True, "valid PNG + .png.aux.xml user upload."

    return True, "valid IMAGERY input."

def validate_tactical(file_name: str, size_bytes: int):
    name_lower = file_name.lower()

    # Ignore all known system derivatives (.mdata, .kml.ext_, .kmz.ext_, etc.)
    if is_system_derivative(name_lower):
        return True, "system-generated derivative; naming ignored."

    # Ignore any DPS outputs (can appear anywhere or at the end)
    if re.search(r"_(dps)(?:_|\.|$)", name_lower):
        return True, "DPS product type is system-generated; naming ignored."

    base, ext = os.path.splitext(name_lower)
    if ext not in TACTICAL_VALID_INPUT_EXTS:
        return False, "only .kml or .kmz are allowed in TACTICAL."

    # Must match one of the valid tactical patterns
    mA = TACTICAL_A.match(file_name)
    mB = TACTICAL_B.match(file_name)
    if not (mA or mB):
        return False, "missing or invalid product type (must match approved TACTICAL types)."

    # PERIM acres check – must be whole number if present
    if re.search(r"_PERIM_", file_name, re.IGNORECASE):
        if re.search(r"_[0-9]+\.[0-9]+(acres|ac)?\.", name_lower):
            return False, "acres value must be a whole number (e.g., 7acres not 7.2acres)."

    # Mission name hyphen rule
    tokens = file_name.split("_")
    if len(tokens) >= 1 and not hyphen_only_okay(tokens[0]):
        return False, "mission name contains invalid characters (only letters/digits/hyphens)."

    return True, "valid TACTICAL input."

def validate_video(file_name: str, all_names_lower: set, size_bytes: int):
    name_lower = file_name.lower()

    # Ignore system derivatives (.mdata, .kml.ext_, etc.)
    if is_system_derivative(name_lower):
        return True, "system-generated derivative; naming ignored."

    base, ext = os.path.splitext(name_lower)

    # Only check valid video-related input extensions
    if ext not in [".ts", ".mp4", ".kml"]:
        return False, f"unexpected file type '{ext}' in VIDEO (only .ts, .mp4 + .kml allowed)."

    # Hyphen-only mission rule
    tokens = file_name.split("_")
    if len(tokens) >= 1 and not hyphen_only_okay(tokens[0]):
        return False, "mission name contains invalid characters (only letters/digits/hyphens)."

    # Validate filename pattern
    matchedA = bool(VIDEO_A.match(file_name))
    matchedB = bool(VIDEO_B.match(file_name))
    if not (matchedA or matchedB):
        return False, "does not match VIDEO Option A/B naming pattern."

    # --- CASE 1: TS upload (user input) ---
    if ext == ".ts":
        return True, "valid standalone TS upload (user input)."

    # --- CASE 2: MP4 upload ---
    if ext == ".mp4":
        # 2a: Ignore MP4s generated from TS
        ts_candidate = f"{os.path.splitext(file_name)[0]}.ts".lower()
        if ts_candidate in all_names_lower:
            return True, "system-generated MP4 from TS; ignored."

        # 2b: Valid MP4 if accompanied by matching KML
        kml_candidate = f"{os.path.splitext(file_name)[0]}.kml".lower()
        if kml_candidate in all_names_lower:
            if _mb(size_bytes) > VIDEO_MP4_MAX_MB:
                return False, f"MP4 exceeds size limit ({VIDEO_MP4_MAX_MB} MB)."
            return True, "valid MP4 + KML user upload."

        # 2c: No TS or KML → invalid upload
        return False, "MP4 missing matching .kml companion and not generated from TS."

    # --- CASE 3: KML upload ---
    if ext == ".kml":
        # Ignore KMLs that belong to TS or MP4 (system-generated)
        mp4_candidate = f"{os.path.splitext(file_name)[0]}.mp4".lower()
        ts_candidate = f"{os.path.splitext(file_name)[0]}.ts".lower()
        if mp4_candidate in all_names_lower or ts_candidate in all_names_lower:
            return True, "system-generated KML from video; ignored."
        # Otherwise, it’s not a valid independent upload
        return False, "standalone KML found in VIDEO without companion MP4."

    return True, "valid VIDEO input."

# ------------------------------------------------------------------------------
# S3 scanning
# ------------------------------------------------------------------------------
def check_bucket(bucket_name: str, window_days: int, client) -> List[Dict[str, Any]]:
    logger.info(f"Scanning bucket: {bucket_name}")
    paginator = client.get_paginator("list_objects_v2")
    malformed: List[Dict[str, Any]] = []

    try:
        all_keys: List[str] = []
        page_objs: List[Dict[str, Any]] = []

        for page in paginator.paginate(Bucket=bucket_name):
            contents = page.get("Contents", [])
            page_objs.extend(contents)
            for o in contents:
                all_keys.append(o["Key"])

        all_names_lower = {os.path.basename(k).lower() for k in all_keys}

        for obj in page_objs:
            key = obj.get("Key")
            if not key or key.endswith("/"):
                continue

            folder = key.split("/")[0] if "/" in key else "NoFolder"
            if folder not in SCAN_FOLDERS:
                continue

            last_mod = obj.get("LastModified")
            if not last_mod or not _within_window(last_mod, window_days):
                continue

            name = os.path.basename(key)
            if not name.strip():
                continue

            size_bytes = obj.get("Size", 0)

            if folder == "IMAGERY":
                ok, reason = validate_imagery(name, all_names_lower, size_bytes)
            elif folder == "TACTICAL":
                ok, reason = validate_tactical(name, size_bytes)
            elif folder == "VIDEO":
                ok, reason = validate_video(name, all_names_lower, size_bytes)
            else:
                ok, reason = True, "folder not monitored."

            if not ok:
                malformed.append({
                    "bucket": bucket_name,
                    "folder": folder,
                    "file_name": name,
                    "issue": reason
                })
                logger.warning(f"[{folder}] {name}: {reason}")

    except ClientError as e:
        logger.error(f"AWS error scanning {bucket_name}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error scanning {bucket_name}: {e}")

    return malformed

# ------------------------------------------------------------------------------
# HTTP trigger
# ------------------------------------------------------------------------------
DEFAULT_BUCKETS = [
    "aeveximagery", "bia-iaa", "mtstate-iaa1", "spuraviationiaa", "wastate-n216kq",
    "fsagencyiaa", "orstate", "snccostate", "bodeintel", "courtneyimagery",
    "sbcnova", "costatenova", "coulsoniaa", "ocfa-uas"
]

def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    POST body (optional):
    {
      "buckets": ["bucket-a", "bucket-b"],
      "window_days": 60
    }
    """
    try:
        body = {}
        try:
            body = req.get_json()
        except ValueError:
            body = {}

        buckets = body.get("buckets") or DEFAULT_BUCKETS
        try:
            window_days = int(body.get("window_days") or os.environ.get("PAST_DAYS_WINDOW", PAST_DAYS_WINDOW))
        except Exception:
            window_days = PAST_DAYS_WINDOW

        scan_start = datetime.utcnow().isoformat() + "Z"
        findings: List[Dict[str, Any]] = []

        for b in buckets:
            findings.extend(check_bucket(b, window_days, s3))

        scan_end = datetime.utcnow().isoformat() + "Z"

        resp = {
            "malformed": findings,
            "checked_buckets": buckets,
            "window_days": window_days,
            "scan_start": scan_start,
            "scan_end": scan_end,
            "count": len(findings),
        }

        return func.HttpResponse(
            json.dumps(resp),
            status_code=200,
            mimetype="application/json",
            headers={
                # Helpful CORS headers if calling from PA/Logic Apps or browser-based tools
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
            }
        )

    except Exception as e:
        logger.exception("Scan failed with an unhandled error.")
        err = {"error": str(e)}
        return func.HttpResponse(
            json.dumps(err),
            status_code=500,
            mimetype="application/json"
        )
