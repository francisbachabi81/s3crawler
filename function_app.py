import json, os, logging, re
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

import azure.functions as func
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

# ---- import your existing rules (place rules.py next to this file) ----
from rules import (
    SCAN_FOLDERS, PAST_DAYS_WINDOW,
    imagery_patterns, tactical_patterns, video_patterns,
    IMAGERY_VALID_INPUT_EXTS, IMAGERY_SYSTEM_KMZ_EXT, IMAGERY_KMZ_MAX_MB,
    TACTICAL_VALID_INPUT_EXTS,
    VIDEO_MP4_MAX_MB,
    is_system_derivative, hyphen_only_okay,
)

app = func.FunctionApp()
logger = logging.getLogger("s3crawler")
logger.setLevel(logging.INFO)

# ---- AWS client via env vars ----
def _make_s3():
    return boto3.client(
        "s3",
        aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        region_name=os.environ.get("AWS_REGION", "us-west-2"),
        config=BotoConfig(retries={"max_attempts": 10, "mode": "standard"})
    )

s3 = _make_s3()

# ---- precompile patterns ----
IMAGERY_A, IMAGERY_B = imagery_patterns()
TACTICAL_A, TACTICAL_B = tactical_patterns()
VIDEO_A,   VIDEO_B     = video_patterns()

def _within_window(dt, days: int) -> bool:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt >= datetime.now(timezone.utc) - timedelta(days=days)

def _mb(b: int) -> float:
    return b / (1024.0 * 1024.0)

# ---------------- validators (same logic as your script) ----------------
def validate_imagery(file_name: str, all_names_lower: set, size_bytes: int):
    name_lower = file_name.lower()

    if is_system_derivative(name_lower):
        return True, "system-generated derivative; naming ignored."
    if name_lower.endswith(".kml"):
        return True, "system-generated KML in IMAGERY; naming ignored."
    if name_lower.endswith(".png.aux.xml"):
        return True, "PNG auxiliary metadata file (.png.aux.xml); valid companion."

    base, ext = os.path.splitext(name_lower)

    if name_lower.endswith(IMAGERY_SYSTEM_KMZ_EXT):
        if _mb(size_bytes) > IMAGERY_KMZ_MAX_MB:
            return False, f"system-generated KMZ exceeds {IMAGERY_KMZ_MAX_MB} MB."
        return True, "system-generated KMZ within size limit."

    if ext not in IMAGERY_VALID_INPUT_EXTS:
        return False, f"unexpected file type '{ext}' in IMAGERY (only .tif/.tiff or .png + .aux.xml)."

    tokens = file_name.split("_")
    if len(tokens) >= 1 and not hyphen_only_okay(tokens[0]):
        return False, "mission name contains invalid characters (only letters/digits/hyphens)."

    matchedA = bool(IMAGERY_A.match(file_name))
    matchedB = bool(IMAGERY_B.match(file_name))
    if not (matchedA or matchedB):
        return False, "does not match IMAGERY Option A/B naming pattern."

    if ext == ".png":
        tiff_candidates = [
            f"{os.path.splitext(file_name)[0]}.tif".lower(),
            f"{os.path.splitext(file_name)[0]}.tiff".lower()
        ]
        if any(t in all_names_lower for t in tiff_candidates):
            return True, "system-generated PNG from TIF/TIFF; naming ignored."

        aux_candidate = f"{os.path.splitext(file_name)[0]}.png.aux.xml".lower()
        if aux_candidate not in all_names_lower:
            return False, "PNG missing matching .png.aux.xml companion with same mission and timestamp."

        return True, "valid PNG + .png.aux.xml user upload."

    return True, "valid IMAGERY input."

def validate_tactical(file_name: str, size_bytes: int):
    name_lower = file_name.lower()
    if is_system_derivative(name_lower):
        return True, "system-generated derivative; naming ignored."
    if re.search(r"_(dps)(?:_|\.|$)", name_lower):
        return True, "DPS product type is system-generated; naming ignored."

    base, ext = os.path.splitext(name_lower)
    if ext not in TACTICAL_VALID_INPUT_EXTS:
        return False, "only .kml or .kmz are allowed in TACTICAL."

    mA = TACTICAL_A.match(file_name)
    mB = TACTICAL_B.match(file_name)
    if not (mA or mB):
        return False, "missing or invalid product type (must match approved TACTICAL types)."

    if re.search(r"_PERIM_", file_name, re.IGNORECASE):
        if re.search(r"_[0-9]+\.[0-9]+(acres|ac)?\.", name_lower):
            return False, "acres value must be a whole number (e.g., 7acres not 7.2acres)."

    tokens = file_name.split("_")
    if len(tokens) >= 1 and not hyphen_only_okay(tokens[0]):
        return False, "mission name contains invalid characters (only letters/digits/hyphens)."

    return True, "valid TACTICAL input."

def validate_video(file_name: str, all_names_lower: set, size_bytes: int):
    name_lower = file_name.lower()
    if is_system_derivative(name_lower):
        return True, "system-generated derivative; naming ignored."

    base, ext = os.path.splitext(name_lower)
    if ext not in [".ts", ".mp4", ".kml"]:
        return False, f"unexpected file type '{ext}' in VIDEO (only .ts, .mp4 + .kml allowed)."

    tokens = file_name.split("_")
    if len(tokens) >= 1 and not hyphen_only_okay(tokens[0]):
        return False, "mission name contains invalid characters (only letters/digits/hyphens)."

    matchedA = bool(VIDEO_A.match(file_name))
    matchedB = bool(VIDEO_B.match(file_name))
    if not (matchedA or matchedB):
        return False, "does not match VIDEO Option A/B naming pattern."

    if ext == ".ts":
        return True, "valid standalone TS upload (user input)."

    if ext == ".mp4":
        ts_candidate = f"{os.path.splitext(file_name)[0]}.ts".lower()
        if ts_candidate in all_names_lower:
            return True, "system-generated MP4 from TS; ignored."

        kml_candidate = f"{os.path.splitext(file_name)[0]}.kml".lower()
        if kml_candidate in all_names_lower:
            if _mb(size_bytes) > VIDEO_MP4_MAX_MB:
                return False, f"MP4 exceeds size limit ({VIDEO_MP4_MAX_MB} MB)."
            return True, "valid MP4 + KML user upload."

        return False, "MP4 missing matching .kml companion and not generated from TS."

    if ext == ".kml":
        mp4_candidate = f"{os.path.splitext(file_name)[0]}.mp4".lower()
        ts_candidate = f"{os.path.splitext(file_name)[0]}.ts".lower()
        if mp4_candidate in all_names_lower or ts_candidate in all_names_lower:
            return True, "system-generated KML from video; ignored."
        return False, "standalone KML found in VIDEO without companion MP4."

    return True, "valid VIDEO input."

# ---------------- S3 scanning ----------------
DEFAULT_BUCKETS = [
    "aeveximagery", "bia-iaa", "mtstate-iaa1", "spuraviationiaa", "wastate-n216kq",
    "fsagencyiaa", "orstate", "snccostate", "bodeintel", "courtneyimagery",
    "sbcnova", "costatenova", "coulsoniaa", "ocfa-uas"
]

def check_bucket(bucket: str, window_days: int, client) -> List[Dict[str, Any]]:
    malformed: List[Dict[str, Any]] = []
    paginator = client.get_paginator("list_objects_v2")

    all_keys, objs = [], []
    for page in paginator.paginate(Bucket=bucket):
        contents = page.get("Contents", [])
        objs.extend(contents)
        for o in contents:
            all_keys.append(o["Key"])

    all_names_lower = {os.path.basename(k).lower() for k in all_keys}

    for obj in objs:
        key = obj.get("Key")
        if not key or key.endswith("/"):
            continue

        folder = key.split("/")[0] if "/" in key else "NoFolder"
        if folder not in SCAN_FOLDERS:
            continue

        lm = obj.get("LastModified")
        if not lm or not _within_window(lm, window_days):
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
                "bucket": bucket,
                "folder": folder,
                "file_name": name,
                "issue": reason
            })
            logger.warning("[%s] %s: %s", folder, name, reason)

    return malformed

# ---------------- HTTP route ----------------
@app.function_name(name="S3Crawler")
@app.route(route="scan", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def scan(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json(silent=True) or {}
        buckets = body.get("buckets") or DEFAULT_BUCKETS
        try:
            window_days = int(body.get("window_days") or os.environ.get("PAST_DAYS_WINDOW", PAST_DAYS_WINDOW))
        except Exception:
            window_days = PAST_DAYS_WINDOW

        start = datetime.utcnow().isoformat() + "Z"
        out: List[Dict[str, Any]] = []
        for b in buckets:
            out.extend(check_bucket(b, window_days, s3))
        end = datetime.utcnow().isoformat() + "Z"

        resp = {
            "malformed": out,
            "checked_buckets": buckets,
            "window_days": window_days,
            "scan_start": start,
            "scan_end": end,
            "count": len(out)
        }
        return func.HttpResponse(json.dumps(resp), mimetype="application/json", status_code=200)

    except Exception as e:
        logger.exception("scan failed")
        return func.HttpResponse(json.dumps({"error": str(e)}), mimetype="application/json", status_code=500)
