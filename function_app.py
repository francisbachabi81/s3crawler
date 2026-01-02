import os, json, logging, re, ast
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

import azure.functions as func
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet

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


def _load_key_bytes() -> bytes:
    k = os.environ.get("FERNET_KEY")
    if k:
        return k.encode()
    key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secret.key")
    with open(key_path, "rb") as fh:
        return fh.read()


def _decrypt(b: str) -> str:
    key = _load_key_bytes()
    f = Fernet(key)
    token_bytes = ast.literal_eval(b) if (b.startswith("b'") or b.startswith('b"')) else b.encode()
    return f.decrypt(token_bytes).decode()


def _get_env(name: str, default=None, decrypt_if_fernet: bool = True):
    v = os.environ.get(name, default)
    if v is None:
        return None
    if not isinstance(v, str):
        return v
    if decrypt_if_fernet and (v.startswith("gAAAAA") or v.startswith("b'") or v.startswith('b"')):
        try:
            return _decrypt(v)
        except Exception as e:
            raise RuntimeError(f"Failed to decrypt app setting {name}: {e}") from e
    return v


def _default_region() -> str:
    # Read default AWS region from Function App settings; fallback to us-east-1
    return _get_env("AWS_REGION", "us-east-1", decrypt_if_fernet=False)


def _base_s3(region: str = None):
    if not region:
        region = _default_region()
    akid = _get_env("AWS_ACCESS_KEY_ID")
    skey = _get_env("AWS_SECRET_ACCESS_KEY")
    stkn = _get_env("AWS_SESSION_TOKEN")  # optional
    if not akid or not skey:
        raise RuntimeError("Missing AWS_ACCESS_KEY_ID and/or AWS_SECRET_ACCESS_KEY.")
    return boto3.client(
        "s3",
        aws_access_key_id=akid,
        aws_secret_access_key=skey,
        aws_session_token=stkn,
        region_name=region,
        config=BotoConfig(retries={"max_attempts": 10, "mode": "standard"}),
    )


_CLIENTS_BY_REGION: Dict[str, Any] = {}


def client_for_region(region: str):
    if not region:
        region = _default_region()
    if region == "EU":  # legacy alias
        region = "eu-west-1"
    if region not in _CLIENTS_BY_REGION:
        _CLIENTS_BY_REGION[region] = _base_s3(region)
    return _CLIENTS_BY_REGION[region]


def bucket_region(bucket: str) -> str:
    s3_any = _base_s3(_default_region())
    try:
        r = s3_any.get_bucket_location(Bucket=bucket)
        loc = r.get("LocationConstraint")
        return "us-east-1" if not loc else ("eu-west-1" if loc == "EU" else loc)
    except ClientError as e:
        headers = (getattr(e, "response", {}) or {}).get("ResponseMetadata", {}).get("HTTPHeaders", {})
        hinted = headers.get("x-amz-bucket-region")
        if hinted:
            return hinted
        raise


IMAGERY_A, IMAGERY_B = imagery_patterns()
TACTICAL_A, TACTICAL_B = tactical_patterns()
VIDEO_A,   VIDEO_B     = video_patterns()


def _within_window(dt, days: int) -> bool:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt >= datetime.now(timezone.utc) - timedelta(days=days)


def _mb(b: int) -> float:
    return b / (1024.0 * 1024.0)


def validate_imagery(file_name: str, all_names_lower: set, size_bytes: int):
    name_lower = file_name.lower()
    if is_system_derivative(name_lower): return True, "system-generated derivative; naming ignored."
    if name_lower.endswith(".kml"):      return True, "system-generated KML in IMAGERY; naming ignored."
    if name_lower.endswith(".png.aux.xml"): return True, "PNG auxiliary metadata file (.png.aux.xml); valid companion."

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

    if not (IMAGERY_A.match(file_name) or IMAGERY_B.match(file_name)):
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
    if is_system_derivative(name_lower): return True, "system-generated derivative; naming ignored."
    if re.search(r"_(dps)(?:_|\.|$)", name_lower): return True, "DPS product type is system-generated; naming ignored."

    base, ext = os.path.splitext(name_lower)
    if ext not in TACTICAL_VALID_INPUT_EXTS:
        return False, "only .kml or .kmz are allowed in TACTICAL."

    if not (TACTICAL_A.match(file_name) or TACTICAL_B.match(file_name)):
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
    if is_system_derivative(name_lower): return True, "system-generated derivative; naming ignored."

    base, ext = os.path.splitext(name_lower)
    if ext not in [".ts", ".mp4", ".kml"]:
        return False, f"unexpected file type '{ext}' in VIDEO (only .ts, .mp4 + .kml allowed)."

    tokens = file_name.split("_")
    if len(tokens) >= 1 and not hyphen_only_okay(tokens[0]):
        return False, "mission name contains invalid characters (only letters/digits/hyphens)."

    if not (VIDEO_A.match(file_name) or VIDEO_B.match(file_name)):
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
        ts_candidate  = f"{os.path.splitext(file_name)[0]}.ts".lower()
        if mp4_candidate in all_names_lower or ts_candidate in all_names_lower:
            return True, "system-generated KML from video; ignored."
        return False, "standalone KML found in VIDEO without companion MP4."

    return True, "valid VIDEO input."


DEFAULT_BUCKETS = [
    "aeveximagery", "bia-iaa", "mtstate-iaa1", "spuraviationiaa", "wastate-n216kq",
    "fsagencyiaa", "orstate", "snccostate", "bodeintel", "courtneyimagery",
    "sbcnova", "costatenova", "coulsoniaa", "ocfa-uas"
]


def get_default_buckets() -> List[str]:
    csv = _get_env("S3_BUCKETS_CSV", "")
    if csv:
        return [b.strip() for b in csv.split(",") if b.strip()]
    return DEFAULT_BUCKETS


def check_bucket(bucket: str, window_days: int) -> List[Dict[str, Any]]:
    malformed: List[Dict[str, Any]] = []

    region = bucket_region(bucket)
    client = client_for_region(region)

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


def run_scan(window_days: int) -> Dict[str, Any]:
    buckets = get_default_buckets()
    start_dt = datetime.utcnow()
    start_iso = start_dt.isoformat() + "Z"

    results: List[Dict[str, Any]] = []
    for b in buckets:
        results.extend(check_bucket(b, window_days))

    end_dt = datetime.utcnow()
    end_iso = end_dt.isoformat() + "Z"
    duration_ms = int((end_dt - start_dt).total_seconds() * 1000)

    return {
        "malformed": results,
        "telemetry": {
            "window_days": window_days,
            "bucket_count": len(buckets),
            "count": len(results),
            "scan_start": start_iso,
            "scan_end": end_iso,
            "duration_ms": duration_ms
        }
    }


# ---------------- HTTP trigger ----------------
@app.function_name(name="S3CrawlerHttp")
@app.route(route="scan", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def scan(req: func.HttpRequest) -> func.HttpResponse:
    try:
        try:
            body = req.get_json()
        except ValueError:
            body = {}

        try:
            window_days = int(body.get("window_days") or _get_env("PAST_DAYS_WINDOW", PAST_DAYS_WINDOW))
        except Exception:
            window_days = PAST_DAYS_WINDOW

        payload = run_scan(window_days)
        return func.HttpResponse(
            json.dumps(payload),
            status_code=200,
            mimetype="application/json"
        )
    except Exception as e:
        logger.exception("HTTP scan failed")
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )