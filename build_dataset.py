"""
Build an enriched vulnerability-exploitation dataset.

Source A: CISA Known Exploited Vulnerabilities (KEV) catalog
          https://github.com/cisagov/kev-data
Source B: MITRE CVE Program record list (CVE List V5)
          https://github.com/CVEProject/cvelistV5

Every CVE in the KEV catalog is joined to its authoritative CVE Program record, from
which CVSS v3.1 vector components, CISA SSVC decision points, CWE identifiers,
publication dates and reference counts are extracted.

Run from the project folder. Reads data/cisa_kev_catalog.csv (downloaded from Source A
if missing) and writes data/kev_cve_enriched_raw.csv. That file is the snapshot the
notebook analyses, so the script will not replace it unless run with --force.
"""
import json
import re
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.csv"
HDR = {"User-Agent": "coursework-dataset-builder"}

DATADIR = Path("data")
KEV_PATH = DATADIR / "cisa_kev_catalog.csv"
OUT_PATH = DATADIR / "kev_cve_enriched_raw.csv"


def record_url(cve: str) -> str:
    _, year, num = cve.split("-")
    return f"{BASE}/{year}/{num[:-3]}xxx/{cve}.json"


def fetch(cve: str, retries: int = 3):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(record_url(cve), headers=HDR)
            with urllib.request.urlopen(req, timeout=30) as r:
                return cve, json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return cve, None
            time.sleep(1.5 * (attempt + 1))
        except Exception:
            time.sleep(1.5 * (attempt + 1))
    return cve, None


CWE_RE = re.compile(r"CWE-\d+")


def parse(cve: str, j: dict) -> dict:
    out = {"cveID": cve}
    if not j:
        return out

    meta = j.get("cveMetadata", {})
    out["datePublished"] = (meta.get("datePublished") or "")[:10] or None
    out["dateReserved"] = (meta.get("dateReserved") or "")[:10] or None
    out["assignerShortName"] = meta.get("assignerShortName")
    out["cveState"] = meta.get("state")

    cna = j["containers"].get("cna", {})
    adps = j["containers"].get("adp", [])

    # description
    descs = [d.get("value", "") for d in cna.get("descriptions", []) if d.get("lang", "en").startswith("en")]
    desc = descs[0] if descs else ""
    out["description"] = desc
    out["desc_word_count"] = len(desc.split())

    # references: count across cna + adp
    refs = list(cna.get("references", []))
    for a in adps:
        refs += a.get("references", [])
    seen, uniq = set(), []
    for r in refs:
        u = r.get("url")
        if u and u not in seen:
            seen.add(u)
            uniq.append(r)
    out["reference_count"] = len(uniq)
    tags = {t for r in uniq for t in r.get("tags", [])}
    out["has_exploit_reference"] = int(bool(tags & {"exploit", "x_transferred-exploit"}))
    out["has_patch_reference"] = int(bool(tags & {"patch", "vendor-advisory"}))

    # CWE from cna and adp problemTypes
    cwes = set()
    for container in [cna] + adps:
        for pt in container.get("problemTypes", []):
            for d in pt.get("descriptions", []):
                if d.get("cweId"):
                    cwes.add(d["cweId"])
                cwes.update(CWE_RE.findall(d.get("description", "") or ""))
    out["cwe_list"] = ";".join(sorted(cwes)) if cwes else None
    out["cwe_count"] = len(cwes)
    out["cwe_primary"] = sorted(cwes)[0] if cwes else None

    # CVSS: prefer v3.1, fall back to v3.0; search cna then adp
    cvss = None
    for container in [cna] + adps:
        for m in container.get("metrics", []):
            for key in ("cvssV3_1", "cvssV3_0"):
                if key in m and m[key].get("baseScore") is not None:
                    cvss = m[key]
                    break
            if cvss:
                break
        if cvss:
            break

    if cvss:
        out["cvss_base_score"] = cvss.get("baseScore")
        out["cvss_severity"] = cvss.get("baseSeverity")
        out["attack_vector"] = cvss.get("attackVector")
        out["attack_complexity"] = cvss.get("attackComplexity")
        out["privileges_required"] = cvss.get("privilegesRequired")
        out["user_interaction"] = cvss.get("userInteraction")
        out["scope_changed"] = cvss.get("scope")
        out["confidentiality_impact"] = cvss.get("confidentialityImpact")
        out["integrity_impact"] = cvss.get("integrityImpact")
        out["availability_impact"] = cvss.get("availabilityImpact")
        out["cvss_vector"] = cvss.get("vectorString")

    # CISA SSVC decision points
    for a in adps:
        for m in a.get("metrics", []):
            o = m.get("other", {})
            if o.get("type") == "ssvc":
                for opt in o.get("content", {}).get("options", []):
                    for k, v in opt.items():
                        out["ssvc_" + k.lower().replace(" ", "_")] = v

    # affected product count
    aff = cna.get("affected", [])
    out["affected_entry_count"] = len(aff)
    return out


def load_kev() -> pd.DataFrame:
    # Use the committed catalog snapshot if present; otherwise download the current one.
    if not KEV_PATH.exists():
        print(f"{KEV_PATH} not found. Downloading the current KEV catalog...")
        DATADIR.mkdir(exist_ok=True)
        req = urllib.request.Request(KEV_URL, headers=HDR)
        with urllib.request.urlopen(req, timeout=60) as r:
            KEV_PATH.write_bytes(r.read())
    return pd.read_csv(KEV_PATH)


def main():
    if OUT_PATH.exists() and "--force" not in sys.argv[1:]:
        sys.exit(f"{OUT_PATH} already exists and is the snapshot the notebook analyses. "
                 "Re-run with --force to replace it.")
    kev = load_kev()
    ids = kev["cveID"].tolist()
    print(f"KEV catalog: {len(ids):,} CVEs. Fetching CVE Program records...")

    t0 = time.time()
    rows, done = [], 0
    with ThreadPoolExecutor(max_workers=24) as ex:
        for cve, j in ex.map(fetch, ids):
            rows.append(parse(cve, j))
            done += 1
            if done % 250 == 0:
                print(f"  {done:>5}/{len(ids)}  ({time.time()-t0:.0f}s)")

    cve_df = pd.DataFrame(rows)
    print(f"Fetched {len(cve_df):,} records in {time.time()-t0:.0f}s")
    print(f"  records with CVSS : {cve_df['cvss_base_score'].notna().sum():,}")
    print(f"  records with CWE  : {cve_df['cwe_primary'].notna().sum():,}")
    print(f"  records missing   : {cve_df['datePublished'].isna().sum():,}")

    merged = kev.merge(cve_df, on="cveID", how="left", validate="one_to_one")
    merged.to_csv(OUT_PATH, index=False)
    print(f"\nSaved {OUT_PATH}: {merged.shape[0]:,} rows x {merged.shape[1]} columns")


if __name__ == "__main__":
    main()
