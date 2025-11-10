#!/usr/bin/env python3
import os, re, json, argparse
from typing import Dict, Any, List, Optional, Tuple

SRC_REPO = "source/src/test"
INCIDENTS_PATH = "incidents.json"
ROOTCAUSE_PATH = "rootcause_data.json"
GITHUB_BASE = "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/"
OVERRIDES_PATH = "scripts/overrides.json"


# -----------------------------
# Helpers
# -----------------------------

def _load_overrides() -> Dict[str, Dict[str, Any]]:
    """Load optional per-contract overrides.

    Schema (array or object) examples:
    - [{"contract": "src/test/2025-07/gmx_exp.sol", "date": "20250709", ... }]
    - {"src/test/2025-07/gmx_exp.sol": {"date": "20250709", ...}}

    Returns a mapping keyed by normalized contract path.
    """
    if not os.path.exists(OVERRIDES_PATH):
        return {}
    try:
        with open(OVERRIDES_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, list):
            out = {}
            for item in raw:
                if not isinstance(item, dict):
                    continue
                key = item.get("contract") or item.get("Contract")
                if not key:
                    continue
                out[str(key)] = item
            return out
        elif isinstance(raw, dict):
            return raw
    except Exception:
        return {}
    return {}


def _norm_start_ym(s: Optional[str]) -> Optional[str]:
    """Normalize a year-month string to YYYYMM or return None.

    Accepts forms like '202505' or '2025-05'.
    """
    if not s:
        return None
    digits = re.sub(r"[^0-9]", "", str(s))
    return digits[:6] if len(digits) >= 6 else None


def _normalize_currency(token: str) -> str:
    t = (token or "").upper().replace("US$", "USD").replace("$", "USD").strip()
    if t in {"USD$", "US D", "US", "U S D"}:
        t = "USD"
    return t


def _parse_loss_and_currency(text: str) -> Tuple[float, str]:
    """Parse loss and currency from file content.

    Handles patterns like:
      - "Total Lost : 285.7K USD"
      - "Total Lost: ~1.7M US$"
      - "Total Lost - $6.8k"
      - "Total Lost : 4.1M VUSD"
    Returns (lost_numeric, currency)
    """
    lost = 0.0
    currency = "USD"
    if not text:
        return lost, currency

    # Broad search around @KeyInfo but tolerant
    # Capture number, optional suffix, optional currency-like token
    m = re.search(
        r"(?:Total\s+)?Lo(?:ss|st)\s*[:\-]\s*~?\s*\$?\s*"
        r"([0-9][0-9,\.]*?)\s*([KMBkmb]?)\s*([A-Za-z$]{0,6})?",
        text,
        re.IGNORECASE,
    )
    if not m:
        return lost, currency

    num_s = m.group(1).replace(",", "")
    suf = (m.group(2) or "").upper()
    cur = _normalize_currency(m.group(3) or "USD")

    try:
        base = float(num_s)
    except Exception:
        base = 0.0

    mult = 1.0
    if suf == "K":
        mult = 1_000
    elif suf == "M":
        mult = 1_000_000
    elif suf == "B":
        mult = 1_000_000_000

    # If currency looked like just '$', we normalized to USD already
    return base * mult, cur or "USD"


def _parse_type(text: str) -> str:
    if not text:
        return ""
    m = re.search(r"@Type\s*[:\-]\s*([^\n\r]+)", text, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _parse_chain(text: str) -> str:
    if not text:
        return "Unknown"
    m = re.search(r"createSelectFork\(\s*\"([a-zA-Z0-9_\-]+)\"", text)
    if not m:
        return "Unknown"
    net = m.group(1).lower()
    mapping = {
        "mainnet": "Ethereum",
        "eth_mainnet": "Ethereum",
        "ethereum": "Ethereum",
        "bsc": "BSC",
        "bnb": "BSC",
        "arbitrum": "Arbitrum",
        "arb": "Arbitrum",
        "base": "Base",
        "polygon": "Polygon",
        "matic": "Polygon",
        "optimism": "Optimism",
        "op": "Optimism",
        "fantom": "Fantom",
        "avalanche": "Avalanche",
        "avax": "Avalanche",
        "scroll": "Scroll",
        "blast": "Blast",
        "linea": "Linea",
    }
    return mapping.get(net, net.capitalize())


def _pretty_default_name(filename: str) -> str:
    base = filename.replace("_exp.sol", "").replace("_", " ")
    return base


def update_incidents(start_ym: Optional[str] = None, preserve_order: bool = False):
    """Append new exploit PoCs from DeFiHackLabs into incidents.json."""
    overrides = _load_overrides()
    # Normalize filter once
    start_ym = _norm_start_ym(start_ym)
    incidents: List[Dict[str, Any]] = []
    existing_contracts = set()
    existing_by_contract: Dict[str, Dict[str, Any]] = {}
    if os.path.exists(INCIDENTS_PATH):
        with open(INCIDENTS_PATH, "r", encoding="utf-8") as f:
            incidents = json.load(f)
            for x in incidents:
                c = x.get("Contract")
                if c:
                    existing_contracts.add(c)
                    existing_by_contract[c] = x

    for root, _, files in os.walk(SRC_REPO):
        for f in files:
            if not f.endswith("_exp.sol"):
                continue
            rel = os.path.join(root, f).replace("\\", "/").replace("source/", "")
            # Prepare defaults
            name = f.replace("_exp.sol", "")
            m = re.search(r"(\d{4})-(\d{2})", root)
            date = f"{m.group(1)}{m.group(2)}01" if m else "00000000"
            folder_ym = f"{m.group(1)}{m.group(2)}" if m else None
            folder_y = m.group(1) if m else None
            folder_m = m.group(2) if m else None
            # Skip folders older than the requested start year-month
            if start_ym and folder_ym and folder_ym < start_ym:
                continue
            if start_ym and not folder_ym:
                # If folder does not follow YYYY-MM, skip when filtering is requested
                continue
            type_ = ""
            lost = 0.0
            loss_type = "USD"
            chain = "Unknown"

            try:
                text = open(
                    os.path.join("source", rel), encoding="utf-8", errors="ignore"
                ).read()
                # Parse loss and currency from PoC file
                lost, loss_type = _parse_loss_and_currency(text)
                # Parse type
                type_ = _parse_type(text)
                # Parse chain from createSelectFork("<network>")
                chain = _parse_chain(text)

                # KISS: If Total Lost not present in PoC, try sibling README.md
                readme_text = None
                # Try common README filename casings
                readme_candidates = [
                    os.path.join("source", os.path.dirname(rel), "README.md"),
                    os.path.join("source", os.path.dirname(rel), "Readme.md"),
                    os.path.join("source", os.path.dirname(rel), "readme.md"),
                    os.path.join("source", os.path.dirname(rel), "README.MD"),
                ]
                for _p in readme_candidates:
                    try:
                        readme_text = open(_p, encoding="utf-8", errors="ignore").read()
                        if readme_text:
                            break
                    except Exception:
                        readme_text = None

                # Parse README near the PoC reference: date, name, type, loss, contract path
                if readme_text:
                    # Initialize holders
                    rd_date_final: Optional[str] = None
                    rd_type_final: Optional[str] = None
                    rd_name_final: Optional[str] = None
                    rd_contract_final: Optional[str] = None
                    rd_lost_final: Optional[float] = None
                    rd_loss_type_final: Optional[str] = None
                    processed_from_section = False

                    # First attempt: split README into sections by '---' divider and parse the matching section
                    try:
                        sections = re.split(r"^\s*---\s*$", readme_text, flags=re.MULTILINE)
                    except Exception:
                        sections = []

                    if sections:
                        best_idx = -1
                        best_score = -1
                        best_contract = None
                        fname_lower = f.lower()
                        rel_lower = rel.lower()
                        name_lower = name.lower()
                        name_space_lower = name_lower.replace("_", " ")
                        # Score each section for relevance
                        for i, sec in enumerate(sections):
                            s = sec
                            sl = s.lower()
                            score = 0
                            sec_contract = None
                            # Forge contract line in section
                            m_forge = re.search(r"forge\s+test.*--contracts\s+(\S+_exp\.sol)", s, re.IGNORECASE)
                            if m_forge:
                                score = max(score, 3)
                                sec_contract = m_forge.group(1).lstrip("./")
                            # Markdown contract link in section
                            m_mdlink = re.search(r"\[([^\]]+_exp\.sol)\]\((src/test/[^\)]+)\)", s, re.IGNORECASE)
                            if m_mdlink:
                                score = max(score, 2)
                                sec_contract = m_mdlink.group(2)
                            # Contract block: 'Contract' then filename
                            m_contract_block = re.search(r"####?\s*Contract[\s\S]{0,80}?\((src/test/[^\)]+)\)", s, re.IGNORECASE)
                            if m_contract_block:
                                score = max(score, 2)
                                sec_contract = m_contract_block.group(1)
                            # Direct mentions
                            if fname_lower in sl or rel_lower in sl:
                                score = max(score, 2)
                            if name_lower in sl or name_space_lower in sl:
                                score = max(score, 1)
                            # Prefer sections that reference our specific filename
                            if score > best_score and (fname_lower in sl or sec_contract or rel_lower in sl):
                                best_score = score
                                best_idx = i
                                best_contract = sec_contract

                        if best_idx >= 0 and best_score > 0:
                            sec = sections[best_idx]
                            lines = sec.splitlines()

                            # Header patterns
                            pat_hdr = re.compile(
                                r"^[#*\-\s]*"
                                r"(?P<date>(?:\d{8}|\d{4}[\-.]\d{2}[\-.]\d{2}))\s+"
                                r"(?P<proj>.+?)\s+[-–—:]\s+(?P<type>[^|#\r\n]+)",
                                re.IGNORECASE,
                            )
                            pat_hdr_nodate = re.compile(
                                r"^[#*\-\s]*(?P<proj>.+?)\s+[-–—:]\s+(?P<type>[^|#\r\n]+)",
                                re.IGNORECASE,
                            )

                            def _norm_date(date_raw: str) -> Optional[str]:
                                if not date_raw:
                                    return None
                                if "-" in date_raw or "." in date_raw:
                                    parts = re.split(r"[-.]", date_raw)
                                    if len(parts) == 3 and all(p.isdigit() for p in parts):
                                        return f"{parts[0]}{parts[1]}{parts[2]}"
                                    return None
                                return date_raw if len(date_raw) == 8 and date_raw.isdigit() else None

                            # Find first header line in section
                            for ln in lines:
                                m1 = pat_hdr.match(ln.strip())
                                if m1:
                                    rd_date_final = _norm_date(m1.group("date"))
                                    rd_name_final = (m1.group("proj") or "").strip()
                                    t = (m1.group("type") or "").strip()
                                    if "|" in t:
                                        t = t.split("|", 1)[0].strip()
                                    rd_type_final = t
                                    break
                                m2 = pat_hdr_nodate.match(ln.strip())
                                if m2 and not rd_name_final and not rd_type_final:
                                    rd_name_final = (m2.group("proj") or "").strip()
                                    t = (m2.group("type") or "").strip()
                                    if "|" in t:
                                        t = t.split("|", 1)[0].strip()
                                    rd_type_final = t
                                    # No date: leave rd_date_final None

                            # Loss within section
                            for ln in lines:
                                m_loss = re.search(
                                    r"(?:Total\s+)?Lo(?:ss|st)\s*[:\-]\s*~?\s*\$?\s*([0-9][0-9,\.]*?)\s*([KMBkmb]?)\s*([A-Za-z$]{0,10})?",
                                    ln,
                                    re.IGNORECASE,
                                )
                                if not m_loss:
                                    m_loss = re.search(r"^\s*#+\s*Lost:?\s+([0-9][0-9,\.]*)(?:\s*([KMBkmb]))?(?:\s+([A-Za-z$]{1,10}))?",
                                                       ln, re.IGNORECASE)
                                if not m_loss:
                                    continue
                                try:
                                    base = float((m_loss.group(1) or "0").replace(",", ""))
                                except Exception:
                                    base = 0.0
                                suf = (m_loss.group(2) or "").upper()
                                mult = 1.0
                                if suf == "K":
                                    mult = 1_000
                                elif suf == "M":
                                    mult = 1_000_000
                                elif suf == "B":
                                    mult = 1_000_000_000
                                rd_lost_final = base * mult
                                rd_loss_type_final = _normalize_currency(m_loss.group(3) or "USD")
                                break

                            # Contract from best_contract if found
                            if best_contract:
                                rd_contract_final = best_contract

                            # Apply from section
                            if rd_name_final or rd_type_final or rd_date_final or rd_lost_final is not None or rd_contract_final:
                                if rd_name_final:
                                    name = rd_name_final
                                if rd_date_final:
                                    date = rd_date_final
                                if rd_type_final:
                                    type_ = rd_type_final
                                if rd_lost_final is not None:
                                    lost = rd_lost_final
                                if rd_loss_type_final:
                                    loss_type = rd_loss_type_final
                                if rd_contract_final:
                                    cpath = rd_contract_final.replace("\\", "/").lstrip("./")
                                    if cpath.startswith("src/test/"):
                                        rel = cpath
                                    else:
                                        if folder_y and folder_m and cpath.lower().endswith("_exp.sol") and "/" not in cpath:
                                            rel = f"src/test/{folder_y}-{folder_m}/{cpath}"
                                processed_from_section = True

                    # Fallback to previous line/window based parsing if section parsing didn't yield
                    if processed_from_section:
                        lines = []  # Skip legacy path
                    else:
                        lines = readme_text.splitlines()
                    fname_lower = f.lower()
                    rel_lower = rel.lower()
                    # Include project name variants for anchoring
                    name_lower = name.lower()
                    name_space_lower = name_lower.replace("_", " ")

                    # Build prioritized anchor indices to avoid "Index" link blocks
                    anchors_primary = []
                    anchors_secondary = []
                    md_link_contract_pat = re.compile(r"\[[^\]]*" + re.escape(f.lower()) + r"\]\((src/test/[^\)]+)\)", re.IGNORECASE)
                    for i, ln in enumerate(lines):
                        lower = ln.lower()
                        # Highest priority: forge command referencing a contract
                        if re.search(r"forge\s+test.*--contracts\s+\S+_exp\.sol", ln, re.IGNORECASE):
                            anchors_primary.append(i)
                            continue
                        # Direct filename/path mention
                        if fname_lower in lower or rel_lower in lower:
                            anchors_primary.append(i)
                            continue
                        # Markdown link that directly references this contract
                        if md_link_contract_pat.search(lower):
                            anchors_primary.append(i)
                            continue
                    # Secondary: lines that mention the project name but are not markdown link index items
                    if not anchors_primary:
                        for i, ln in enumerate(lines):
                            s = ln.strip()
                            lower = s.lower()
                            if s.startswith("["):
                                # Likely an index line; skip in secondary pass
                                continue
                            if name_lower in lower or name_space_lower in lower:
                                anchors_secondary.append(i)
                        # Also consider lines that look like headers with a leading date
                        if not anchors_secondary:
                            for i, ln in enumerate(lines):
                                if re.match(r"^[#*\-\s]*\d{4}[-.]?\d{2}[-.]?\d{2}\b", ln):
                                    anchors_secondary.append(i)

                    anchor_idxs = anchors_primary or anchors_secondary

                    # Also consider 'Contract' block listing the filename on the next line
                    for i, ln in enumerate(lines):
                        if re.match(r"^\s*contract\s*$", ln, re.IGNORECASE):
                            # Find next non-empty line
                            k = i + 1
                            while k < len(lines) and not lines[k].strip():
                                k += 1
                            if k < len(lines) and lines[k].strip().lower().endswith("_exp.sol"):
                                if fname_lower in lines[k].strip().lower():
                                    anchor_idxs.append(i)
                                    # Also capture filename as potential contract path if rd_contract_final not set
                    

                    # Regex allowing bullets and multiple date formats and dash variants
                    pat_hdr = re.compile(
                        r"^[#*\-\s]*"
                        r"(?P<date>(?:\d{8}|\d{4}[\-.]\d{2}[\-.]\d{2}))\s+"
                        r"(?P<proj>.+?)\s+[-–—:]\s+(?P<type>[^|#\r\n]+)",
                        re.IGNORECASE,
                    )

                    # If still not set from section parsing, initialize for legacy
                    if not processed_from_section:
                        rd_date_final = None
                        rd_type_final = None
                        rd_name_final = None
                        rd_contract_final = None
                        rd_lost_final = None
                        rd_loss_type_final = None

                    def _norm_date(date_raw: str) -> Optional[str]:
                        if not date_raw:
                            return None
                        if "-" in date_raw or "." in date_raw:
                            parts = re.split(r"[-.]", date_raw)
                            if len(parts) == 3 and all(p.isdigit() for p in parts):
                                return f"{parts[0]}{parts[1]}{parts[2]}"
                            return None
                        return date_raw if len(date_raw) == 8 and date_raw.isdigit() else None

                    # Secondary header pattern without date (e.g., "Project - Type")
                    pat_hdr_nodate = re.compile(
                        r"^[#*\-\s]*" r"(?P<proj>.+?)\s+[-–—:]\s+(?P<type>[^|#\r\n]+)",
                        re.IGNORECASE,
                    )

                    # Search around anchors
                    window = 30
                    for idx in ([] if processed_from_section else (anchor_idxs or range(len(lines)))):
                        # Look for forge contract line to capture Contract path
                        m_forge = re.search(r"forge\s+test.*--contracts\s+(\S+_exp\.sol)", lines[idx], re.IGNORECASE)
                        if m_forge and not rd_contract_final:
                            rd_contract_final = m_forge.group(1).lstrip("./")

                        # Search upward for header
                        for j in range(max(0, idx - window), idx + 1):
                            m_hdr = pat_hdr.match(lines[j].strip())
                            if m_hdr:
                                rd_date_final = _norm_date(m_hdr.group("date")) or rd_date_final
                                # Clean type
                                t = (m_hdr.group("type") or "").strip()
                                if "|" in t:
                                    t = t.split("|", 1)[0].strip()
                                rd_type_final = t or rd_type_final
                                # Name from header
                                proj = (m_hdr.group("proj") or "").strip()
                                rd_name_final = proj or rd_name_final
                                break
                            # Try header without date if date-form header not present
                            m_hdr2 = pat_hdr_nodate.match(lines[j].strip())
                            if m_hdr2 and not rd_name_final and not rd_type_final:
                                t = (m_hdr2.group("type") or "").strip()
                                if "|" in t:
                                    t = t.split("|", 1)[0].strip()
                                rd_type_final = t or rd_type_final
                                proj = (m_hdr2.group("proj") or "").strip()
                                rd_name_final = proj or rd_name_final

                        # Search downward for loss line near header/anchor
                        for j in range(idx, min(len(lines), idx + window)):
                            lnum = lines[j]
                            # Markdown contract link in proximity: [Name_exp.sol](src/test/YYYY-MM/Name_exp.sol)
                            if not rd_contract_final:
                                m_mdlink = re.search(r"\[([^\]]+_exp\.sol)\]\((src/test/[^\)]+)\)", lnum, re.IGNORECASE)
                                if m_mdlink:
                                    rd_contract_final = m_mdlink.group(2)

                            m_loss = re.search(
                                r"(?:Total\s+)?Lo(?:ss|st)\s*[:\-]\s*~?\s*\$?\s*([0-9][0-9,\.]*?)\s*([KMBkmb]?)\s*([A-Za-z$]{0,10})?",
                                lnum,
                                re.IGNORECASE,
                            )
                            if not m_loss:
                                # Secondary heading-style loss: '### Lost: 15,261.68 BUSD'
                                m_loss = re.search(r"^\s*#+\s*Lost:?\s+([0-9][0-9,\.]*)(?:\s*([KMBkmb]))?(?:\s+([A-Za-z$]{1,10}))?",
                                                   lnum, re.IGNORECASE)
                                if not m_loss:
                                    continue
                            # Convert loss number with suffix
                            try:
                                base = float((m_loss.group(1) or "0").replace(",", ""))
                            except Exception:
                                base = 0.0
                            suf = (m_loss.group(2) or "").upper()
                            mult = 1.0
                            if suf == "K":
                                mult = 1_000
                            elif suf == "M":
                                mult = 1_000_000
                            elif suf == "B":
                                mult = 1_000_000_000
                            rd_lost_final = base * mult
                            rd_loss_type_final = _normalize_currency(m_loss.group(3) or "USD")
                            break

                        if rd_date_final or rd_type_final or rd_lost_final is not None or rd_contract_final:
                            # We found relevant info near this anchor; stop scanning further anchors
                            break

                    # Apply README-derived fields with priority
                    if rd_name_final:
                        name = rd_name_final
                    if rd_date_final:
                        # Prefer README-provided specific date
                        date = rd_date_final
                    if rd_type_final:
                        type_ = rd_type_final
                    if rd_lost_final is not None:
                        lost = rd_lost_final
                    if rd_loss_type_final:
                        loss_type = rd_loss_type_final
                    if rd_contract_final:
                        # Normalize contract path relative to repo root
                        cpath = rd_contract_final.replace("\\", "/").lstrip("./")
                        # If it looks like src/test/... keep as-is; else fallback to rel
                        if cpath.startswith("src/test/"):
                            rel = cpath
                        else:
                            # If it is just a filename, construct with current folder year-month
                            if folder_y and folder_m and cpath.lower().endswith("_exp.sol") and "/" not in cpath:
                                rel = f"src/test/{folder_y}-{folder_m}/{cpath}"

            except Exception:
                pass

            # Apply overrides if any
            ov = overrides.get(rel)
            if ov:
                date = ov.get("date", date)
                # Name override
                name = ov.get("name", name)
                # Type override
                type_ = ov.get("type", type_)
                # Loss override
                lost = ov.get("Lost", lost)
                loss_type = ov.get("lossType", ov.get("loss_type", loss_type))
                # Chain override
                chain = ov.get("chain", chain)

            # If already exists in JSON, update it (workflow-friendly) and skip append
            if rel in existing_contracts:
                item = existing_by_contract[rel]
                # Merge fields (prefer overrides and parsed values when present)
                if date:
                    item["date"] = date
                if name:
                    item["name"] = name
                if type_:
                    item["type"] = type_
                if isinstance(lost, (int, float)) and lost != 0.0:
                    item["Lost"] = float(lost)
                if loss_type:
                    item["lossType"] = loss_type
                if chain:
                    item["chain"] = chain
                continue

            # Fresh entry
            new_item = {
                "date": date,
                "name": name or _pretty_default_name(f),
                "type": type_,
                "Lost": float(lost),
                "lossType": loss_type,
                "Contract": rel,
            }
            if chain:
                new_item["chain"] = chain
            incidents.append(new_item)

    if not preserve_order:
        incidents.sort(key=lambda x: x["date"], reverse=True)
    with open(INCIDENTS_PATH, "w", encoding="utf-8") as f:
        json.dump(incidents, f, indent=2)
    return incidents


def update_rootcause(incidents):
    """Ensure every incident has a matching entry in rootcause_data.json."""
    overrides = _load_overrides()
    if os.path.exists(ROOTCAUSE_PATH):
        with open(ROOTCAUSE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = {}

    added = False
    # Helper: find existing key by contract url
    def _find_key_by_contract(url: str) -> Optional[str]:
        for k, v in data.items():
            if isinstance(v, dict) and v.get("Contract") == url:
                return k
        return None

    for inc in incidents:
        name = inc["name"]
        contract_url = f"{GITHUB_BASE}{inc['Contract']}"

        # If override changed the display name, migrate any existing entry with the same contract link
        existing_key = _find_key_by_contract(contract_url)
        if existing_key and existing_key != name:
            data[name] = data.pop(existing_key)
            added = True

        if name not in data:
            data[name] = {
                "type": inc.get("type", ""),
                "date": f"{inc['date'][:4]}-{inc['date'][4:6]}-{inc['date'][6:]}" if len(inc.get("date", "")) == 8 else "",
                "rootCause": "",
                "images": [],
                "Lost": f"{inc.get('Lost', 0)} {inc.get('lossType', 'USD')}",
                "Contract": contract_url,
            }
            added = True

        # Apply overrides to rootcause entry if present
        ov = overrides.get(inc["Contract"])
        if ov:
            entry = data[name]
            if ov.get("type"):
                entry["type"] = ov["type"]
            if ov.get("date") and len(ov["date"]) == 8:
                entry["date"] = f"{ov['date'][:4]}-{ov['date'][4:6]}-{ov['date'][6:]}"
            # Append link references into rootCause for visibility
            links = ov.get("links") or ov.get("references")
            if links:
                if isinstance(links, str):
                    links = [links]
                refs = "\n".join(f"- {u}" for u in links if isinstance(u, str))
                prefix = "Link reference(s):\n" if refs else ""
                if refs:
                    if entry.get("rootCause"):
                        entry["rootCause"] = entry["rootCause"].rstrip() + "\n\n" + prefix + refs
                    else:
                        entry["rootCause"] = prefix + refs

    if added:
        with open(ROOTCAUSE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    return added


def main():
    parser = argparse.ArgumentParser(description="Update incidents and root cause data from source repo")
    parser.add_argument("--start-ym", dest="start_ym", help="Process only items from this YYYYMM onward (e.g., 202505)", default=None)
    parser.add_argument("--preserve-order", dest="preserve_order", help="Preserve existing incidents.json order and append new items at the end", action="store_true")
    args = parser.parse_args()

    incidents = update_incidents(start_ym=args.start_ym, preserve_order=args.preserve_order)
    added = update_rootcause(incidents)
    print("✅ Data updated." if added else "No new exploits found.")


if __name__ == "__main__":
    main()
