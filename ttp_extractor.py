import os
import re
import yaml
import json
import requests
import feedparser
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode
import signal
from io import BytesIO
from PIL import Image
import pytesseract
import trafilatura
import collections
import unicodedata
import string
from dateutil.parser import parse as date_parse
import logging
import argparse
from llm_providers import create_provider, LLMProvider

# Try to use curl_cffi for better browser impersonation, fallback to requests
try:
    from curl_cffi import requests as cf_requests
    USE_CURL_CFFI = True
except ImportError:
    USE_CURL_CFFI = False

# Optional: pillow-avif-plugin enables AVIF decoding (Webflow CDN serves these)
try:
    import pillow_avif  # noqa: F401
    AVIF_SUPPORT = True
except ImportError:
    AVIF_SUPPORT = False

# CONFIG
URLS_FILE = "urls.txt"
CACHE_FILE = "processed_urls.txt"
VERBOSE = os.getenv("VERBOSE", "1") == "1"  # Set VERBOSE=0 to disable detailed logging
REQUEST_DELAY = float(os.getenv("REQUEST_DELAY", "2.0"))  # Seconds between requests to same domain
MAX_ARTICLES_PER_SOURCE = int(os.getenv("MAX_ARTICLES_PER_SOURCE", "12"))  # Per-source article cap

# Global LLM provider (initialized in main)
llm_provider: LLMProvider = None

# Global OCR cache - keyed by image URL, persists for the run
# Many sites serve the same chrome/sidebar images on every article
_ocr_cache = {}

# Setup logging - dual output to console and file
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO if VERBOSE else logging.WARNING)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO if VERBOSE else logging.WARNING)
console_handler.setFormatter(logging.Formatter('%(message)s'))

# File handler - always logs everything
file_handler = logging.FileHandler('output.log', mode='w')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))

logger.addHandler(console_handler)
logger.addHandler(file_handler)

PROMPT_TEMPLATE = """You are extracting detection-engineering signals from a threat intelligence report. The output will seed Sigma and Sysmon detection rules, so accuracy matters more than completeness — incorrect data is worse than missing data.

OUTPUT: Return ONLY raw YAML. No markdown fences, no commentary, no preamble.

EXTRACTION RULES:
1. Extract ONLY values that appear verbatim in the report. Do NOT infer, guess, normalize, or invent values to fill fields.
2. If a field has no data in the report, return an empty list: []. Never use null, "N/A", "Unknown", or placeholder text.
3. Preserve full strings: complete command lines, full registry paths, full file paths, full URLs. Do not truncate.
4. If the same value appears in multiple OCR'd forms (e.g., "C:\\Users\\admin\\..." and "C:\\Users\\adimin\\..."), include only the most plausible single canonical version. Drop obvious OCR corruption (impossible IP octets >255, hashes with non-hex characters, paths with stray spaces mid-word).
5. For obfuscated payloads (base64, hex, encoded PowerShell), include them verbatim.
6. Defang IOCs consistently using bracket notation: 192.168.1[.]1, evil[.]com, hxxps://bad[.]com/path. If the report defangs some IOCs and not others, normalize all to the defanged form.
7. Do NOT include detection-rule pseudocode (e.g., "process == cmd.exe AND parent == explorer.exe"). Only extract observed telemetry.

YAML FORMATTING:
- Use block-style lists with "- " prefix, one item per line.
- Do not quote list items unless the value contains a colon followed by a space.
- Empty lists: write as [] on the same line as the key.

SCHEMA:
title: Exact title of the report
description: One or two sentences summarizing the threat
attribution: Named threat actor, APT group, or nation-state. Empty string if not attributed.
malware_families: []
cves: []
ttps:
  processes: []          # process image names only (e.g., powershell.exe)
  command_lines: []      # full process command lines as observed
  powershell: []         # PowerShell scripts or one-liners
  scripts: []            # VBS, JScript, Python, Bash, batch scripts
  registry_keys: []      # full registry paths
  image_loads: []        # DLLs or modules loaded
  network_connections: [] # one per line, format: "process -> destination:port" when known
  file_activity: []      # full file paths created, dropped, modified, or read
  persistence: []        # persistence mechanism descriptions, one per line
  process_relations: []  # parent -> child format, one per line
iocs:
  hashes: []
  ip_addresses: []
  domains: []
  urls: []
authors: []

EXAMPLE INPUT (synthetic - not a real report):
"During analysis we observed the EXAMPLEONLY-loader spawn EXAMPLEONLY-proc.exe with the command 'EXAMPLEONLY-proc.exe -arg EXAMPLEONLY_arg_value'. The malware established persistence via HKCU\\EXAMPLEONLY-key\\Run\\EXAMPLEONLY-entry pointing to C:\\EXAMPLEONLY-path\\EXAMPLEONLY-file.exe. C2 traffic was observed to placeholder.invalid on port 443. SHA256: deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef. Authored by EXAMPLEONLY-AUTHOR-NAME, EXAMPLEONLY-Org."

EXAMPLE OUTPUT (synthetic - shape only - NEVER copy any of these values into your output):
title: ""
description: A loader spawned a process with an argument and established Run-key persistence pointing to a file in a custom directory.
attribution: ""
malware_families: []
cves: []
ttps:
  processes:
    - EXAMPLEONLY-proc.exe
  command_lines:
    - EXAMPLEONLY-proc.exe -arg EXAMPLEONLY_arg_value
  powershell: []
  scripts: []
  registry_keys:
    - HKCU\\EXAMPLEONLY-key\\Run\\EXAMPLEONLY-entry
  image_loads: []
  network_connections:
    - EXAMPLEONLY-proc.exe -> placeholder.invalid:443
  file_activity:
    - C:\\EXAMPLEONLY-path\\EXAMPLEONLY-file.exe
  persistence:
    - Registry Run key (HKCU) pointing to C:\\EXAMPLEONLY-path\\EXAMPLEONLY-file.exe
  process_relations: []
iocs:
  hashes:
    - deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
  ip_addresses: []
  domains:
    - placeholder.invalid
  urls: []
authors:
  - EXAMPLEONLY-AUTHOR-NAME

CRITICAL RULES FOR YOUR OUTPUT - READ CAREFULLY:

1. The example above is SYNTHETIC. Every value in it (EXAMPLEONLY-*, placeholder.invalid, deadbeef hashes) is a marker that exists ONLY to demonstrate schema shape. NONE of these values appear in real reports. NEVER copy any value from the example into your output. If you find yourself emitting "EXAMPLEONLY-proc.exe" or "powershell.exe -NoP -W Hidden -Enc SQBFAFgA..." or "C:\\Users\\Public\\update.exe" or "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater" or "placeholder.invalid" or "deadbeef" hashes - STOP. Those are example values, not real extractions.

2. DO NOT INVENT VALUES TO FILL FIELDS. If the report contains no PowerShell commands, the powershell field MUST be empty: powershell: []. If the report does not mention Windows registry keys, registry_keys MUST be []. If the article is about Android malware, do not include Windows-specific values. If the article is about a CTF binary exploit, do not include malware persistence values. Match the actual content of the report. An empty list is correct and expected when the report does not cover that area.

3. Quote any title, description, or attribution value that contains a colon. Example: title: "Section: Subtitle"

4. Quote any list item that starts with the characters `{`, `[`, `>`, `|`, `&`, `*`, `!`, `%`, `@`, or backtick. These are YAML reserved characters and break parsing if unquoted. Example list item: - "{[Text.Encoding]::UTF8.GetString(...)}"

5. For hashes, output ONLY the hex value with no prefix. Do NOT include "MD5:", "SHA1:", "SHA256:", or "MD5|" prefixes. The hash field accepts any hex string of length 32 (MD5), 40 (SHA1), or 64 (SHA256).

REPORT:
{REPORT_TEXT}
"""

bad_patterns = [
    r"/faq", r"/platform", r"/industry", r"/category", r"/tag",
    r"/features", r"/services", r"/page", r"/newsletter", r"\?paged=\d+",
    r"\?_paged=\d+", r"/about", r"/rsac/", r"/weekly", r"/monthly", r"/quarterly"
]

# Schema constants - must match PROMPT_TEMPLATE
EXPECTED_TTP_FIELDS = [
    'processes', 'command_lines', 'powershell', 'scripts',
    'registry_keys', 'image_loads', 'network_connections',
    'file_activity', 'persistence', 'process_relations'
]
EXPECTED_IOC_FIELDS = ['hashes', 'ip_addresses', 'domains', 'urls']

# Legacy field names (uppercase / old naming) -> canonical lowercase
LEGACY_KEY_MAP = {
    'TTPs': 'ttps',
    'IOCs': 'iocs',
    'CVEs': 'cves',
    'commandline': 'command_lines',
    'command_line': 'command_lines',
    'image_load': 'image_loads',
    'scripting_engine': 'scripts',
}


# Locale path patterns to normalize away during deduplication.
# Matches /blog-uk/, /blog-de/, etc. (2-letter ISO codes) and /uk/blog/, /de/blog/.
# The canonical form is always plain /blog/.
_LOCALE_BLOG_SUFFIX = re.compile(r'/blog-[a-z]{2}(?:-[a-z]{2})?/', re.I)
_LOCALE_BLOG_PREFIX = re.compile(r'/[a-z]{2}/blog/', re.I)


def normalize_url(u: str) -> str:
    """Canonicalize for equality checks: drop fragment, trim trailing slash in
    path, lower host, and collapse locale-specific blog paths to canonical form.

    The locale collapsing means /resources/blog-uk/foo and /resources/blog/foo
    will compare equal - this prevents processing the same article twice when
    a site's RSS feed lists multiple language variants.
    """
    p = urlparse(u.strip())
    path = p.path

    # Collapse /blog-XX/ -> /blog/
    path = _LOCALE_BLOG_SUFFIX.sub('/blog/', path)
    # Collapse /XX/blog/ -> /blog/
    path = _LOCALE_BLOG_PREFIX.sub('/blog/', path)

    path = path.rstrip('/') or '/'
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not k.lower().startswith('utm_')]
    return urlunparse((p.scheme.lower() or 'https', p.netloc.lower(), path, '', urlencode(q), ''))

def read_start_urls() -> set[str]:
    if not os.path.exists(URLS_FILE):
        return set()
    with open(URLS_FILE, 'r') as f:
        return {normalize_url(line) for line in f if line.strip()}


def cross_validate_against_source(merged_data, source_text):
    """Drop fabricated values from fabrication-prone fields by checking
    that each value (or a distinctive substring of it) appears in the source.

    This is the highest-leverage anti-hallucination measure: the model loves
    to fabricate plausible-looking PowerShell commands, registry keys, and
    encoded payloads when the article mentions those concepts but doesn't
    show concrete examples. Cross-validation catches those because the
    fabricated values don't appear anywhere in the actual article text.

    Fields validated (must appear verbatim in source):
      ttps.command_lines
      ttps.powershell
      ttps.scripts (filename items only)
      ttps.registry_keys
      ttps.file_activity
      iocs.hashes
      iocs.ip_addresses
      iocs.domains
      iocs.urls

    Fields NOT validated (paraphrased or synthesized):
      title, description, attribution, persistence, process_relations,
      network_connections (process->dest is synthesized), processes (often
      inferred from command lines), malware_families, cves, image_loads,
      authors

    Args:
        merged_data: the merged YAML dict (mutated in place)
        source_text: the full article text the LLM saw, with all chunks
                     concatenated (HTML body + OCR)

    Returns the modified data and a count of dropped items for logging.
    """
    if not source_text:
        return merged_data, 0

    # Build a normalized, case-folded version of source for substring checks.
    # Keep both fanged and defanged search strings so we match either form.
    src = source_text.lower()
    # Defanged-to-fanged: also build a version of source with defanging stripped
    src_fanged = src.replace('[.]', '.').replace('[:]', ':').replace('hxxp://', 'http://').replace('hxxps://', 'https://').replace('[/', '/')

    dropped = 0

    def in_source(value):
        """Check whether `value` appears in source text in any reasonable form."""
        if not isinstance(value, str) or not value.strip():
            return True  # let empty/non-string pass through other filters
        v = value.strip().lower()
        # Direct match in source (most common)
        if v in src:
            return True
        if v in src_fanged:
            return True
        # Try fanged-equivalent of value
        v_fanged = v.replace('[.]', '.').replace('[:]', ':').replace('hxxp://', 'http://').replace('hxxps://', 'https://').replace('[/', '/')
        if v_fanged in src:
            return True
        if v_fanged in src_fanged:
            return True
        # Try defanged-equivalent of value (in case the article defangs and the LLM didn't)
        v_defanged = re.sub(r'(\w)\.(\w)', r'\1[.]\2', v)
        if v_defanged in src:
            return True
        return False

    def in_source_substring(value, min_substr=20):
        """For long command lines: check if a distinctive substring of the
        value appears in source. We require at least min_substr characters of
        contiguous match to reduce false positives.
        """
        if not isinstance(value, str) or not value.strip():
            return True
        v = value.strip()
        if len(v) < min_substr:
            return in_source(v)
        # Direct check first
        if in_source(v):
            return True
        # Sliding window: check substrings of length min_substr
        v_lower = v.lower()
        # Skip alphabetic-only short tokens; require alphanumeric or path-like content
        for i in range(0, len(v_lower) - min_substr + 1, max(1, min_substr // 2)):
            sub = v_lower[i:i+min_substr]
            # Skip substrings that are mostly whitespace/punctuation
            if sum(c.isalnum() for c in sub) < min_substr * 0.5:
                continue
            if sub in src or sub in src_fanged:
                return True
        return False

    # Process TTPs that should be verbatim
    if isinstance(merged_data.get('ttps'), dict):
        verbatim_fields = ['command_lines', 'powershell', 'registry_keys', 'file_activity']
        for field in verbatim_fields:
            items = merged_data['ttps'].get(field, [])
            if not isinstance(items, list):
                continue
            kept = []
            for item in items:
                # For long command lines and powershell scripts, allow substring match
                if field in ('command_lines', 'powershell') and isinstance(item, str) and len(item) > 30:
                    if in_source_substring(item):
                        kept.append(item)
                    else:
                        dropped += 1
                        logger.debug(f"    Dropped fabricated {field}: {item[:80]}")
                else:
                    if in_source(item):
                        kept.append(item)
                    else:
                        dropped += 1
                        logger.debug(f"    Dropped fabricated {field}: {item}")
            merged_data['ttps'][field] = kept

        # Scripts: validate only items that look like filenames (skip
        # multiline code blocks - those get passed through with substring match).
        scripts = merged_data['ttps'].get('scripts', [])
        if isinstance(scripts, list):
            kept = []
            for item in scripts:
                if not isinstance(item, str):
                    continue
                # If it looks like a filename (short, has extension), require verbatim match
                if len(item) < 100 and re.match(r'^[\w./\\-]+\.\w{1,5}$', item.strip()):
                    if in_source(item):
                        kept.append(item)
                    else:
                        dropped += 1
                        logger.debug(f"    Dropped fabricated script filename: {item}")
                else:
                    # Long script body - use substring match
                    if in_source_substring(item):
                        kept.append(item)
                    else:
                        dropped += 1
                        logger.debug(f"    Dropped fabricated script body: {item[:80]}")
            merged_data['ttps']['scripts'] = kept

    # Process IOCs - all should be verbatim
    if isinstance(merged_data.get('iocs'), dict):
        for field in ['hashes', 'ip_addresses', 'domains', 'urls']:
            items = merged_data['iocs'].get(field, [])
            if not isinstance(items, list):
                continue
            kept = []
            for item in items:
                if in_source(item):
                    kept.append(item)
                else:
                    dropped += 1
                    logger.debug(f"    Dropped fabricated {field}: {item}")
            merged_data['iocs'][field] = kept

    return merged_data, dropped



def normalize_schema(data):
    """Force LLM output into canonical schema regardless of how the model nested things.

    Handles:
    - Legacy uppercase keys (TTPs, IOCs, CVEs)
    - Top-level fields that should be nested under ttps/iocs
    - Missing fields (filled with empty lists)
    - Scalars where lists are expected
    - List items that look like schema placeholders ("- CVE-YYYY-NNNNN", etc.)
    """
    if not isinstance(data, dict):
        return {}

    # 1. Rename legacy keys to canonical names
    for old, new in LEGACY_KEY_MAP.items():
        if old in data:
            if new in data and isinstance(data[new], dict) and isinstance(data[old], dict):
                # merge old into new
                for k, v in data[old].items():
                    if k not in data[new]:
                        data[new][k] = v
                del data[old]
            elif new in data and isinstance(data[new], list) and isinstance(data[old], list):
                data[new].extend(x for x in data[old] if x not in data[new])
                del data[old]
            else:
                data[new] = data.pop(old)

    # Also rename legacy keys inside ttps if they appear there
    if isinstance(data.get('ttps'), dict):
        for old, new in LEGACY_KEY_MAP.items():
            if old in data['ttps']:
                if new in data['ttps']:
                    if isinstance(data['ttps'][new], list) and isinstance(data['ttps'][old], list):
                        data['ttps'][new].extend(x for x in data['ttps'][old] if x not in data['ttps'][new])
                    del data['ttps'][old]
                else:
                    data['ttps'][new] = data['ttps'].pop(old)

    # 2. Ensure ttps and iocs containers exist as dicts
    if not isinstance(data.get('ttps'), dict):
        data['ttps'] = {}
    if not isinstance(data.get('iocs'), dict):
        data['iocs'] = {}

    # 3. Move misnested fields up to ttps/iocs
    for key in list(data.keys()):
        if key in EXPECTED_TTP_FIELDS and key not in data['ttps']:
            data['ttps'][key] = data.pop(key)
        elif key in EXPECTED_IOC_FIELDS and key not in data['iocs']:
            data['iocs'][key] = data.pop(key)

    # 4. Ensure every expected field exists as a list and is actually a list
    for key in EXPECTED_TTP_FIELDS:
        v = data['ttps'].setdefault(key, [])
        if v is None or v == '' or v == '[]':
            data['ttps'][key] = []
        elif isinstance(v, str):
            data['ttps'][key] = _parse_string_as_list(v)
        elif not isinstance(v, list):
            data['ttps'][key] = [v] if v else []

    for key in EXPECTED_IOC_FIELDS:
        v = data['iocs'].setdefault(key, [])
        if v is None or v == '' or v == '[]':
            data['iocs'][key] = []
        elif isinstance(v, str):
            data['iocs'][key] = _parse_string_as_list(v)
        elif not isinstance(v, list):
            data['iocs'][key] = [v] if v else []

    # 5. Top-level list fields
    for key in ['malware_families', 'cves', 'authors']:
        v = data.setdefault(key, [])
        if v is None or v == '' or v == '[]':
            data[key] = []
        elif isinstance(v, str):
            data[key] = _parse_string_as_list(v)
        elif not isinstance(v, list):
            data[key] = [v] if v else []

    # 6. Top-level scalar fields
    for key in ['title', 'description', 'attribution']:
        v = data.get(key)
        if v is None or v == '[]' or (isinstance(v, list) and not v):
            data[key] = ''
        elif isinstance(v, list):
            data[key] = ' '.join(str(x) for x in v if x)

    # 6b. Sanity check the title - reject if it looks like a chunk-boundary
    # artifact (overly long or starts mid-sentence/with a dependent fragment).
    title = str(data.get('title', '')).strip()
    if title and _looks_like_corrupted_title(title):
        data['title'] = ''

    # 7. Strip placeholder/garbage list items
    data = _strip_placeholder_items(data)

    # 7b. Strip markdown link wrappers from list items - trafilatura
    # sometimes emits '[text](url)' for HTML anchors. Convert to just 'text'.
    for container_key in ['ttps', 'iocs']:
        if isinstance(data.get(container_key), dict):
            for field, items in data[container_key].items():
                if isinstance(items, list):
                    data[container_key][field] = [
                        _strip_markdown_link(x) if isinstance(x, str) else x
                        for x in items
                    ]
    for key in ['malware_families', 'cves', 'authors']:
        if isinstance(data.get(key), list):
            data[key] = [
                _strip_markdown_link(x) if isinstance(x, str) else x
                for x in data[key]
            ]

    # 8. Normalize hashes - strip prefixes, validate hex, dedupe
    if isinstance(data.get('iocs'), dict):
        if isinstance(data['iocs'].get('hashes'), list):
            data['iocs']['hashes'] = _normalize_hashes(data['iocs']['hashes'])

        # Filter RFC reserved IPs - these are never legitimate IOCs
        # (192.168.x.x, 10.x.x.x, 127.x.x.x, etc.)
        if isinstance(data['iocs'].get('ip_addresses'), list):
            data['iocs']['ip_addresses'] = [
                ip for ip in data['iocs']['ip_addresses']
                if not _is_reserved_ip(ip)
            ]

        # Dedupe other IOC fields case-insensitively (catches the "MD5|45a2..."
        # repeated 4 times pattern, plus defanging variants)
        for ioc_field in ['ip_addresses', 'domains', 'urls']:
            if isinstance(data['iocs'].get(ioc_field), list):
                data['iocs'][ioc_field] = _dedupe_ioc_list(data['iocs'][ioc_field])

    return data


# Strip markdown link wrappers from values: '[gskqf.com](http://gskqf.com)' -> 'gskqf.com'
# Trafilatura sometimes emits these when extracting from HTML where text and
# anchor href differ.
_MARKDOWN_LINK_RE = re.compile(r'\[([^\]]+?)\]\((https?://[^\)]+?)\)')


def _strip_markdown_link(value):
    """If value contains a markdown link, return just the text portion.
    Handles both standalone links and links embedded in larger strings.
    """
    if not isinstance(value, str):
        return value
    # If the entire value is just a markdown link, return only the text portion
    m = _MARKDOWN_LINK_RE.fullmatch(value.strip())
    if m:
        return m.group(1).strip()
    # Otherwise replace any embedded markdown links with their text
    return _MARKDOWN_LINK_RE.sub(lambda m: m.group(1), value)


def _is_reserved_ip(ip_value):
    """Detect IPs that are RFC reserved or otherwise never legitimate IOCs.

    Handles defanged forms like '192.168.1[.]1' as well as plain '192.168.1.1'.
    Returns True if the value should be filtered from IOC outputs.
    """
    if not ip_value:
        return False
    s = str(ip_value).strip()
    # Strip defanging brackets
    plain = s.replace('[.]', '.').replace('[:]', ':').replace('[/', '/')
    # Extract the IP portion (might have :port suffix)
    m = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::\d+)?$', plain)
    if not m:
        return False
    octets = [int(x) for x in m.groups()]
    # Validate octet ranges - if not valid, let it through (will fail other checks)
    if any(o > 255 for o in octets):
        return True  # invalid IP, definitely filter
    a, b, c, d = octets
    # RFC 1918 private ranges
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    # Loopback
    if a == 127:
        return True
    # Link-local (RFC 3927)
    if a == 169 and b == 254:
        return True
    # Multicast
    if 224 <= a <= 239:
        return True
    # Reserved/broadcast
    if a == 0 or a == 255:
        return True
    # 0.0.0.0 already caught above
    return False


def _normalize_hashes(hashes):
    """Strip common prefixes from hash strings and validate they're hex.

    Handles patterns like:
      MD5:abc123...     -> abc123...
      SHA256: abc123... -> abc123...
      MD5|abc123...     -> abc123...
      MD5abc123...      -> abc123...   (no separator)
      SHA-256:abc...    -> abc...

    Drops anything that isn't valid hex of length 32 (MD5), 40 (SHA1), or
    64 (SHA256). Dedupes case-insensitively while preserving first-seen casing.
    """
    if not hashes:
        return []

    # Pattern: optional algorithm prefix with various separators, then hex.
    # The (?:...)? makes the prefix optional. \W* matches any separator
    # (colon, pipe, dash, space, none).
    prefix_re = re.compile(
        r'^(?:(?:MD5|SHA-?1|SHA-?256|SHA-?512)\W*)?([0-9a-f]+)$',
        re.IGNORECASE
    )

    seen_lower = set()
    cleaned = []
    for raw in hashes:
        if raw is None:
            continue
        s = str(raw).strip()
        if not s:
            continue

        # Try the prefix-stripping regex
        m = prefix_re.match(s)
        if m:
            hex_part = m.group(1).lower()
            # Validate length
            if len(hex_part) in (32, 40, 64):
                if hex_part not in seen_lower:
                    seen_lower.add(hex_part)
                    cleaned.append(hex_part)
                continue

        # Fallback: extract any embedded hex sequence of valid hash length
        for hex_match in re.finditer(r'\b([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b', s, re.IGNORECASE):
            hex_part = hex_match.group(1).lower()
            if hex_part not in seen_lower:
                seen_lower.add(hex_part)
                cleaned.append(hex_part)

        # If neither matched, the value is garbage - silently drop

    return cleaned


def _dedupe_ioc_list(items):
    """Dedupe IOC list case-insensitively while preserving original casing."""
    if not items:
        return []
    seen_lower = set()
    out = []
    for item in items:
        if item is None:
            continue
        s = str(item).strip()
        if not s:
            continue
        key = s.lower()
        if key not in seen_lower:
            seen_lower.add(key)
            out.append(s)
    return out


# Words that almost never start a real article title, but commonly start
# mid-sentence prose fragments captured by chunk-boundary truncation.
_TITLE_BAD_PREFIXES = (
    'the ', 'a ', 'an ', 'this ', 'that ', 'these ', 'those ',
    'and ', 'but ', 'or ', 'so ', 'because ', 'since ', 'although ',
    'while ', 'whereas ', 'however ', 'therefore ',
    'is ', 'was ', 'are ', 'were ', 'has ', 'have ', 'had ',
    'will ', 'would ', 'should ', 'could ', 'may ', 'might ',
    'it ', 'they ', 'we ', 'i ',
)


def _looks_like_corrupted_title(title: str) -> bool:
    """Heuristic: detect titles that are actually prose fragments grabbed by
    a chunk-boundary slip."""
    if not title:
        return False
    # Real titles are rarely longer than ~200 chars
    if len(title) > 200:
        return True
    # Real titles don't typically end in a period (they end with a word)
    # but sometimes they do, so we only flag this combined with other signals
    lower = title.lower()
    starts_with_lowercase = title[0].islower() if title else False
    starts_with_dependent = any(lower.startswith(p) for p in _TITLE_BAD_PREFIXES)
    ends_in_period = title.rstrip().endswith('.')
    # Single-letter or punctuation-only start = mid-word slice ("e current user session")
    starts_with_fragment = len(title) >= 2 and title[0].isalpha() and title[1] == ' '
    if starts_with_fragment:
        return True
    # Combined: dependent prefix AND ends in period AND has multiple sentences
    if starts_with_dependent and ends_in_period and '. ' in title:
        return True
    return False


def _parse_string_as_list(s):
    """Parse a string that should have been a YAML list.

    Handles common LLM mistakes like:
      "- Point Wild"            -> ["Point Wild"]
      "- foo\n- bar"            -> ["foo", "bar"]
      "[]"                      -> []
      "[a, b, c]"               -> ["a", "b", "c"]
      "Single Value"            -> ["Single Value"]
    """
    if not s or not isinstance(s, str):
        return []
    s = s.strip()
    if not s or s in ('[]', '""', "''"):
        return []

    # Inline flow-style list
    if s.startswith('[') and s.endswith(']'):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [x.strip().strip('"').strip("'") for x in inner.split(',') if x.strip()]

    # Block-style list rendered into a string ("- foo\n- bar")
    if '\n' in s or s.startswith('-'):
        items = []
        for line in s.split('\n'):
            line = line.strip()
            if line.startswith('- '):
                items.append(line[2:].strip())
            elif line.startswith('-'):
                items.append(line[1:].strip())
            elif line:
                items.append(line)
        return [x for x in items if x]

    # Single value
    return [s]


PLACEHOLDER_PATTERNS = [
    re.compile(r'^<.*>$'),                    # <author name>, <CVE-YYYY-NNNNN>
    re.compile(r'^-\s*CVE-YYYY', re.I),       # "- CVE-YYYY-NNNNN"
    re.compile(r'^CVE-YYYY', re.I),
    re.compile(r'^null$', re.I),
    re.compile(r'^N/?A$', re.I),
    re.compile(r'^unknown$', re.I),
    re.compile(r'^placeholder', re.I),
    re.compile(r'^example\s', re.I),
    re.compile(r'^MD5/SHA1/SHA256$', re.I),
    re.compile(r'^IPv4/IPv6$', re.I),
    # Few-shot example contamination - reject anything echoing the prompt example
    re.compile(r'placeholder\.invalid', re.I),
    re.compile(r'^(deadbeef){4,}', re.I),         # at least 32 chars of repeated 'deadbeef'
    re.compile(r'EXAMPLE_AUTHOR_PLACEHOLDER', re.I),
    re.compile(r'^Jane Smith$', re.I),            # legacy example name from earlier prompt
    re.compile(r'^John Doe$', re.I),              # generic placeholder name model invents
    re.compile(r'^Jane Doe$', re.I),
    re.compile(r'^Author Name$', re.I),           # literal placeholder pattern
    re.compile(r'^<author[\s_]*name>$', re.I),
    re.compile(r'evil\[\.\]example\[\.\]com', re.I),  # legacy example domain
    re.compile(r'^Acme Threat Labs', re.I),
]


# Substrings that, if found ANYWHERE in a value, mean the value is contaminated
# from the few-shot example. Unlike PLACEHOLDER_PATTERNS which use whole-match,
# these match anywhere in the string.
#
# CRITICAL: only include strings that are distinctive enough to never appear
# in a real article. "powershell.exe" alone is too common to filter, but the
# exact synthetic command line "powershell.exe -NoP -W Hidden -Enc SQBFAFgA"
# is unique to our example.
EXAMPLE_CONTAMINATION_SUBSTRINGS = [
    # Current marker (v7+)
    'EXAMPLEONLY',
    # Legacy synthetic values - some still leak from previous prompt versions
    'placeholder.invalid',
    'EXAMPLE_AUTHOR_PLACEHOLDER',
    'evil[.]example[.]com',
    'evil.example.com',
    'Acme Threat Labs',
    # Distinctive value-strings from the v6/v6.1 example that the model
    # frequently copies into unrelated outputs (Android, CTF, Linux articles
    # that have no Windows content). These are the FULL strings, not just
    # parts - 'powershell.exe' alone is not contamination, but the exact
    # synthetic command line is.
    'powershell.exe -NoP -W Hidden -Enc SQBFAFgA',
    r'C:\Users\Public\update.exe',
    r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater',
    'Registry Run key (HKCU) pointing to C:\\Users\\Public\\update.exe',
    # Generic fabricated hashes the model invents to fill iocs.hashes
    '1234567890abcdef1234567890abcdef',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'ffffffffffffffffffffffffffffffff',
    '0000000000000000000000000000000',  # 31+ zeros
]


def _is_placeholder(value):
    if value is None:
        return True
    s = str(value).strip()
    if not s or s in ('[]', '{}', '""', "''"):
        return True
    # Whole-match patterns
    for pat in PLACEHOLDER_PATTERNS:
        if pat.match(s):
            return True
    # Substring contamination from few-shot example - matches anywhere in value.
    # We normalize backslashes to handle the YAML escape variability: a
    # registry path may be parsed as 'HKCU\Software\...' or 'HKCU\\Software\\...'
    # depending on whether the model used a quoted or unquoted scalar.
    s_lower = s.lower()
    s_normalized = s_lower.replace('\\\\', '\\')  # collapse double backslashes
    for substr in EXAMPLE_CONTAMINATION_SUBSTRINGS:
        substr_lower = substr.lower()
        substr_normalized = substr_lower.replace('\\\\', '\\')
        if substr_lower in s_lower or substr_normalized in s_normalized:
            return True
    # Repeated 'deadbeef' anywhere (not just at start)
    if re.search(r'(deadbeef){4,}', s, re.I):
        return True
    return False


def _strip_placeholder_items(data):
    """Walk the schema and remove items that match placeholder patterns."""
    for container_key in ['ttps', 'iocs']:
        if isinstance(data.get(container_key), dict):
            for field, items in data[container_key].items():
                if isinstance(items, list):
                    data[container_key][field] = [
                        x for x in items if not _is_placeholder(x)
                    ]

    for key in ['malware_families', 'cves', 'authors']:
        if isinstance(data.get(key), list):
            data[key] = [x for x in data[key] if not _is_placeholder(x)]

    if _is_placeholder(data.get('attribution')):
        data['attribution'] = ''

    return data


def merge_yamls(chunks):
    """Merge YAML chunks emitted from sequential LLM calls.

    All chunks pass through normalize_schema first so the merge logic only ever
    sees canonical structure.
    """
    merged = {}
    for chunk in chunks:
        try:
            data = yaml.safe_load(chunk)
        except yaml.YAMLError:
            continue

        # Normalize list-of-dicts at top level (some models emit this)
        if isinstance(data, list):
            tmp = {}
            for item in data:
                if isinstance(item, dict):
                    for k, v in item.items():
                        if k not in tmp:
                            tmp[k] = v
                        elif isinstance(v, list) and isinstance(tmp[k], list):
                            tmp[k].extend(x for x in v if x not in tmp[k])
                        elif isinstance(v, dict) and isinstance(tmp[k], dict):
                            for sk, sv in v.items():
                                if sk not in tmp[k]:
                                    tmp[k][sk] = sv
            data = tmp

        if not isinstance(data, dict):
            continue

        # Normalize before merging - this is the key fix for cross-chunk
        # schema inconsistency
        data = normalize_schema(data)

        if not merged:
            merged = data
            continue

        # Merge into accumulator
        for key, value in data.items():
            if value in (None, "", [], {}):
                continue
            if key not in merged or merged[key] in (None, "", [], {}):
                merged[key] = value
            elif isinstance(value, list) and isinstance(merged.get(key), list):
                merged[key].extend(v for v in value if v not in merged[key])
            elif isinstance(value, dict) and isinstance(merged.get(key), dict):
                for subkey, subval in value.items():
                    if subval in (None, "", [], {}):
                        continue
                    if subkey not in merged[key] or not merged[key][subkey]:
                        merged[key][subkey] = subval
                    elif isinstance(subval, list) and isinstance(merged[key][subkey], list):
                        merged[key][subkey].extend(v for v in subval if v not in merged[key][subkey])
                    else:
                        merged[key][subkey] = subval
            else:
                # Scalar handling per field:
                # - title, attribution: keep the FIRST non-empty value. Later
                #   chunks often produce malformed prose-as-title when chunk
                #   boundaries cut mid-sentence.
                # - description: prefer longer (more complete summary) but
                #   reject anything over 1000 chars (likely a chunk boundary
                #   artifact, not a real description).
                # - other scalars: first-wins (safest default).
                if key in ('title', 'attribution'):
                    pass  # already have a non-empty value, keep it
                elif key == 'description':
                    new_str = str(value)
                    old_str = str(merged[key])
                    if len(new_str) > len(old_str) and len(new_str) <= 1000:
                        merged[key] = value
                else:
                    # Default for unknown scalar fields: first non-empty wins
                    pass

    # Final normalize pass to clean up after merge
    if merged:
        merged = normalize_schema(merged)
    return merged


def clean_text(text):
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[\x00-\x1F\x7F-\x9F\u2000-\u206F\u2190-\u21FF]", "", text)
    return text


def extract_date(url, html):
    soup = BeautifulSoup(html, "html.parser")

    # <time datetime="...">
    time_tag = soup.find("time")
    if time_tag and time_tag.get("datetime"):
        try:
            return date_parse(time_tag["datetime"]).strftime("%B %d, %Y")
        except Exception:
            pass

    # <meta name="date" content="..."> or article:published_time
    meta_date = soup.find("meta", {"name": "date"}) or soup.find("meta", {"property": "article:published_time"})
    if meta_date and meta_date.get("content"):
        try:
            return date_parse(meta_date["content"]).strftime("%B %d, %Y")
        except Exception:
            pass

    # Date from URL path
    match = re.search(r"/(20\d{2})[/-](\d{1,2})[/-](\d{1,2})", url)
    if match:
        try:
            return datetime(int(match[1]), int(match[2]), int(match[3])).strftime("%B %d, %Y")
        except Exception:
            pass

    # Last resort: scan visible text - but only the article body, not arbitrary
    # text (which catches dates in IOCs, persistence artifacts, etc.)
    article_root = (soup.find('article') or soup.find('main') or soup)
    text = article_root.get_text()[:5000]  # limit to first 5k chars to favor header dates
    date_patterns = [
        r'\b\d{4}-\d{2}-\d{2}\b',
        r'\b\d{2}/\d{2}/\d{4}\b',
        r'\b\d{1,2} [A-Za-z]+ \d{4}\b'
    ]
    for pattern in date_patterns:
        match = re.search(pattern, text)
        if match:
            try:
                parsed = date_parse(match.group(0))
                # Sanity check: reject dates more than ~30 years old or in the future
                if 1995 <= parsed.year <= datetime.utcnow().year + 1:
                    return parsed.strftime("%B %d, %Y")
            except Exception:
                continue

    return datetime.utcnow().strftime("%B %d, %Y")


def read_cached_urls():
    if not os.path.exists(CACHE_FILE):
        return set()
    with open(CACHE_FILE, "r") as f:
        return set(line.strip() for line in f)


def append_to_cache(url, start_urls: set[str] = None):
    if start_urls is None:
        start_urls = set()

    nu = normalize_url(url)
    normalized_start_urls = {normalize_url(u) for u in start_urls}
    if nu in normalized_start_urls:
        logger.info(f"    ⏩ Not caching (is a base/start URL): {nu}")
        return

    parsed = urlparse(nu)
    if parsed.path == '/blog' or parsed.path == '/':
        return

    if any(re.search(p, nu.lower()) for p in bad_patterns):
        return

    cached = read_cached_urls()
    if nu not in cached:
        with open(CACHE_FILE, 'a') as f:
            f.write(nu + '\n')


IOC_PATTERNS = [
    re.compile(r"\b[a-f0-9]{32,64}\b", re.I),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"\bhttps?://[^\s)>\]]+\b", re.I),
    re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I),
]


def is_security_report(text, url):
    t = (text or "").lower()
    score = 0
    matched_keywords = []

    for kw in ["cve", "malware", "exploit", "ransomware", "backdoor", "apt",
               "payload", "command", "persistence", "ttps", "threat", "advisory",
               "campaign", "malicious", "attack", "analysis", "cybercrime",
               "phish", "stealer", "loader", "dropper", "dfir", "sysmon",
               "powershell", "registry", "process injection"]:
        if kw in t:
            score += 1
            matched_keywords.append(kw)

    if re.search(r"CVE-\d{4}-\d{4,7}", t, re.I):
        score += 2
        matched_keywords.append("CVE-ID")
    if re.search(r"\bT1[0-9]{3}\b", t):
        score += 2
        matched_keywords.append("MITRE-TTP")

    if any(p.search(t) for p in IOC_PATTERNS):
        score += 2
        matched_keywords.append("IOCs")

    if re.search(r"/author/|/team/|/experts/|/page/\d+", url.lower()):
        logger.info(f"   ❌ Rejected (author/team page): {url}")
        return False

    is_report = score >= 2
    if is_report:
        logger.info(f"   ✓ Security report (score={score}, keywords={matched_keywords})")
    else:
        logger.info(f"   ⚠️ Not security report (score={score}, keywords={matched_keywords})")

    return is_report


# Track last request time per domain for rate limiting
_domain_last_request = {}


def _dedupe_path_segments(url):
    """Collapse adjacent duplicate path segments: /blog/blog/foo -> /blog/foo.

    This fixes the urljoin pitfall where a base URL like /media-center/blog/
    plus an href like 'blog/slug' produces /media-center/blog/blog/slug.
    """
    p = urlparse(url)
    segments = p.path.split('/')
    deduped = []
    for s in segments:
        if deduped and s and s == deduped[-1]:
            continue
        deduped.append(s)
    new_path = '/'.join(deduped)
    if new_path != p.path:
        return urlunparse((p.scheme, p.netloc, new_path, p.params, p.query, p.fragment))
    return None  # no change


def _fetch_via_wayback(url, timeout=20):
    """Attempt to retrieve the most recent Wayback Machine snapshot of a URL."""
    try:
        # Wayback's "closest" API
        api = f"https://archive.org/wayback/available?url={url}"
        if USE_CURL_CFFI:
            r = cf_requests.get(api, impersonate="chrome", timeout=timeout)
        else:
            r = requests.get(api, timeout=timeout)
        if r.status_code != 200:
            return ""
        data = r.json()
        snapshot = data.get('archived_snapshots', {}).get('closest', {})
        if not snapshot.get('available'):
            return ""
        snap_url = snapshot.get('url')
        if not snap_url:
            return ""
        # Use the id_ flag to get the original page without Wayback's banner
        if '/web/' in snap_url:
            snap_url = snap_url.replace('/web/', '/web/', 1)
            # Insert id_ after the timestamp
            parts = snap_url.split('/web/', 1)
            if len(parts) == 2:
                ts_and_rest = parts[1]
                first_slash = ts_and_rest.find('/')
                if first_slash > 0:
                    timestamp = ts_and_rest[:first_slash]
                    rest = ts_and_rest[first_slash:]
                    snap_url = f"{parts[0]}/web/{timestamp}id_{rest}"
        logger.info(f"    🕰️ Trying Wayback snapshot: {snap_url}")
        if USE_CURL_CFFI:
            r2 = cf_requests.get(snap_url, impersonate="chrome", timeout=timeout, allow_redirects=True)
        else:
            r2 = requests.get(snap_url, timeout=timeout, allow_redirects=True)
        if r2.status_code == 200 and r2.text:
            logger.info(f"    ✓ Wayback returned {len(r2.text)} chars")
            return r2.text
    except Exception as e:
        logger.warning(f"    ⚠️ Wayback fallback failed: {e}")
    return ""


def fetch_html_content(url, timeout=20, _allow_recovery=True):
    """Fetch HTML. Returns empty string on any failure (4xx, 5xx, or exception).

    On 404, attempts recovery by:
      1. Collapsing duplicate path segments (urljoin artifact)
      2. Falling back to Wayback Machine
    Recovery is only attempted at the top level (_allow_recovery=True) to
    prevent recursion.
    """
    import time

    domain = urlparse(url).netloc
    if domain in _domain_last_request:
        elapsed = time.time() - _domain_last_request[domain]
        if elapsed < REQUEST_DELAY:
            sleep_time = REQUEST_DELAY - elapsed
            logger.info(f"    ⏱️ Rate limiting: sleeping {sleep_time:.1f}s for {domain}")
            time.sleep(sleep_time)

    _domain_last_request[domain] = time.time()

    status = 0
    text = ""
    try:
        if USE_CURL_CFFI:
            resp = cf_requests.get(url, impersonate="chrome", timeout=timeout, allow_redirects=True)
        else:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "DNT": "1",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Cache-Control": "max-age=0",
            }
            resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)

        status = resp.status_code
        text = resp.text or ""

        # PDF detection: skip non-HTML content. Threat reports occasionally
        # come as PDFs (FBI/CISA advisories, vendor whitepapers). Without
        # proper PDF extraction we'd feed binary garbage to the LLM, which
        # then fabricates plausible-looking output from the few-shot example.
        # Better to skip cleanly than produce hallucinated YAML.
        content_type = resp.headers.get('Content-Type', '').lower()
        url_lower = url.lower()
        is_pdf = (
            'application/pdf' in content_type
            or url_lower.endswith('.pdf')
            or (text[:4] == '%PDF')  # magic bytes - sometimes Content-Type lies
        )
        if is_pdf:
            logger.info(f"    ⏩ Skipped: PDF document not supported ({url})")
            return ""

        # Anti-bot detection
        if 'cf-browser-verification' in text or 'Just a moment' in text:
            logger.warning(f"    ⚠️ Cloudflare challenge detected for {domain}")
            return ""
        if 'px-captcha' in text or 'PerimeterX' in text:
            logger.warning(f"    ⚠️ PerimeterX challenge detected for {domain}")
            return ""
        if 'distil_r_captcha' in text:
            logger.warning(f"    ⚠️ Distil Networks challenge detected for {domain}")
            return ""

        if status >= 400:
            logger.warning(f"    ⚠️ HTTP {status} fetching {url}")
            text = ""  # discard error page body so it can't be processed downstream

    except Exception as e:
        logger.error(f"    ❌ Fetch failed for {url}: {e}")
        text = ""

    # Recovery attempts on 404 only
    if not text and status == 404 and _allow_recovery:
        # 1. Try collapsing duplicate path segments
        deduped = _dedupe_path_segments(url)
        if deduped:
            logger.info(f"    🔧 Retrying with deduped path: {deduped}")
            recovered = fetch_html_content(deduped, timeout=timeout, _allow_recovery=False)
            if recovered:
                return recovered

        # 2. Fall back to Wayback Machine
        wayback_text = _fetch_via_wayback(url, timeout=timeout)
        if wayback_text:
            return wayback_text

    return text


def discover_rss_feeds(soup, base_url):
    rss = []
    for link in soup.find_all('link', attrs={'rel': 'alternate'}):
        link_type = link.get('type', '').lower()
        if 'rss' in link_type or 'atom' in link_type or 'xml' in link_type:
            href = link.get('href')
            if href:
                full_url = urljoin(base_url, href)
                rss.append(full_url)
                logger.info(f"    Found RSS feed: {full_url}")
    return sorted(set(rss))


def try_common_feed_urls(base_url):
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    common_paths = [
        '/feed/', '/rss/', '/feed', '/rss', '/atom.xml',
        '/rss.xml', '/feed.xml', '/blog/feed/', '/blog/rss/',
    ]

    found_feeds = []
    for path in common_paths:
        test_url = base + path
        try:
            resp = requests.head(test_url, timeout=5, allow_redirects=True)
            if resp.status_code == 200:
                content_type = resp.headers.get('Content-Type', '').lower()
                if 'xml' in content_type or 'rss' in content_type or 'atom' in content_type:
                    found_feeds.append(test_url)
                    logger.info(f"    Found feed via common path: {test_url}")
        except Exception:
            continue

    return found_feeds


THREAT_POSITIVE = {
    "threat", "research", "reverse", "malware", "ransom", "cve", "apt", "ttx",
    "ioc", "iocs", "ttp", "ttps", "exploit", "loader", "stealer", "backdoor",
    "campaign", "dfir", "ir", "forensic", "shellcode", "c2", "command-and-control",
    "botnet", "phishing", "initial-access", "persistence", "lateral", "exfiltration",
    "tactics", "techniques", "procedure", "tactic", "technique", "procedure", "intrusion",
    "detect", "detection", "hunt", "hunting", "analysis", "analyzing", "reverse-engineering",
    "vulnerability", "0day", "zero-day", "rce", "lpe", "privesc", "advisory",
}

# Strong negatives - these almost certainly indicate non-research content.
# Removed: guide, howto, how-to, tips, feature, partner, customer (too common in legit posts)
MARKETING_NEGATIVE = {
    "press-release", "press", "webinar", "podcast", "release-notes", "roadmap",
    "pricing", "case-study", "testimonial", "announcing", "announcement",
    "newsletter", "weekly-recap", "monthly-recap", "quarterly", "hiring",
    "career", "careers", "culture", "company-news", "investor", "funding",
    "raise", "raised", "series-a", "series-b", "series-c",
}


# Path patterns that indicate research/blog content vs product/marketing
RESEARCH_PATH_INDICATORS = [
    '/blog/', '/research/', '/posts/', '/post/', '/insights/',
    '/threat-research/', '/intelligence/', '/labs/', '/articles/',
    '/news/', '/security-blog/', '/threat-intelligence/', '/tech_blog/',
]


def link_priority_score(url):
    """Lower score = higher priority. Sorts research-path URLs above
    product/service pages when both pass the filter."""
    u = url.lower()
    p = urlparse(u)
    path = p.path

    # Strong signal: /blog/, /research/, etc.
    for indicator in RESEARCH_PATH_INDICATORS:
        if indicator in path:
            # Bonus for date pattern in path
            if re.search(r'/20\d{2}/\d{1,2}/', path):
                return 0
            return 1

    # Mid signal: substantive multi-segment paths often used by labs
    segments = [s for s in path.split('/') if s]
    if len(segments) >= 2:
        last = segments[-1]
        # Slug with multiple word-tokens (more likely article than product)
        word_tokens = re.split(r'[-_]', last)
        if len(word_tokens) >= 4:
            return 2

    # Low signal: short slugs, often product/service pages
    return 3


def is_probable_research_link(href: str, link_text: str = "") -> bool:
    u = (href or "").lower()
    t = (link_text or "").lower()

    # Strong negatives kill it immediately
    for neg in MARKETING_NEGATIVE:
        if f"/{neg}/" in u or f"/{neg}-" in u or f"-{neg}/" in u:
            logger.info(f"    ❌ Rejected (marketing URL pattern '{neg}'): {href}")
            return False
        # Anchor text only counts if it's a strong negative phrase, not a single word
        if len(neg) > 6 and neg in t:
            logger.info(f"    ❌ Rejected (marketing anchor '{neg}'): {href}")
            return False

    # Strong positives
    if any(f"/{pos}/" in u or f"/{pos}-" in u or f"-{pos}/" in u for pos in THREAT_POSITIVE):
        logger.info(f"    ✓ Accepted (threat keyword in URL): {href}")
        return True
    if any(pos in t for pos in THREAT_POSITIVE):
        logger.info(f"    ✓ Accepted (threat keyword in anchor text): {href}")
        return True

    # Date pattern on a blog/research host or path is a strong positive signal
    parsed = urlparse(href)
    netloc = parsed.netloc.lower()
    has_blog_indicator = (
        '/blog/' in u
        or netloc.startswith('blog.')
        or netloc.startswith('research.')
        or netloc.startswith('labs.')
    )
    if has_blog_indicator and re.search(r"/20\d{2}/\d{1,2}/", u):
        logger.info(f"    ✓ Accepted (blog with date pattern): {href}")
        return True

    # NEW DEFAULT: accept blog/post URLs with substantive slugs unless clearly junk.
    # Most modern security blogs use slug-only URLs and the old default-reject
    # was killing legitimate posts.
    p = urlparse(href)
    path = p.path.rstrip('/')
    segments = [s for s in path.split('/') if s]
    in_research_path = any(ind in path.lower() for ind in RESEARCH_PATH_INDICATORS)

    if segments:
        last = segments[-1]
        word_tokens = [t for t in re.split(r'[-_]', last) if t]

        # Inside a research path, be very permissive: any non-trivial slug
        # is treated as a candidate post. This catches NTT-style URLs like
        # /tech_blog/stoatwaffle_malware/ and /tech_blog/byovd_disables_edr/.
        if in_research_path:
            # Reject only obvious non-content
            if last in ('index', 'home', 'feed', 'rss', 'archive'):
                pass
            elif len(last) >= 6 and (len(word_tokens) >= 2 or len(last) >= 12):
                logger.info(f"    ✓ Accepted (slug in research path): {href}")
                return True

        # Outside research paths, require longer multi-token slugs to avoid
        # matching product/service pages like /attack-surface-management
        # (3 tokens) or /cyber-ai-glossary (3 tokens). 4+ tokens is the
        # threshold for "looks like an article title."
        if len(word_tokens) >= 4 and len(last) >= 12:
            logger.info(f"    ✓ Accepted (long substantive slug): {href}")
            return True

    logger.info(f"    ⚠️ Rejected (no clear research signal): {href}")
    return False


def extract_links_from_index(base_url, soup=None):
    if soup is None:
        html = fetch_html_content(base_url)
        if not html:
            logger.warning(f"    ⚠️ Failed to fetch HTML from {base_url}")
            return []
        soup = BeautifulSoup(html, "html.parser")

    # Respect <base href> if present (some Framer/SPA sites set this)
    base_tag = soup.find('base', href=True)
    effective_base = urljoin(base_url, base_tag['href']) if base_tag else base_url

    base_domain = urlparse(base_url).netloc

    anchors = soup.find_all('a', href=True)
    logger.info(f"    Found {len(anchors)} total anchor tags on page")

    kept = []
    off_domain = 0
    root_paths = 0

    for a in anchors:
        full_url = urljoin(effective_base, a['href'])
        # Defensively collapse any /seg/seg/ artifacts from urljoin
        deduped = _dedupe_path_segments(full_url)
        if deduped:
            full_url = deduped

        p = urlparse(full_url)
        if p.netloc != base_domain:
            off_domain += 1
            continue
        path = p.path.rstrip('/')
        if not path or path in ('/', '/blog'):
            root_paths += 1
            continue

        text = (a.get_text() or '').strip()
        if is_probable_research_link(full_url, text):
            kept.append(normalize_url(full_url))

    kept = sorted(set(kept))
    logger.info(f"    Filtered: {off_domain} off-domain, {root_paths} root/blog paths")
    logger.info(f"    Kept {len(kept)} likely article links")
    return kept


def timeout_handler(signum, frame):
    raise TimeoutError("Trafilatura extraction timed out.")


signal.signal(signal.SIGALRM, timeout_handler)


def _trafilatura_extract_compat(html: str):
    try:
        return trafilatura.extract(
            html,
            include_comments=False,
            include_tables=True,
            favor_references=True,
        )
    except TypeError:
        return trafilatura.extract(
            html,
            include_comments=False,
            include_tables=True,
        )


def find_article_root(soup):
    """Locate the main article body, falling back progressively.

    The goal is to scope image extraction (and ideally text extraction) to the
    actual content, not nav/footer/sidebar/related-posts.
    """
    # Try semantic HTML first
    article = soup.find('article')
    if article:
        return article

    main = soup.find('main')
    if main:
        return main

    role_main = soup.find(attrs={'role': 'main'})
    if role_main:
        return role_main

    # Common content class patterns
    content = soup.find(class_=re.compile(
        r'(article|post|blog|entry|story)[-_](body|content|main|wrapper|container)',
        re.I
    ))
    if content:
        return content

    # Generic content classes
    content = soup.find(class_=re.compile(r'^(content|main-content|post-content)$', re.I))
    if content:
        return content

    return soup


def strip_chrome(node):
    """Remove site chrome elements that get included in image scans.

    Operates in-place on the BeautifulSoup node. Safe to call on the article
    root or on a clone of the full soup.
    """
    if node is None:
        return node

    # Remove structural chrome
    for tag_name in ['nav', 'header', 'footer', 'aside']:
        for tag in node.find_all(tag_name):
            tag.decompose()

    # Remove by class/id pattern
    chrome_pattern = re.compile(
        r'(related|recommended|sidebar|footer|header|nav|menu|share|social|'
        r'cookie|newsletter|subscribe|popup|modal|banner|breadcrumb|pagination|'
        r'comment|author-bio|tags?|categories|widget|promo|advert|sponsor)',
        re.I
    )
    for tag in node.find_all(attrs={'class': chrome_pattern}):
        tag.decompose()
    for tag in node.find_all(attrs={'id': chrome_pattern}):
        tag.decompose()

    return node


def extract_text_from_page(url):
    html = fetch_html_content(url)
    if not html:
        return "", ""

    signal.alarm(60)
    try:
        downloaded = _trafilatura_extract_compat(html)
    except TimeoutError:
        logger.warning(f"    ⚠️ Trafilatura timed out for: {url}")
        downloaded = None
    finally:
        signal.alarm(0)

    soup = BeautifulSoup(html, "html.parser")

    # Scope to article root and strip chrome before extracting code/tables
    article_root = find_article_root(soup)
    # Operate on a copy so we don't mutate soup (image extraction uses original)
    from copy import copy
    article_clean = copy(article_root)
    article_clean = strip_chrome(article_clean)

    # Code/pre blocks (commands live here)
    code_chunks = []
    for node in article_clean.select("pre, code, kbd, samp"):
        txt = node.get_text("\n", strip=True)
        if txt and len(txt) >= 3:
            code_chunks.append(txt)
    code_blob = "\n".join(code_chunks)

    # Tables (IOC grids)
    table_lines = []
    for table in article_clean.find_all("table"):
        for r in table.find_all("tr"):
            cols = [c.get_text(" ", strip=True) for c in r.find_all(["th", "td"])]
            if any(cols):
                table_lines.append("\t".join(cols))
    table_blob = "\n".join(table_lines)

    if not downloaded:
        downloaded = article_clean.get_text("\n", strip=True)

    rich = "\n\n".join([
        "=== ARTICLE BODY ===",
        clean_text(downloaded or ""),
        "=== CODE BLOCKS ===",
        code_blob,
        "=== TABLES ===",
        table_blob
    ]).strip()

    return rich, html


# Image MIME types we can decode
DECODABLE_IMAGE_TYPES = {'image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp', 'image/bmp'}
if AVIF_SUPPORT:
    DECODABLE_IMAGE_TYPES.add('image/avif')


def extract_images_from_html(html, base_url):
    """Extract content images, scoped to the article body and excluding chrome.

    This is the primary fix for the OCR explosion - instead of grabbing every
    <img> on the page (which includes nav, footer, related-posts thumbnails,
    social icons, etc.), we scope to the article root and strip known chrome
    containers first.
    """
    soup = BeautifulSoup(html, "html.parser")
    article_root = find_article_root(soup)

    # Operate on a copy so original soup is unmodified
    from copy import copy
    article_clean = copy(article_root)
    article_clean = strip_chrome(article_clean)

    img_urls = []
    seen = set()

    for img in article_clean.find_all('img'):
        src = img.get('src') or img.get('data-src') or img.get('data-lazy-src') or img.get('data-original')
        if not src:
            continue

        full_url = urljoin(base_url, src)
        if not full_url.startswith('http'):
            continue

        if full_url in seen:
            continue
        seen.add(full_url)
        img_urls.append(full_url)

    logger.info(f"    Found {len(img_urls)} content images (article-scoped, deduped)")
    return img_urls


def should_ocr_image(width, height):
    """Pre-filter images by dimensions before downloading/OCRing."""
    # Too small - icons, buttons, avatars
    if width < 200 or height < 100:
        return False, f"too small ({width}x{height})"

    # Too large - hero images, full-page screenshots, infographics that won't OCR well
    if width > 3000 or height > 3000:
        return False, f"too large ({width}x{height})"

    # Extreme aspect ratio - banners, dividers, sidebars
    aspect = width / height if height else 0
    if aspect > 8 or (aspect < 0.2 and aspect > 0):
        return False, f"extreme aspect ratio ({aspect:.1f}:1)"

    # Logo-sized squares - usually brand assets
    if 180 <= width <= 400 and 180 <= height <= 400 and abs(width - height) < 60:
        return False, f"likely logo ({width}x{height})"

    return True, None


def preprocess_image_for_ocr(img):
    """Preprocess for OCR. NOTE: removed the binary threshold step - it was
    destroying anti-aliased terminal text and producing the cascading typos
    we saw (admin -> adimin -> acimin -> aimin)."""
    from PIL import ImageEnhance, ImageFilter

    # Grayscale
    img = img.convert('L')

    # Modest contrast bump (was 2.0 - too aggressive)
    enhancer = ImageEnhance.Contrast(img)
    img = enhancer.enhance(1.5)

    # Light sharpening
    img = img.filter(ImageFilter.SHARPEN)

    return img


def is_quality_ocr_text(text, min_chars=20):
    """Reject obviously corrupted OCR output.

    Used to gatekeep what gets fed back to the LLM. Bad OCR is worse than
    no OCR. This intentionally errs toward acceptance for technical content
    (long paths, hashes, URLs) which can look "wordless" but is valuable.
    """
    if not text or len(text.strip()) < min_chars:
        return False

    s = text.strip()

    # Letter ratio: real content has reasonable proportion of alphabetic chars.
    # Threshold is loose because IPs, hashes, paths legitimately have many non-letters.
    letters = sum(1 for c in s if c.isalpha())
    if letters / len(s) < 0.3:
        return False

    # Look for ANY recognizable technical content - if found, accept.
    # This protects registry paths, hashes, IPs, URLs from being filtered.
    technical_patterns = [
        r'[A-Z]:\\',                          # Windows path
        r'/(?:usr|var|etc|opt|home|tmp)/',    # Unix path
        r'HKEY_|HKLM|HKCU',                   # Registry
        r'\b[a-f0-9]{32,}\b',                 # Hash
        r'\b\d+\.\d+\.\d+\.\d+\b',            # IP
        r'https?://',                          # URL
        r'\.(?:exe|dll|ps1|bat|vbs|js|py)\b', # Executable extension
        r'CVE-\d{4}',                          # CVE
        r'[a-zA-Z0-9_-]+\.(?:com|net|org|io|ru|cn)\b',  # Domain
    ]
    import re as _re
    for pat in technical_patterns:
        if _re.search(pat, s, _re.IGNORECASE):
            return True

    # No obvious technical content - apply word-shape heuristics
    words = [w for w in s.split() if w]
    if not words:
        return False

    # Reject if dominated by single characters (sparse OCR garbage)
    single_char_words = sum(1 for w in words if len(w) == 1)
    if single_char_words / len(words) > 0.4:
        return False

    # If there's at least one word of reasonable length AND multiple words,
    # treat it as plausible prose
    multi_char_words = [w for w in words if len(w) > 2]
    if len(multi_char_words) < 3:
        return False

    avg_word_len = sum(len(w) for w in words) / len(words)
    if avg_word_len > 25:  # very loose - only catches truly garbled output
        return False

    return True


def ocr_image(img_url):
    """Download, preprocess, and OCR a single image. Returns extracted text or
    empty string. Cached by URL across the run."""
    if img_url in _ocr_cache:
        return _ocr_cache[img_url]

    try:
        # Download
        if USE_CURL_CFFI:
            resp = cf_requests.get(img_url, impersonate="chrome", timeout=10)
        else:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
                "Referer": "https://www.google.com/",
            }
            resp = requests.get(img_url, headers=headers, timeout=10)
        resp.raise_for_status()

        # MIME type filter - skip undecodable formats early
        content_type = resp.headers.get('Content-Type', '').lower().split(';')[0].strip()
        if content_type and content_type not in DECODABLE_IMAGE_TYPES:
            _ocr_cache[img_url] = ''
            return ''

        img_data = resp.content
        img = Image.open(BytesIO(img_data))
        width, height = img.size

        # Pre-OCR size filter
        ok, reason = should_ocr_image(width, height)
        if not ok:
            logger.info(f"      ⏩ Skipped ({reason})")
            _ocr_cache[img_url] = ''
            return ''

        logger.info(f"      Image size: {width}x{height}")

        processed_img = preprocess_image_for_ocr(img)
        custom_config = r'--oem 3 --psm 6'
        text = pytesseract.image_to_string(processed_img, config=custom_config)

        if not text.strip():
            logger.info(f"      ⚠️ No text found")
            _ocr_cache[img_url] = ''
            return ''

        if not is_quality_ocr_text(text):
            logger.info(f"      ⚠️ OCR text rejected as low quality ({len(text.strip())} chars)")
            _ocr_cache[img_url] = ''
            return ''

        cleaned = text.strip()
        logger.info(f"      ✓ Extracted {len(cleaned)} characters")
        _ocr_cache[img_url] = cleaned
        return cleaned

    except requests.RequestException as e:
        logger.warning(f"      ❌ Failed to download: {e}")
        _ocr_cache[img_url] = ''
        return ''
    except Exception as e:
        # PIL can't decode (e.g., AVIF without plugin, SVG, etc.)
        msg = str(e)
        if 'cannot identify image file' in msg:
            logger.info(f"      ⏩ Undecodable image format")
        else:
            logger.warning(f"      ❌ OCR failed: {e}")
        _ocr_cache[img_url] = ''
        return ''


def extract_text_from_images(img_urls):
    """OCR a list of images, with caching and quality filtering."""
    extracted = []
    success_count = 0
    cache_hits = 0

    for idx, img_url in enumerate(img_urls, 1):
        if img_url in _ocr_cache:
            cache_hits += 1
            cached = _ocr_cache[img_url]
            if cached:
                extracted.append(f"=== Image {idx} (cached) ===\n{cached}")
                success_count += 1
            continue

        logger.info(f"    OCR [{idx}/{len(img_urls)}]: {img_url[:80]}...")
        text = ocr_image(img_url)
        if text:
            extracted.append(f"=== Image {idx}: {img_url} ===\n{text}")
            success_count += 1

    logger.info(f"    OCR Summary: {success_count}/{len(img_urls)} extracted, {cache_hits} cache hits")
    return "\n\n".join(extracted)


def extract_yaml_from_response(raw_response: str) -> str:
    """Extract a valid YAML document from an LLM response.

    Strategy (in order):
      1. Match a fenced code block (``` or ```yaml).
      2. Try parsing the whole response as YAML.
      3. Find the largest YAML-looking region and try parsing it.
      4. Try truncating from the end (recover from mid-output truncation).

    Lossy regex-based salvage was REMOVED - it produced flat scalars that
    discarded all nested structure (the very TTP/IOC data we care most
    about). Better to fail loudly so the orchestrator sees the chunk failed.
    """
    if not raw_response or not raw_response.strip():
        return ""

    # Strategy 1: fenced block (most common when model is well-behaved)
    fence_match = re.search(r"```(?:yaml)?\s*\n?(.*?)\n?\s*```", raw_response, re.DOTALL | re.IGNORECASE)
    if fence_match:
        candidate = fence_match.group(1).strip()
        result = _try_yaml_with_fixups(candidate)
        if result:
            return result

    # Strategy 2: parse the whole thing
    result = _try_yaml_with_fixups(raw_response.strip())
    if result:
        return result

    # Strategy 3: find a YAML-looking substring. Look for a line that starts
    # with a known top-level key ("title:", "description:", etc.) and parse
    # from there to end.
    top_keys = ['title:', 'description:', 'attribution:', 'malware_families:', 'cves:', 'ttps:', 'iocs:', 'authors:']
    for key in top_keys:
        idx = raw_response.find(key)
        if idx >= 0:
            # Walk back to start of that line
            line_start = raw_response.rfind('\n', 0, idx) + 1
            candidate = raw_response[line_start:].strip()
            # Strip trailing fences if any
            candidate = re.sub(r'```\s*$', '', candidate).strip()
            result = _try_yaml_with_fixups(candidate)
            if result:
                logger.info(f"    ⚙️ Found YAML starting at '{key}'")
                return result
            break  # try truncation strategies on this candidate too

    # Strategy 4: truncate from end (recover from mid-stream truncation
    # when max_tokens hits and a final list item is incomplete)
    candidate = raw_response.strip()
    # Strip outer fence if present
    candidate = re.sub(r'^```(?:yaml)?\s*\n?', '', candidate)
    candidate = re.sub(r'\n?\s*```\s*$', '', candidate)
    lines = candidate.splitlines()
    for cutoff in range(len(lines), max(len(lines) - 30, 0), -1):
        trimmed = "\n".join(lines[:cutoff]).strip()
        result = _try_yaml_with_fixups(trimmed)
        if result:
            logger.info(f"    ⚙️ Recovered YAML by truncating last {len(lines) - cutoff} lines")
            return result

    return ""


def _try_yaml_with_fixups(s):
    """Try to parse YAML, with fixups for common LLM mistakes."""
    if not s or not s.strip():
        return None

    # Direct attempt
    doc = _try_parse_yaml(s)
    if doc is not None:
        normalized = _normalize_yaml_doc(doc)
        if normalized:
            return yaml.dump(normalized, sort_keys=False).strip()

    # Common LLM mistake: tabs in indentation. YAML forbids tabs.
    if '\t' in s:
        fixed = s.replace('\t', '  ')
        doc = _try_parse_yaml(fixed)
        if doc is not None:
            normalized = _normalize_yaml_doc(doc)
            if normalized:
                return yaml.dump(normalized, sort_keys=False).strip()

    # Common mistake: trailing commas in flow-style lists
    if ',]' in s or ',}' in s:
        fixed = re.sub(r',(\s*[\]}])', r'\1', s)
        doc = _try_parse_yaml(fixed)
        if doc is not None:
            normalized = _normalize_yaml_doc(doc)
            if normalized:
                return yaml.dump(normalized, sort_keys=False).strip()

    # SCALAR-WITH-COLON FIXUP: auto-quote scalar values containing colons.
    # Example: "title: Foo: Bar" -> "title: \"Foo: Bar\""
    fixed = _quote_scalars_with_colons(s)
    if fixed != s:
        doc = _try_parse_yaml(fixed)
        if doc is not None:
            normalized = _normalize_yaml_doc(doc)
            if normalized:
                return yaml.dump(normalized, sort_keys=False).strip()

    # FLOW-CHAR-IN-LIST-ITEM FIXUP: auto-quote list items that start with
    # YAML flow indicators. Common when extracting code samples like:
    #   - {[Text.Encoding]::UTF8.GetString(...)}
    #   - [byte[]]($foo)
    # YAML reads { and [ as flow-style starts, so unquoted versions fail.
    fixed = _quote_list_items_starting_with_flow_chars(s)
    if fixed != s:
        doc = _try_parse_yaml(fixed)
        if doc is not None:
            normalized = _normalize_yaml_doc(doc)
            if normalized:
                return yaml.dump(normalized, sort_keys=False).strip()

    # Combined fixup: try both fixups together for cases where both classes
    # of error appear in the same response.
    combined = _quote_list_items_starting_with_flow_chars(_quote_scalars_with_colons(s))
    if combined != s:
        doc = _try_parse_yaml(combined)
        if doc is not None:
            normalized = _normalize_yaml_doc(doc)
            if normalized:
                return yaml.dump(normalized, sort_keys=False).strip()

    return None


# YAML characters that start flow-style nodes or trigger special parsing.
# A list item starting with one of these (without quoting) will fail to parse
# unless the rest is also valid flow-style YAML.
_YAML_FLOW_START_CHARS = set('{[>|&*!%@`')


def _quote_list_items_starting_with_flow_chars(s):
    """Find lines like '  - {foo: bar}' or '  - [byte[]]' and quote them.

    Specifically targets list items (lines whose content after indentation
    starts with '- ') whose value starts with a YAML flow indicator. Skips
    list items that are clearly intended as flow-style (trivial cases like
    '- [a, b, c]' that PyYAML can parse just fine).
    """
    out_lines = []
    for line in s.splitlines():
        # Match list items: indentation, "- ", then the value
        m = re.match(r'^(\s*-\s+)(.+)$', line)
        if not m:
            out_lines.append(line)
            continue
        prefix, value = m.group(1), m.group(2)
        # Skip if already quoted
        if value.startswith('"') or value.startswith("'"):
            out_lines.append(line)
            continue
        # Skip if value doesn't start with a flow char
        if not value or value[0] not in _YAML_FLOW_START_CHARS:
            out_lines.append(line)
            continue
        # Skip if the value is plausibly a valid flow-style construct that
        # PyYAML can already parse. We check: starts with [ or {, ends with
        # matching ] or }, balanced brackets, and contains no embedded
        # YAML-breaking patterns (`::`, `[[`, `{[`, etc. that occur in
        # PowerShell/C# code).
        if _is_plausibly_valid_flow(value):
            out_lines.append(line)
            continue
        # Quote the value. Use double quotes; escape backslashes and double quotes.
        escaped = value.replace('\\', '\\\\').replace('"', '\\"')
        out_lines.append(f'{prefix}"{escaped}"')
    return '\n'.join(out_lines)


def _is_plausibly_valid_flow(value):
    """Heuristic: detect strings that LOOK like valid YAML flow-style and
    should be left alone.

    We're trying to distinguish:
      - `[a, b, c]`  -> valid flow list, leave alone
      - `{key: val}` -> valid flow mapping, leave alone
      - `[byte[]]([Convert]::FromBase64String($_)| ForEach-Object{...})` -> code, must quote
    """
    v = value.strip()
    if not v:
        return False
    # Patterns that almost always indicate code/expressions (PowerShell, C#,
    # JavaScript) rather than YAML flow:
    code_indicators = ['::', '[[', ']]', '{[', ']}', '$_', '$env:', '@(']
    if any(ind in v for ind in code_indicators):
        return False
    # Try parsing it as a standalone YAML value to check validity
    try:
        yaml.safe_load(v)
        return True
    except yaml.YAMLError:
        return False
    return False


# Top-level scalar fields that frequently contain unquoted colons in LLM output
SCALAR_FIELDS_TO_QUOTE = ('title', 'description', 'attribution')


def _quote_scalars_with_colons(s):
    """Find lines like 'title: Foo: Bar' and rewrite to 'title: "Foo: Bar"'.

    Only operates on known top-level scalar fields - we never touch list
    items or nested keys.
    """
    out_lines = []
    for line in s.splitlines():
        # Only target the start of the line (no leading whitespace = top-level field)
        m = re.match(r'^([a-z_]+):\s+(.+)$', line)
        if m and m.group(1) in SCALAR_FIELDS_TO_QUOTE:
            key, value = m.group(1), m.group(2).strip()
            # If value already quoted, skip
            if value.startswith('"') or value.startswith("'"):
                out_lines.append(line)
                continue
            # If value contains a colon-space (or trailing colon), it needs quoting
            if ': ' in value or value.endswith(':'):
                # Escape any embedded double quotes
                escaped = value.replace('\\', '\\\\').replace('"', '\\"')
                out_lines.append(f'{key}: "{escaped}"')
                continue
        out_lines.append(line)
    return '\n'.join(out_lines)


def _try_parse_yaml(s: str):
    try:
        return yaml.safe_load(s)
    except Exception:
        return None


def _normalize_yaml_doc(doc):
    if isinstance(doc, dict):
        return doc

    if isinstance(doc, list):
        merged = {}
        for item in doc:
            if isinstance(item, dict):
                for k, v in item.items():
                    if k not in merged:
                        merged[k] = v
                    elif isinstance(v, list) and isinstance(merged[k], list):
                        merged[k].extend(x for x in v if x not in merged[k])
                    elif isinstance(v, dict) and isinstance(merged[k], dict):
                        for sk, sv in v.items():
                            if sk not in merged[k]:
                                merged[k][sk] = sv
        return merged if merged else None

    return None


def ask_llm(text, _retry=False):
    from math import ceil

    global llm_provider

    # Use 3.0 chars/token (vs 3.5) - more conservative for code/path-heavy content
    # which tokenizes more densely than prose. Cap at 8000 input tokens to leave
    # room for the prompt template (~1k tokens) and the response (~6k tokens)
    # within a 16k context window.
    estimated_tokens = ceil(len(text) / 3.0)
    if estimated_tokens > 8000:
        logger.warning(f"    ⚠️ Skipped (input too long: ~{estimated_tokens} tokens)")
        return ""

    system_prompt = "You are an expert cybersecurity analyst extracting detection-engineering signals from threat reports."
    # Use string replace instead of .format() because the prompt contains
    # literal curly braces (in YAML reserved-char examples and elsewhere).
    # .format() would try to interpret those as field names and crash with
    # KeyError or ValueError.
    user_prompt = PROMPT_TEMPLATE.replace("{REPORT_TEXT}", text)

    try:
        raw_response = llm_provider.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=0.2,
            max_tokens=6500  # bumped from 5000 - dense reports need room for full TTP lists
        )

        yaml_candidate = extract_yaml_from_response(raw_response)
        if yaml_candidate:
            return yaml_candidate

        # Logging: when extraction fails entirely, show the structure of what
        # came back so we can diagnose
        resp_len = len(raw_response) if raw_response else 0
        logger.warning(f"    ⚠️ No valid YAML found in {resp_len}-char response.")
        if raw_response:
            preview = raw_response[:300].replace('\n', ' | ')
            logger.warning(f"    Response preview: {preview}...")
            tail = raw_response[-200:].replace('\n', ' | ')
            logger.warning(f"    Response tail: ...{tail}")

            # Dump the full failed response for offline analysis. These are
            # the diagnostic gold for understanding why parsing fails.
            try:
                dump_dir = "failed_responses"
                os.makedirs(dump_dir, exist_ok=True)
                ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S-%f")
                dump_path = os.path.join(dump_dir, f"failed-{ts}.txt")
                with open(dump_path, 'w', encoding='utf-8') as f:
                    f.write(f"# Failed YAML extraction\n")
                    f.write(f"# Timestamp: {datetime.utcnow().isoformat()}\n")
                    f.write(f"# Response length: {resp_len} chars\n")
                    f.write(f"# Input chunk preview: {text[:200]!r}\n")
                    f.write(f"# {'='*60}\n\n")
                    f.write(raw_response)
                logger.warning(f"    📝 Full response dumped to: {dump_path}")
            except Exception as dump_err:
                logger.warning(f"    ⚠️ Could not dump failed response: {dump_err}")
        return ""

    except Exception as e:
        err_str = str(e).lower()
        is_transient = any(s in err_str for s in (
            'timed out', 'timeout', 'connection reset', 'connection aborted',
            'connection refused', 'broken pipe', 'remote disconnected',
            'eof occurred', 'incomplete read'
        ))
        if is_transient and not _retry:
            logger.warning(f"    ⚠️ Transient LLM error ({e}); retrying once...")
            import time
            time.sleep(3)  # brief pause before retry
            return ask_llm(text, _retry=True)

        logger.error(f"    ❌ LLM request failed: {e}")
        logger.error(f"    ❌ Payload text (truncated): {text[:500]}")
        return ""


def has_meaningful_content(data):
    """Check if normalized YAML data contains meaningful technical content."""
    if not isinstance(data, dict):
        return False

    ttps = data.get('ttps', {})
    iocs = data.get('iocs', {})
    cves = data.get('cves', [])

    # Any non-empty TTP field
    if isinstance(ttps, dict):
        for key, value in ttps.items():
            if isinstance(value, list) and len(value) > 0:
                logger.info(f"    ✓ Found meaningful TTP data in '{key}': {len(value)} items")
                return True

    # Any IOCs
    if isinstance(iocs, dict):
        for key, value in iocs.items():
            if isinstance(value, list) and len(value) > 0:
                logger.info(f"    ✓ Found IOCs: {len(value)} {key}")
                return True

    # CVEs are useful even without IOCs/TTPs (advisory posts)
    if isinstance(cves, list) and len(cves) > 0:
        logger.info(f"    ✓ Found CVEs: {cves}")
        return True

    # Malware family + attribution + description = useful even without raw IOCs
    has_attribution = bool(data.get('attribution', '').strip())
    has_malware = isinstance(data.get('malware_families'), list) and len(data['malware_families']) > 0
    if has_attribution and has_malware:
        logger.info(f"    ✓ Found attribution + malware family (light record)")
        return True

    logger.info("    ⚠️ No meaningful technical content found")
    return False


def write_yaml(content, source, malware):
    now = datetime.utcnow()
    year = now.strftime("%Y")
    month = now.strftime("%m")
    timestamp = now.strftime("%Y%m%d-%H%M%S")

    output_dir = os.path.join("results", year, month)
    os.makedirs(output_dir, exist_ok=True)

    filename = os.path.join(output_dir, f"{timestamp}-{source}-{malware}.yml")
    with open(filename, "w") as f:
        f.write(content)
    logger.info(f"    💾 Saved: {filename}")


def handle_article(url, cached, start_urls):
    nu = normalize_url(url)
    if nu in start_urls:
        logger.info(f"  ⏩ Skipped (is a start URL): {url}")
        return
    if nu in cached:
        logger.info(f"  ⏩ Skipped (already cached): {url}")
        return
    if url in cached:
        logger.info(f"  ⏩ Skipped (already cached, non-normalized): {url}")
        return

    logger.info(f"  Checking article: {url}")
    text, raw_html = extract_text_from_page(url)

    # Get OCR text first - some posts have technical content only in screenshots
    image_urls = extract_images_from_html(raw_html, url)
    image_text = extract_text_from_images(image_urls) if image_urls else ""

    # Combined text used for both gating and LLM extraction
    full_text = clean_text(text + "\n" + image_text)

    # Gate AFTER OCR so screenshot-heavy posts can pass
    if not is_security_report(full_text, url):
        logger.info("   ⚠️ Skipped (not a security advisory)")
        append_to_cache(url, start_urls)
        cached.add(nu)  # keep in-memory cache in sync
        return

    try:
        chunks = split_text_into_chunks(full_text)
        all_sections = []
        chunk_failures = 0

        for i, chunk in enumerate(chunks):
            logger.info(f"    → Processing chunk {i+1}/{len(chunks)}")
            logger.info(f"      Chunk length (chars): {len(chunk)}")
            logger.info(f"      Est. tokens: ~{int(len(chunk) / 3.4)}")

            if len(chunk) > 30000:
                logger.warning("      ⚠️ Trimming chunk to 30,000 characters")
                chunk = chunk[:30000]

            yaml_response = ask_llm(chunk)
            if yaml_response:
                all_sections.append(yaml_response.strip())
            else:
                chunk_failures += 1
                # If the first chunk fails on a multi-chunk article, the
                # output will be missing the most important content. Abort
                # rather than save partial garbage.
                if i == 0 and len(chunks) > 1:
                    logger.error(f"    ❌ First chunk failed on multi-chunk article - aborting (would produce partial output)")
                    return

        if not all_sections:
            logger.warning("    Skipped (no valid YAML extracted from chunks)")
            return

        if chunk_failures > 0:
            logger.warning(f"    ⚠️ {chunk_failures}/{len(chunks)} chunks failed LLM extraction")

        merged_data = merge_yamls(all_sections)
        merged_data["reference"] = url

        # Cross-validate against the source text. This catches the common
        # failure mode where the LLM fabricates plausible-looking PowerShell
        # commands, registry keys, or encoded payloads when the article
        # mentions concepts but doesn't show concrete examples.
        merged_data, dropped_count = cross_validate_against_source(merged_data, full_text)
        if dropped_count > 0:
            logger.info(f"    🛡️ Cross-validation dropped {dropped_count} fabricated value(s)")

        extracted_date = extract_date(url, raw_html)
        merged_data["date_of_publication"] = extracted_date if extracted_date else "Unknown"
        merged_data["file_creation_date"] = datetime.utcnow().strftime("%B %d, %Y")

        if not has_meaningful_content(merged_data):
            logger.info("    ⏩ Skipped writing YAML (no meaningful technical content)")
            append_to_cache(url, start_urls)
            cached.add(nu)
            return

        yaml_output = yaml.dump(merged_data, sort_keys=False, allow_unicode=True)

        mf_list = merged_data.get("malware_families", [])
        malware = mf_list[0].lower().replace(" ", "-") if mf_list else "unknown"
        # Sanitize for filesystem
        malware = re.sub(r'[^a-z0-9\-]', '', malware) or "unknown"

        source = url.split("/")[2].replace("www.", "").replace(".com", "")

        write_yaml(yaml_output, source, malware)
        append_to_cache(url, start_urls)
        cached.add(nu)

    except Exception as e:
        logger.error(f"   ❌ Failed to process {url}: {e}")
        import traceback
        logger.debug(traceback.format_exc())


def split_text_into_chunks(text, chunk_size=18000, overlap=1500):
    """Split text into overlapping chunks. Default 18k chars ~= 6k tokens at
    code-heavy density, leaving headroom for prompt + response in a 16k context."""
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start = end - overlap
    return chunks


def is_feed_url(url):
    u = url.lower()
    return any(ind in u for ind in ("/rss", "/feed", ".xml"))


def parse_args():
    parser = argparse.ArgumentParser(
        description="TTP-Threat-Feeds: Extract TTPs and IOCs from threat intelligence reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
LLM Provider Examples:
  --lmstudio                        Use LM Studio (default)
  --lmstudio --endpoint http://...  Use LM Studio with custom endpoint
  --ollama --model llama3.1:70b     Use Ollama with specific model
  --openai --model gpt-4o           Use OpenAI GPT-4o
  --claude --model claude-opus-4    Use Anthropic Claude
  --gemini --model gemini-2.0-flash Use Google Gemini

API Keys (for cloud providers):
  Set environment variables: OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY
  Or use --api-key flag
        """
    )

    provider_group = parser.add_mutually_exclusive_group()
    provider_group.add_argument('--lmstudio', action='store_true', default=True, help='Use LM Studio (default)')
    provider_group.add_argument('--ollama', action='store_true', help='Use Ollama')
    provider_group.add_argument('--openai', action='store_true', help='Use OpenAI API')
    provider_group.add_argument('--claude', action='store_true', help='Use Anthropic Claude API')
    provider_group.add_argument('--gemini', action='store_true', help='Use Google Gemini API')

    parser.add_argument('--model', type=str, help='Model name to use')
    parser.add_argument('--endpoint', type=str, help='API endpoint (for local providers)')
    parser.add_argument('--api-key', type=str, help='API key (for cloud providers)')

    args = parser.parse_args()

    if args.ollama:
        args.provider = 'ollama'
    elif args.openai:
        args.provider = 'openai'
    elif args.claude:
        args.provider = 'claude'
    elif args.gemini:
        args.provider = 'gemini'
    else:
        args.provider = 'lmstudio'

    return args


def initialize_llm_provider(args):
    global llm_provider

    provider_config = {}

    defaults = {
        'lmstudio': {
            'model_name': 'qwen2.5-coder-32b-instruct',
            'endpoint': 'http://127.0.0.1:1234/v1/chat/completions'
        },
        'ollama': {
            'model_name': 'qwen2.5-coder:32b',
            'endpoint': 'http://127.0.0.1:11434/api/chat'
        },
        'openai': {'model_name': 'gpt-4o'},
        'claude': {'model_name': 'claude-sonnet-4-6'},
        'gemini': {'model_name': 'gemini-2.0-flash'}
    }

    provider_defaults = defaults.get(args.provider, {})

    if args.model:
        provider_config['model_name'] = args.model
    else:
        provider_config['model_name'] = provider_defaults.get('model_name')

    if args.endpoint:
        provider_config['endpoint'] = args.endpoint
    elif 'endpoint' in provider_defaults:
        provider_config['endpoint'] = provider_defaults['endpoint']

    if args.api_key:
        provider_config['api_key'] = args.api_key

    try:
        llm_provider = create_provider(args.provider, **provider_config)
        logger.info(f"🤖 Initialized LLM Provider: {llm_provider.get_provider_name()}")
        logger.info(f"   Model: {llm_provider.model_name}")
        if hasattr(llm_provider, 'endpoint'):
            logger.info(f"   Endpoint: {llm_provider.endpoint}")
    except Exception as e:
        logger.error(f"❌ Failed to initialize LLM provider: {e}")
        raise


def main():
    global llm_provider

    args = parse_args()
    initialize_llm_provider(args)

    start_urls = read_start_urls()
    cached = read_cached_urls()
    with open(URLS_FILE, "r") as f:
        base_urls = [u.strip() for u in f if u.strip()]

    if USE_CURL_CFFI:
        logger.info("🌐 Using curl_cffi with automatic Chrome impersonation")
    else:
        logger.info("🌐 Using requests library with manual headers (curl_cffi not installed)")

    if AVIF_SUPPORT:
        logger.info("🖼️  AVIF image support enabled")
    else:
        logger.info("🖼️  AVIF support not available (pip install pillow-avif-plugin)")

    logger.info(f"Starting scan with {len(base_urls)} sources, {len(cached)} cached URLs")

    for base in base_urls:
        logger.info(f"\n{'='*80}")
        logger.info(f"Scanning: {base}")
        logger.info(f"{'='*80}")
        try:
            links = []
            if is_feed_url(base):
                logger.info(f"  Detected RSS/Feed URL")
                feed = feedparser.parse(base)

                if not feed.entries:
                    logger.warning(f"  ⚠️ No entries found in feed")
                else:
                    logger.info(f"  Found {len(feed.entries)} entries in feed")

                date_filtered = 0
                for entry in feed.entries:
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        try:
                            pub_date = datetime(*entry.published_parsed[:6])
                            if pub_date.date() >= (datetime.utcnow().date() - timedelta(days=7)):
                                links.append(entry.link)
                            else:
                                date_filtered += 1
                        except (TypeError, ValueError) as e:
                            logger.warning(f"  ⚠️ Failed to parse date, including anyway: {e}")
                            links.append(entry.link)
                    else:
                        links.append(entry.link)

                if date_filtered > 0:
                    logger.info(f"  Filtered out {date_filtered} entries older than 7 days")
                logger.info(f"  Kept {len(links)} recent feed entries")
            else:
                logger.info(f"  Non-feed URL, attempting RSS auto-discovery")

                html = fetch_html_content(base)
                all_links = []
                if html:
                    soup = BeautifulSoup(html, "html.parser")
                    discovered_feeds = discover_rss_feeds(soup, base)
                    common_feeds = try_common_feed_urls(base)
                    all_feeds = list(set(discovered_feeds + common_feeds))

                    if all_feeds:
                        logger.info(f"  ✓ Discovered {len(all_feeds)} RSS feed(s), using first one")
                        feed_url = all_feeds[0]
                        logger.info(f"  Using feed: {feed_url}")

                        feed = feedparser.parse(feed_url)
                        if feed.entries:
                            logger.info(f"  Found {len(feed.entries)} entries in discovered feed")
                            date_filtered = 0
                            for entry in feed.entries:
                                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                                    try:
                                        pub_date = datetime(*entry.published_parsed[:6])
                                        if pub_date.date() >= (datetime.utcnow().date() - timedelta(days=7)):
                                            links.append(entry.link)
                                        else:
                                            date_filtered += 1
                                    except (TypeError, ValueError) as e:
                                        logger.warning(f"  ⚠️ Failed to parse date, including anyway: {e}")
                                        links.append(entry.link)
                                else:
                                    links.append(entry.link)

                            if date_filtered > 0:
                                logger.info(f"  Filtered out {date_filtered} entries older than 7 days")
                            logger.info(f"  Kept {len(links)} recent feed entries")
                        else:
                            logger.warning(f"  ⚠️ Discovered feed has no entries, falling back to HTML")
                            all_links = extract_links_from_index(base, soup)
                    else:
                        logger.info(f"  No RSS feeds discovered, extracting links from HTML")
                        all_links = extract_links_from_index(base, soup)
                else:
                    logger.warning(f"  ⚠️ Failed to fetch HTML, skipping source")
                    all_links = []

                if not links and all_links:
                    cached_count = 0
                    bad_pattern_count = 0

                    # Filter first, sort by priority second, cap last
                    candidates = []
                    for link in all_links:
                        if link in cached:
                            cached_count += 1
                            continue

                        matched_pattern = None
                        for p in bad_patterns:
                            if re.search(p, link.lower()):
                                matched_pattern = p
                                break

                        if matched_pattern:
                            bad_pattern_count += 1
                            logger.info(f"    ❌ Bad pattern '{matched_pattern}': {link}")
                            continue

                        candidates.append(link)

                    # Sort: research-path URLs first, then product/service pages
                    candidates.sort(key=link_priority_score)
                    links = candidates[:MAX_ARTICLES_PER_SOURCE]

                    if len(candidates) > MAX_ARTICLES_PER_SOURCE:
                        logger.info(f"    Capped at {MAX_ARTICLES_PER_SOURCE} of {len(candidates)} candidates (priority-sorted)")

                    logger.info(f"  Summary: {cached_count} cached, {bad_pattern_count} bad patterns, {len(links)} to process")
                    logger.info(f"  Selected articles (priority-ordered):")
                    for i, link in enumerate(links, 1):
                        score = link_priority_score(link)
                        logger.info(f"    {i}. [priority={score}] {link}")

            logger.info(f"\n  Processing {len(links)} articles...")
            for idx, article_url in enumerate(links, 1):
                matched_pattern = None
                for p in bad_patterns:
                    if re.search(p, article_url.lower()):
                        matched_pattern = p
                        break

                if matched_pattern:
                    logger.info(f"  [{idx}/{len(links)}] ⏩ Skipped bad path '{matched_pattern}': {article_url}")
                    continue

                logger.info(f"  [{idx}/{len(links)}] Processing: {article_url}")
                handle_article(article_url, cached, start_urls)

        except Exception as e:
            logger.error(f"  ❌ Failed to scan {base}: {e}")
            import traceback
            logger.debug(traceback.format_exc())

    # Cache hit summary
    if _ocr_cache:
        total_entries = len(_ocr_cache)
        successful = sum(1 for v in _ocr_cache.values() if v)
        logger.info(f"\n📊 OCR Cache: {total_entries} unique images, {successful} produced text")


if __name__ == "__main__":
    main()
