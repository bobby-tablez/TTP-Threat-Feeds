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

# Try to use curl_cffi for better browser impersonation, fallback to requests
try:
    from curl_cffi import requests as cf_requests
    USE_CURL_CFFI = True
except ImportError:
    USE_CURL_CFFI = False

# CONFIG
LLM_ENDPOINT = "http://127.0.0.1:1234/v1/chat/completions"
HEADERS = {"Content-Type": "application/json"}
MODEL_NAME = "qwen2.5-coder-32b-instruct"
URLS_FILE = "urls.txt"
CACHE_FILE = "processed_urls.txt"
VERBOSE = os.getenv("VERBOSE", "1") == "1"  # Set VERBOSE=0 to disable detailed logging
REQUEST_DELAY = float(os.getenv("REQUEST_DELAY", "2.0"))  # Seconds between requests to same domain

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

PROMPT_TEMPLATE = """
You are a cybersecurity analyst extracting technical indicators from threat intelligence reports for detection engineering.

TASK: Extract TTPs and IOCs from the report below and output ONLY raw YAML.

CRITICAL RULES:
1. Return ONLY YAML - no markdown fences (```), no explanations, no commentary
2. Extract EXACT data only - preserve full command-lines, complete file paths, exact registry keys
3. DO NOT infer, guess, or generate placeholder values
4. If scripts are obfuscated (base64/hex), include them verbatim
5. Extract code from <pre>, <code>, and <table> blocks with full context
6. Use single quotes for strings, compact YAML formatting
7. As all data is important, do not truncate long command, registry, or path strings (e.g., "...")

OUTPUT SCHEMA:
description: <1-2 sentence threat summary>
attribution: <threat actor/APT group/nation-state or null>
malware_families: [<malware family names>]
TTPs:
  processes: [<process names: cmd.exe, powershell.exe, etc.>]
  commandline: [<full command-lines with ALL arguments - no truncation>]
  powershell: [<PowerShell scripts or one-liners>]
  scripting_engine: [<VBS, JScript, Python, Bash scripts>]
  registry_keys: [<full registry paths: HKEY_LOCAL_MACHINE\\...>]
  image_load: [<DLLs/libraries loaded by processes>]
  network_connections: [<process, destination, port>]
  file_activity: [<full file paths created/dropped/accessed/deleted>]
  persistence: [<persistence mechanism descriptions>]
  process_relations: [<parent->child process trees>]
CVEs: [<List of any CVEs identified related to the threat report>]
IOCs:
  hashes: [<MD5, SHA1, SHA256>]
  ip_addresses: [<IPv4/IPv6>]
  domains: [<domain names>]
  urls: [<full URLs>]
authors: [<report authors/researchers>]

If no technical details exist, return only description, attribution, malware_families, and authors with empty TTPs/IOCs.

REPORT:
{text}
"""

bad_patterns = [
    r"/faq", r"/platform", r"/industry", r"/category", r"/tag",
    r"/features", r"/services", r"/page", r"/newsletter", r"\?paged=\d+",
    r"\?_paged=\d+", r"/about", r"\bguide\b", r"\bhowto\b", r"\bhow-to\b",
    r"/rsac/", r"/weekly", r"/monthly", r"/quarterly"
]



def normalize_url(u: str) -> str:
    """Canonicalize for equality checks: drop fragment, trim trailing slash in path, lower host."""
    p = urlparse(u.strip())
    path = p.path.rstrip('/') or '/'
    # (Optional) drop tracking params; keep others
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not k.lower().startswith('utm_')]
    return urlunparse((p.scheme.lower() or 'https', p.netloc.lower(), path, '', urlencode(q), ''))

def read_start_urls() -> set[str]:
    if not os.path.exists(URLS_FILE):
        return set()
    with open(URLS_FILE, 'r') as f:
        return {normalize_url(line) for line in f if line.strip()}

def merge_yamls(chunks):
    merged = {}
    for chunk in chunks:
        try:
            data = yaml.safe_load(chunk)
        except yaml.YAMLError:
            continue

        # NEW: normalize list-of-dicts to one dict
        if isinstance(data, list):
            tmp = {}
            for item in data:
                if isinstance(item, dict):
                    for k, v in item.items():
                        if k not in tmp:
                            tmp[k] = v
                        else:
                            if isinstance(v, list) and isinstance(tmp[k], list):
                                tmp[k].extend(x for x in v if x not in tmp[k])
                            elif isinstance(v, dict) and isinstance(tmp[k], dict):
                                for sk, sv in v.items():
                                    if sk not in tmp[k]:
                                        tmp[k][sk] = sv
                                    elif isinstance(sv, list) and isinstance(tmp[k][sk], list):
                                        tmp[k][sk].extend(x for x in sv if x not in tmp[k][sk])
                                    else:
                                        tmp[k][sk] = sv
                            else:
                                tmp[k] = v
            data = tmp

        if not isinstance(data, dict):
            continue

        for key, value in data.items():
            if value in (None, "", [], {}):
                continue
            if key not in merged:
                merged[key] = value
            elif isinstance(value, list) and isinstance(merged.get(key), list):
                merged[key].extend(v for v in value if v not in merged[key])
            elif isinstance(value, dict) and isinstance(merged.get(key), dict):
                for subkey, subval in value.items():
                    if subval in (None, "", [], {}):
                        continue
                    if subkey not in merged[key]:
                        merged[key][subkey] = subval
                    elif isinstance(subval, list) and isinstance(merged[key][subkey], list):
                        merged[key][subkey].extend(v for v in subval if v not in merged[key][subkey])
                    else:
                        merged[key][subkey] = subval
            else:
                if len(str(value)) > len(str(merged[key])):
                    merged[key] = value
    return merged



def clean_text(text):
    # Normalize and strip bad Unicode
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    # Remove nulls, non-printables, and weird long dashes or symbols
    text = re.sub(r"[\x00-\x1F\x7F-\x9F\u2000-\u206F\u2190-\u21FF]", "", text)
    return text

def extract_date(url, html):
    # 1. Try common <time> or <meta> HTML tags
    soup = BeautifulSoup(html, "html.parser")

    # <time datetime="...">
    time_tag = soup.find("time")
    if time_tag and time_tag.get("datetime"):
        try:
            return date_parse(time_tag["datetime"]).strftime("%B %d, %Y")
        except:
            pass

    # <meta name="date" content="...">
    meta_date = soup.find("meta", {"name": "date"}) or soup.find("meta", {"property": "article:published_time"})
    if meta_date and meta_date.get("content"):
        try:
            return date_parse(meta_date["content"]).strftime("%B %d, %Y")
        except:
            pass

    # 2. Try extracting a date from the URL
    match = re.search(r"/(20\d{2})[/-](\d{1,2})[/-](\d{1,2})", url)
    if match:
        try:
            return datetime(int(match[1]), int(match[2]), int(match[3])).strftime("%B %d, %Y")
        except:
            pass

    # 3. Try scanning page text for known patterns
    text = soup.get_text()
    date_patterns = [
        r'\b\d{4}-\d{2}-\d{2}\b',         # 2024-05-14
        r'\b\d{2}/\d{2}/\d{4}\b',         # 14/05/2024
        r'\b\d{1,2} [A-Za-z]+ \d{4}\b'    # 14 May 2024
    ]
    for pattern in date_patterns:
        match = re.search(pattern, text)
        if match:
            try:
                return date_parse(match.group(0)).strftime("%B %d, %Y")
            except:
                continue

    # 4. Fallback: use current date
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
    # Normalize start_urls for comparison (handles trailing slash differences)
    normalized_start_urls = {normalize_url(u) for u in start_urls}
    if nu in normalized_start_urls:
        logger.info(f"    ⏩ Not caching (is a base/start URL): {nu}")
        return  # never cache your base/start URLs

    parsed = urlparse(nu)
    # Skip only the exact blog index (e.g., '/blog'), but NOT '/blog/<slug>'
    if parsed.path == '/blog' or parsed.path == '/':
        return

    # Keep your existing bad path filter (exact URL still wins)
    if any(re.search(p, nu.lower()) for p in bad_patterns):
        return

    cached = read_cached_urls()
    if nu not in cached:
        with open(CACHE_FILE, 'a') as f:
            f.write(nu + '\n')

IOC_PATTERNS = [
    re.compile(r"\b[a-f0-9]{32,64}\b", re.I),                         # hashes
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),                       # IPv4
    re.compile(r"\bhttps?://[^\s)>\]]+\b", re.I),                     # URLs
    re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I),              # domains
]

def is_security_report(text, url):
    t = (text or "").lower()
    score = 0
    matched_keywords = []

    for kw in ["cve", "malware", "exploit", "ransomware", "backdoor", "apt",
               "payload", "command", "persistence", "ttps", "threat", "advisory",
               "campaign", "malicious", "attack", "analysis", "cybercrime",
               "phish", "stealer", "loader", "dropper", "dfir"]:
        if kw in t:
            score += 1
            matched_keywords.append(kw)

    if re.search(r"CVE-\d{4}-\d{4,7}", t, re.I):
        score += 2
        matched_keywords.append("CVE-ID")
    if re.search(r"\bT1[0-9]{3}\b", t):  # MITRE ATT&CK IDs
        score += 2
        matched_keywords.append("MITRE-TTP")

    # IOC presence = strong signal
    if any(p.search(t) for p in IOC_PATTERNS):
        score += 2
        matched_keywords.append("IOCs")

    # avoid obvious author/team listing pages
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

def fetch_html_content(url, timeout=20):
    """Fetch HTML with polite rate limiting and automatic Chrome impersonation."""
    import time
    from urllib.parse import urlparse

    # Rate limit per domain
    domain = urlparse(url).netloc
    if domain in _domain_last_request:
        elapsed = time.time() - _domain_last_request[domain]
        if elapsed < REQUEST_DELAY:
            sleep_time = REQUEST_DELAY - elapsed
            logger.info(f"    ⏱️ Rate limiting: sleeping {sleep_time:.1f}s for {domain}")
            time.sleep(sleep_time)

    _domain_last_request[domain] = time.time()

    try:
        if USE_CURL_CFFI:
            # Use curl_cffi with automatic Chrome impersonation (always latest stable)
            # This mimics real Chrome's TLS fingerprint + HTTP/2 + headers automatically
            resp = cf_requests.get(url, impersonate="chrome", timeout=timeout, allow_redirects=True)
        else:
            # Fallback to requests with manual headers
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
        if status >= 400:
            logger.warning(f"    ⚠️ HTTP {status} fetching {url}")
        text = resp.text or ""

        # Detect common anti-bot challenges
        if 'cf-browser-verification' in text or 'Just a moment' in text:
            logger.warning(f"    ⚠️ Cloudflare challenge detected for {domain}")
        elif 'px-captcha' in text or 'PerimeterX' in text:
            logger.warning(f"    ⚠️ PerimeterX challenge detected for {domain}")
        elif 'distil_r_captcha' in text:
            logger.warning(f"    ⚠️ Distil Networks challenge detected for {domain}")

        return text
    except Exception as e:
        logger.error(f"    ❌ Fetch failed for {url}: {e}")
        return ""

def discover_rss_feeds(soup, base_url):
    """Discover RSS/Atom feeds from HTML <link> tags."""
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
    """Try common RSS feed URL patterns."""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    common_paths = [
        '/feed/',
        '/rss/',
        '/feed',
        '/rss',
        '/atom.xml',
        '/rss.xml',
        '/feed.xml',
        '/blog/feed/',
        '/blog/rss/',
    ]

    found_feeds = []
    for path in common_paths:
        test_url = base + path
        try:
            # Quick HEAD request to check if feed exists
            resp = requests.head(test_url, timeout=5, allow_redirects=True)
            if resp.status_code == 200:
                content_type = resp.headers.get('Content-Type', '').lower()
                if 'xml' in content_type or 'rss' in content_type or 'atom' in content_type:
                    found_feeds.append(test_url)
                    logger.info(f"    Found feed via common path: {test_url}")
        except:
            continue

    return found_feeds

THREAT_POSITIVE = {
    "threat", "research", "reverse", "malware", "ransom", "cve", "apt", "ttx",
    "ioc", "iocs", "ttp", "ttps", "exploit", "loader", "stealer", "backdoor",
    "campaign", "dfir", "ir", "forensic", "shellcode", "c2", "command-and-control",
    "botnet", "phishing", "initial-access", "persistence", "lateral", "exfiltration",
    "tactics", "techniques", "procedure", "tactic", "technique", "procedure", "intrusion"
}

MARKETING_NEGATIVE = {
    "press", "event", "webinar", "podcast", "release", "roadmap", "q&a",
    "feature", "product", "platform", "pricing", "case-study", "customer", "partner",
    "announcement", "announcing", "guide", "howto", "how-to", "newsletter",
    "weekly", "monthly", "quarterly", "hiring", "career", "culture", "tips"
}

def is_probable_research_link(href: str, link_text: str = "") -> bool:
    u = (href or "").lower()
    t = (link_text or "").lower()

    # require the URL path to look like an article/post (contains a slug)
    #if not re.search(r"/\w[\w-]{3,}$", u):  # e.g., /blog/some-interesting-slug
    #    return False

    # strong negatives first (kill obvious marketing/corp posts)
    for neg in MARKETING_NEGATIVE:
        if f"/{neg}/" in u:
            logger.info(f"    ❌ Rejected (marketing URL pattern '/{neg}/'): {href}")
            return False
        if neg in t:
            logger.info(f"    ❌ Rejected (marketing anchor text '{neg}'): {href}")
            return False

    # strong positives: threat keywords in slug or text
    if any(f"/{pos}/" in u for pos in THREAT_POSITIVE):
        logger.info(f"    ✓ Accepted (threat keyword in URL): {href}")
        return True
    if any(pos in t for pos in THREAT_POSITIVE):
        logger.info(f"    ✓ Accepted (threat keyword in anchor text): {href}")
        return True

    # heuristic: /blog/ + date in path is often a real post
    if "/blog/" in u and re.search(r"/20\d{2}/\d{1,2}/", u):
        logger.info(f"    ✓ Accepted (blog with date pattern): {href}")
        return True

    # default: conservative
    logger.info(f"    ⚠️ Rejected (no threat indicators): {href}")
    return False

def extract_links_from_index(base_url, soup=None):
    """Extract article links from an HTML page. Optionally accepts pre-parsed soup."""
    if soup is None:
        html = fetch_html_content(base_url)
        if not html:
            logger.warning(f"    ⚠️ Failed to fetch HTML from {base_url}")
            return []
        soup = BeautifulSoup(html, "html.parser")

    base_domain = urlparse(base_url).netloc

    anchors = soup.find_all('a', href=True)
    logger.info(f"    Found {len(anchors)} total anchor tags on page")

    kept = []
    off_domain = 0
    root_paths = 0

    for a in anchors:
        full_url = urljoin(base_url, a['href'])
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
    """Call trafilatura.extract with include_tables=True, falling back if the
    installed version doesn't support newer kwargs like favor_references."""
    try:
        return trafilatura.extract(
            html,
            include_comments=False,
            include_tables=True,
            favor_references=True,   # newer trafilatura versions only
        )
    except TypeError:
        # Older version: retry without the unknown kwarg(s)
        return trafilatura.extract(
            html,
            include_comments=False,
            include_tables=True,
        )

def extract_text_from_page(url):
    html = fetch_html_content(url)
    if not html:
        return "", ""

    # Try Trafilatura with a timeout
    signal.alarm(60)
    try:
        downloaded = _trafilatura_extract_compat(html)
    except TimeoutError:
        print(f"    ⚠️ Trafilatura timed out for: {url}")
        downloaded = None
    finally:
        signal.alarm(0)

    soup = BeautifulSoup(html, "html.parser")

    # Grab literal code/pre blocks (commands live here)
    code_chunks = []
    for node in soup.select("pre, code, kbd, samp"):
        txt = node.get_text("\n", strip=True)
        if txt and len(txt) >= 3:
            code_chunks.append(txt)
    code_blob = "\n".join(code_chunks)

    # Flatten tables (common IOC grids)
    table_lines = []
    for table in soup.find_all("table"):
        for r in table.find_all("tr"):
            cols = [c.get_text(" ", strip=True) for c in r.find_all(["th", "td"])]
            if any(cols):
                table_lines.append("\t".join(cols))
    table_blob = "\n".join(table_lines)

    if not downloaded:
        downloaded = soup.get_text("\n", strip=True)

    rich = "\n\n".join([
        "=== ARTICLE BODY ===",
        clean_text(downloaded or ""),
        "=== CODE BLOCKS ===",
        code_blob,
        "=== TABLES ===",
        table_blob
    ]).strip()

    return rich, html

def extract_images_from_html(html, base_url):
    """Extract image URLs from HTML, handling both absolute and relative URLs."""
    soup = BeautifulSoup(html, "html.parser")
    img_urls = []

    for img in soup.find_all('img'):
        # Try multiple src attributes (handles lazy loading)
        src = img.get('src') or img.get('data-src') or img.get('data-lazy-src')
        if not src:
            continue

        # Convert relative URLs to absolute
        full_url = urljoin(base_url, src)

        # Only include http/https URLs
        if full_url.startswith('http'):
            img_urls.append(full_url)

    logger.info(f"    Found {len(img_urls)} images in HTML")
    return img_urls

def preprocess_image_for_ocr(img):
    """Preprocess image to improve OCR accuracy for code/terminal screenshots."""
    from PIL import ImageEnhance, ImageFilter

    # Convert to grayscale
    img = img.convert('L')

    # Increase contrast (helps with low-contrast terminal screenshots)
    enhancer = ImageEnhance.Contrast(img)
    img = enhancer.enhance(2.0)

    # Apply sharpening
    img = img.filter(ImageFilter.SHARPEN)

    # Apply binary threshold (black text on white background works best)
    # This helps with dark terminal screenshots
    img = img.point(lambda x: 0 if x < 140 else 255, '1')

    return img

def extract_text_from_images(img_urls):
    """Extract text from images using OCR with preprocessing and error handling."""
    extracted = []
    success_count = 0

    for idx, img_url in enumerate(img_urls, 1):
        try:
            logger.info(f"    OCR [{idx}/{len(img_urls)}]: {img_url[:80]}...")

            # Download image
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
            img_data = resp.content

            # Open and check image dimensions
            img = Image.open(BytesIO(img_data))
            width, height = img.size

            # Skip tiny images (likely icons/logos)
            if width < 100 or height < 100:
                logger.info(f"      ⏩ Skipped (too small: {width}x{height})")
                continue

            # Skip very large images (likely not screenshots)
            if width > 3000 or height > 3000:
                logger.info(f"      ⏩ Skipped (too large: {width}x{height})")
                continue

            logger.info(f"      Image size: {width}x{height}")

            # Preprocess for better OCR
            processed_img = preprocess_image_for_ocr(img)

            # Run OCR with optimized settings for code/terminal text
            # PSM 6 = Assume uniform block of text (good for code blocks)
            # PSM 11 = Sparse text (good for screenshots with mixed content)
            custom_config = r'--oem 3 --psm 6'
            text = pytesseract.image_to_string(processed_img, config=custom_config)

            if text.strip():
                extracted.append(f"=== Image {idx}: {img_url} ===\n{text.strip()}")
                success_count += 1
                logger.info(f"      ✓ Extracted {len(text.strip())} characters")
            else:
                logger.info(f"      ⚠️ No text found")

        except requests.RequestException as e:
            logger.warning(f"      ❌ Failed to download: {e}")
        except Exception as e:
            logger.warning(f"      ❌ OCR failed: {e}")
            continue

    logger.info(f"    OCR Summary: {success_count}/{len(img_urls)} images extracted successfully")
    return "\n\n".join(extracted)

import yaml
import re

def extract_yaml_from_response(raw_response: str) -> str:
    """
    Return a YAML string if we can confidently parse it (with or without fences).
    Accepts:
      - fenced blocks ```yaml ... ```
      - bare YAML dict
      - YAML list of dicts (we'll merge into one dict)
    Returns '' if nothing valid is found.
    """
    if not raw_response or not raw_response.strip():
        return ""

    # 1) Prefer fenced block if present
    m = re.search(r"```(?:yaml)?\s*(.*?)\s*```", raw_response, re.DOTALL | re.IGNORECASE)
    candidate = m.group(1).strip() if m else raw_response.strip()

    # 2) Try parsing as-is
    doc = _try_parse_yaml(candidate)
    if doc is not None:
        # normalize to a single dict YAML
        normalized = _normalize_yaml_doc(doc)
        if normalized:
            return yaml.dump(normalized, sort_keys=False).strip()

    # Try parsing progressively shorter tails to salvage partial YAML
    lines = candidate.splitlines()
    for cutoff in range(len(lines), max(len(lines) - 10, 0), -1):
        trimmed = "\n".join(lines[:cutoff]).strip()
        doc2 = _try_parse_yaml(trimmed)
        if doc2:
            normalized = _normalize_yaml_doc(doc2)
            if normalized:
                print("    ⚙️ Salvaged partial YAML block.")
                return yaml.dump(normalized, sort_keys=False).strip()

    # As a last resort, extract anything that looks like a key: value pair
    rough_pairs = re.findall(r"^([A-Za-z0-9_]+):\s*(.+)$", candidate, re.M)
    if rough_pairs:
        salvaged = {k: v for k, v in rough_pairs}
        print("    ⚙️ Reconstructed rough YAML from key-value pairs.")
        return yaml.dump(salvaged, sort_keys=False).strip()

    return ""

def _try_parse_yaml(s: str):
    try:
        return yaml.safe_load(s)
    except Exception:
        return None

def _normalize_yaml_doc(doc):
    """
    Accept:
      - dict: return as-is
      - list: if it's a list of dicts, merge; if it's a list of 'key:value' items, coalesce
    """
    if isinstance(doc, dict):
        return doc

    if isinstance(doc, list):
        merged = {}
        for item in doc:
            if isinstance(item, dict):
                for k, v in item.items():
                    if k not in merged:
                        merged[k] = v
                    else:
                        # merge lists/dicts sensibly
                        if isinstance(v, list) and isinstance(merged[k], list):
                            merged[k].extend(x for x in v if x not in merged[k])
                        elif isinstance(v, dict) and isinstance(merged[k], dict):
                            for sk, sv in v.items():
                                if sk not in merged[k]:
                                    merged[k][sk] = sv
                                elif isinstance(sv, list) and isinstance(merged[k][sk], list):
                                    merged[k][sk].extend(x for x in sv if x not in merged[k][sk])
                                else:
                                    merged[k][sk] = sv
                        else:
                            merged[k] = v
            else:
                # ignore scalars in a top-level list; not useful here
                continue
        return merged if merged else None

    # anything else — ignore
    return None


def ask_llm(text):
    import json
    from math import ceil

    estimated_tokens = ceil(len(text) / 3.5)
    if estimated_tokens > 12000:
        print(f"    ⚠️ Skipped (input too long: ~{estimated_tokens} tokens)")
        return ""

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": "You are an expert cybersecurity analyst."},
            {"role": "user", "content": PROMPT_TEMPLATE.format(text=json.dumps(text)[1:-1])}
        ],
        "temperature": 0.2,
        "max_tokens": 5000
    }

    try:
        resp = requests.post(LLM_ENDPOINT, headers=HEADERS, json=payload)
        resp.raise_for_status()
        data = resp.json()

        if "choices" not in data:
            print(f"    ❌ Unexpected LLM response: {data}")
            return ""

        raw_response = data["choices"][0]["message"]["content"]
        yaml_candidate = extract_yaml_from_response(raw_response)
        if yaml_candidate:
            return yaml_candidate

        print("    ⚠️ No valid YAML block found — dumping raw response:")
        print(raw_response[:500])
        return ""

    except Exception as e:
        print(f"    ❌ LLM request failed: {e}")
        print("    ❌ Payload text (truncated):", text[:500])
        return ""



def has_meaningful_content(data):
    """Check if YAML data contains meaningful technical content beyond just description."""
    if not isinstance(data, dict):
        return False

    # Check TTPs section
    ttps = data.get('TTPs', {})
    if isinstance(ttps, dict):
        # Check if any TTP category has non-empty values
        for key, value in ttps.items():
            if isinstance(value, list) and len(value) > 0:
                logger.info(f"    ✓ Found meaningful TTP data in '{key}': {len(value)} items")
                return True
            elif value and not isinstance(value, list):  # Non-list non-empty value
                logger.info(f"    ✓ Found meaningful TTP data in '{key}'")
                return True

    # Check IOCs section
    iocs = data.get('IOCs', {})
    if isinstance(iocs, dict):
        for key, value in iocs.items():
            if isinstance(value, list) and len(value) > 0:
                logger.info(f"    ✓ Found IOCs: {len(value)} {key}")
                return True

    # Also accept malware_families as meaningful
    malware_families = data.get('malware_families', [])
    if isinstance(malware_families, list) and len(malware_families) > 0:
        logger.info(f"    ✓ Found malware families: {malware_families}")
        # But only if there's also some IOCs or TTPs
        if iocs or any(isinstance(v, list) and len(v) > 0 for v in ttps.values() if isinstance(ttps, dict)):
            return True

    logger.info("    ⚠️ No meaningful technical content found (empty TTPs and IOCs)")
    return False

def write_yaml(content, source, malware):
    now = datetime.utcnow()
    year = now.strftime("%Y")
    month = now.strftime("%m")
    day = now.strftime("%d")
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

    print(f"  Checking article: {url}")
    text, raw_html = extract_text_from_page(url)

    if not is_security_report(text, url):
        print("   ⚠️ Skipped (not a security advisory)")
        append_to_cache(url, start_urls)
        return

    try:
        image_urls = extract_images_from_html(raw_html, url)
        image_text = extract_text_from_images(image_urls)
        full_text = clean_text(text + "\n" + image_text)

        chunks = split_text_into_chunks(full_text)
        all_sections = []

        for i, chunk in enumerate(chunks):
            print(f"    → Processing chunk {i+1}/{len(chunks)}")
            print(f"      Chunk length (chars): {len(chunk)}")
            print(f"      Est. tokens: ~{int(len(chunk) / 3.4)}")

            if len(chunk) > 30000:
                print("      ⚠️ Trimming chunk to 30,000 characters")
                chunk = chunk[:30000]

            yaml_response = ask_llm(chunk)
            if yaml_response:
                all_sections.append(yaml_response.strip())

        if not all_sections:
            print("    Skipped (no valid YAML extracted from chunks)")
            return

        # Merge all parsed YAMLs into one dict
        merged_data = merge_yamls(all_sections)
        merged_data["reference"] = url
        extracted_date = extract_date(url, raw_html)
        merged_data["date_of_publication"] = extracted_date if extracted_date else "Unknown"
        merged_data["file_creation_date"] = datetime.utcnow().strftime("%B %d, %Y")

        # Check if content is meaningful before writing
        if not has_meaningful_content(merged_data):
            logger.info("    ⏩ Skipped writing YAML (no meaningful technical content)")
            append_to_cache(url, start_urls)
            return

        yaml_output = yaml.dump(merged_data, sort_keys=False)

        # Extract malware family from final merged dict
        mf_list = merged_data.get("malware_families", [])
        malware = mf_list[0].lower().replace(" ", "-") if mf_list else "unknown"

        source = url.split("/")[2].replace("www.", "").replace(".com", "")
        write_yaml(yaml_output, source, malware)
        append_to_cache(url, start_urls)

    except Exception as e:
        print(f"   ❌ Failed to process {url}: {e}")



def split_text_into_chunks(text, chunk_size=25000, overlap=1500):  # ≈ 8k–9k tokens
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start = end - overlap  # overlap for context continuity
    return chunks

def is_feed_url(url):
    u = url.lower()
    return any(ind in u for ind in ("/rss", "/feed", ".xml"))


def main():
    MAX_ARTICLES_PER_SOURCE = 7
    start_urls = read_start_urls()
    cached = read_cached_urls()
    with open(URLS_FILE, "r") as f:
        base_urls = [u.strip() for u in f if u.strip()]

    # Log which HTTP client is being used
    if USE_CURL_CFFI:
        logger.info("🌐 Using curl_cffi with automatic Chrome impersonation (TLS + HTTP/2 fingerprinting)")
    else:
        logger.info("🌐 Using requests library with manual headers (curl_cffi not installed)")

    logger.info(f"Starting scan with {len(base_urls)} sources, {len(cached)} cached URLs")

    for base in base_urls:
        print(f"\n{'='*80}")
        print(f"Scanning: {base}")
        print(f"{'='*80}")
        try:
            links = []
            if is_feed_url(base):
                logger.info(f"  Detected RSS/Feed URL")
                feed = feedparser.parse(base)

                if not feed.entries:
                    logger.warning(f"  ⚠️ No entries found in feed (may be malformed or blocked)")
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
                            logger.warning(f"  ⚠️ Failed to parse date for entry, including anyway: {e}")
                            links.append(entry.link)
                    else:
                        links.append(entry.link)

                if date_filtered > 0:
                    logger.info(f"  Filtered out {date_filtered} entries older than 7 days")
                logger.info(f"  Kept {len(links)} recent feed entries")
            else:
                logger.info(f"  Non-feed URL, attempting RSS auto-discovery")

                # First, try to discover RSS feeds
                html = fetch_html_content(base)
                if html:
                    soup = BeautifulSoup(html, "html.parser")
                    discovered_feeds = discover_rss_feeds(soup, base)

                    # Also try common feed paths
                    common_feeds = try_common_feed_urls(base)
                    all_feeds = list(set(discovered_feeds + common_feeds))

                    if all_feeds:
                        logger.info(f"  ✓ Discovered {len(all_feeds)} RSS feed(s), using first one")
                        # Use the first discovered feed
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
                                        logger.warning(f"  ⚠️ Failed to parse date for entry, including anyway: {e}")
                                        links.append(entry.link)
                                else:
                                    links.append(entry.link)

                            if date_filtered > 0:
                                logger.info(f"  Filtered out {date_filtered} entries older than 7 days")
                            logger.info(f"  Kept {len(links)} recent feed entries")
                        else:
                            logger.warning(f"  ⚠️ Discovered feed has no entries, falling back to HTML scraping")
                            all_links = extract_links_from_index(base, soup)
                    else:
                        logger.info(f"  No RSS feeds discovered, extracting links from HTML")
                        all_links = extract_links_from_index(base, soup)
                else:
                    logger.warning(f"  ⚠️ Failed to fetch HTML, skipping source")
                    all_links = []

                # If we didn't get links from RSS, process HTML links
                if not links and all_links:
                    # Take first N that aren't cached and aren't obviously bad
                    cached_count = 0
                    bad_pattern_count = 0

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

                        links.append(link)
                        if len(links) >= MAX_ARTICLES_PER_SOURCE:
                            logger.info(f"    Reached max articles limit ({MAX_ARTICLES_PER_SOURCE})")
                            break

                    logger.info(f"  Summary: {cached_count} cached, {bad_pattern_count} bad patterns, {len(links)} to process")

            logger.info(f"\n  Processing {len(links)} articles...")
            for idx, article_url in enumerate(links, 1):
                # Double-check bad patterns (for RSS feeds which skip the above filter)
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

if __name__ == "__main__":
    main()
