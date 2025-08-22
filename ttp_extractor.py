import os
import re
import yaml
import json
import requests
import feedparser
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse
import signal
from io import BytesIO
from PIL import Image
import pytesseract
import trafilatura
import collections
import unicodedata
import string
from dateutil.parser import parse as date_parse
from latest_user_agents import get_latest_user_agents, get_random_user_agent

# CONFIG
LLM_ENDPOINT = "http://127.0.0.1:1234/v1/chat/completions"
HEADERS = {"Content-Type": "application/json"}
MODEL_NAME = "openai/gpt-oss-20b"
URLS_FILE = "urls.txt"
CACHE_FILE = "processed_urls.txt"

PROMPT_TEMPLATE = """
Create a technical YAML Report based on threat data with the goal of extracting TTPs and IoCs. The purpose of the report is to highlight raw data extracted from public security advisories. 
Extract the following information from this cyber threat report and present it in the following format:

Additional critical requirements:
- Only return the raw YAML content. Do not include explanations, introductions or comments.
- If there are no explicit technical details (e.g., command lines, registry keys, process names, etc.), return an empty YAML with only the description, authors, and IOCs keys.
- Do NOT guess or infer any data — even if it seems likely. Do not generate placeholder or generic TTPs.
- When commands are present, include ALL and FULL command line arguements (no truncation).
- Use compact YAML formatting. Use single quotes for all strings.

Include the follwing YAML tags (template):
- description: A 1-2 sentence summary
- attribution: Attribution (threat actor, APT group, country).
- malware_families: Malware family names.
- TTPs: Extract ALL identified observable indicators. No formal sentences in this section, just data. Each TTP subkey containing list items as outlined. If no applicable data is found, provide empty keys. TTPs include the following sub keys:
  - processes: a list of all process names that were apart of the report
  - commandline: Full list of process with commandline arguments
  - powershell: any and all powershell scripts
  - scripting_engine: other scripts such as VBS, JScript, Python, bash, etc.
  - registry_keys: Windows registry keys impacted
  - image_load: Provide details as to processes involved with loaded DLL, or SO libraries
  - network_connections: Processes related - list executables that made network connections, their destination address, URL or hostname along with ports. 
  - file_activity: List of files created, dropped, accessed or deleted (full paths)
  - persistence: description in a list sub keys persistence methods used
  - process_relations: process trees based on your analysis
- IOCs: List all indicators of compromise. These can include hashes, IPs, domains and URLs) 
- authors: Identify and list the people who contributed to the report (the authors).

Context:
{text}
"""

bad_patterns = [
    r"/faq", r"/platform", r"/industry", r"/category", r"/tag",
    r"/features", r"/services", r"/page", r"/newsletter", r"\?paged=\d+",
    r"\?_paged=\d+", r"/about", r"guide", r"howto", r"how-to", r"rsac", r"weekly", r"monthly", r"quarterly"
]

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

def append_to_cache(url):
    from urllib.parse import urlparse

    if any(re.search(p, url.lower()) for p in bad_patterns):
        return

    parsed = urlparse(url)
    if not parsed.path or parsed.path in ["", "/"]:
        return
    cached = read_cached_urls()
    if url not in cached:
        with open(CACHE_FILE, "a") as f:
            f.write(url + "\n")

def is_security_report(text, url):
    keywords = ["cve", "malware", "exploit", "ransomware", "backdoor", "apt", "payload", "command", "persistence", "ttps", "threat", "advisory", "campaign", "malicious", "attack", "analysis", "cybercrime", "operation", "phish", "stealer", "loader", "dropper"]
    score = sum(1 for kw in keywords if kw in text.lower())
    if re.search(r"CVE-\\d{4}-\\d{4,7}", text):
        score += 2
    if re.search(r"T1[0-9]{3}", text):
        score += 2
    if re.search(r"/author/|/team/|/experts/|/page/", url.lower()):
        return False
    return score >= 2

def fetch_html_content(url):
    headers = {"User-Agent": get_random_user_agent()}
    resp = requests.get(url, headers=headers)
    return resp.text

def extract_links_from_index(base_url):
    html = fetch_html_content(base_url)
    soup = BeautifulSoup(html, "html.parser")
    base_parsed = urlparse(base_url)
    base_domain = base_parsed.netloc
    base_path = base_parsed.path.rstrip("/")
    links = []
    for a in soup.find_all('a', href=True):
        full_url = urljoin(base_url, a['href'])
        parsed_url = urlparse(full_url)
        if parsed_url.netloc == base_domain and parsed_url.path.startswith(base_path) and parsed_url.path != base_parsed.path:
            links.append(full_url)
    return sorted(set(links))

def timeout_handler(signum, frame):
    raise TimeoutError("Trafilatura extraction timed out.")

signal.signal(signal.SIGALRM, timeout_handler)

def extract_text_from_page(url):
    html = fetch_html_content(url)
    signal.alarm(60)  # 60-second timeout
    try:
        downloaded = trafilatura.extract(html, include_comments=False, include_tables=False)
        signal.alarm(0)
    except TimeoutError:
        print(f"    ⚠️ Trafilatura timed out for: {url}")
        downloaded = None
    if not downloaded:
        soup = BeautifulSoup(html, "html.parser")
        return soup.get_text(), html
    return downloaded, html

def extract_images_from_html(html):
    soup = BeautifulSoup(html, "html.parser")
    return [img['src'] for img in soup.find_all('img') if img.get('src') and img['src'].startswith('http')]

def extract_text_from_images(img_urls):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    }
    extracted = []
    for img_url in img_urls:
        try:
            img_data = requests.get(img_url, headers=headers).content
            img = Image.open(BytesIO(img_data))
            text = pytesseract.image_to_string(img)
            extracted.append(text)
        except Exception:
            continue
    return "\n".join(extracted)

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

    # 3) Heuristic: sometimes trailing partial lines break YAML; trim to last complete line and retry
    lines = candidate.splitlines()
    if len(lines) > 3:
        trimmed = "\n".join(lines[:-1]).strip()
        doc2 = _try_parse_yaml(trimmed)
        if doc2 is not None:
            normalized = _normalize_yaml_doc(doc2)
            if normalized:
                return yaml.dump(normalized, sort_keys=False).strip()

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

def handle_article(url, cached):
    if url in cached:
        return

    print(f"  Checking article: {url}")
    text, raw_html = extract_text_from_page(url)

    if not is_security_report(text, url):
        print("   ⚠️ Skipped (not a security advisory)")
        append_to_cache(url)
        return

    try:
        image_urls = extract_images_from_html(raw_html)
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
        yaml_output = yaml.dump(merged_data, sort_keys=False)

        # Extract malware family from final merged dict
        mf_list = merged_data.get("malware_families", [])
        malware = mf_list[0].lower().replace(" ", "-") if mf_list else "unknown"

        source = url.split("/")[2].replace("www.", "").replace(".com", "")
        write_yaml(yaml_output, source, malware)
        append_to_cache(url)

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
    rss_indicators = ["/rss", "/feed", ".xml"]
    return any(ind in url.lower() for ind in rss_indicators)

def main():
    MAX_ARTICLES_PER_SOURCE = 5
    cached = read_cached_urls()
    with open(URLS_FILE, "r") as f:
        base_urls = [u.strip() for u in f if u.strip()]

    for base in base_urls:
        print(f"Scanning: {base}")
        try:
            links = []
            if is_feed_url(base):
                feed = feedparser.parse(base)
                for entry in feed.entries:
                    if hasattr(entry, 'published_parsed'):
                        pub_date = datetime(*entry.published_parsed[:6])
                        if pub_date.date() >= (datetime.utcnow().date() - timedelta(days=7)):
                            links.append(entry.link)
                    else:
                        links.append(entry.link)
            else:
                all_links = extract_links_from_index(base)
                valid_links = []
                for link in all_links:
                    if link in cached:
                        continue
                    try:
                        text, _ = extract_text_from_page(link)
                        if is_security_report(text, link):
                            valid_links.append(link)
                    except:
                        continue
                    if len(valid_links) >= MAX_ARTICLES_PER_SOURCE:
                        break
                links = valid_links

            for article_url in links:
                if any(re.search(p, article_url.lower()) for p in bad_patterns):
                    print(f"  ⏩ Skipped bad path: {article_url}")
                    continue
                handle_article(article_url, cached)

        except Exception as e:
            print(f"  Failed to scan {base}: {e}")


if __name__ == "__main__":
    main()
