import os
import re
import yaml
import json
import requests
import feedparser
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urljoin, urlparse
import signal
from io import BytesIO
from PIL import Image
import pytesseract
import trafilatura
import collections
import unicodedata
import string


# CONFIG
LLM_ENDPOINT = "http://127.0.0.1:1234/v1/chat/completions"
HEADERS = {"Content-Type": "application/json"}
MODEL_NAME = "gemma-3-12b-it@q8_0"
URLS_FILE = "urls.txt"
CACHE_FILE = "processed_urls.txt"

PROMPT_TEMPLATE = """
I need you to create a technical YAML Report. The purpose of the YAML report is to present raw data from public security advisories. We need raw commands executed by attackers, registry keys, executed code as part of the TTPs section.
Extract the following information from this cyber threat report:
- description: A 1-2 sentence summary
- date: Extract and provide the date of publication, typically found in the publication header (format: YYYY-MM-DD)
- authors: Author(s)
- attribution: Attribution (threat actor, APT group, country)
- malware_families: Malware family names
- TTPs: Extract ALL actual observable indicators. Each TTP subkey containing list items as outlined (no deviation, only the data listed). TTPs include the following sub keys: (exclude the following sub keys if not present)
  - processs: a list of all process names executed
  - commandline: Full list of process with commandline
  - powershell: powershell scripts
  - scripting_engine: other scripts such as VBS, JScript, Python
  - registry_keys: Windows registry keys impacted
  - network_connections: processes making network connections and their ports, destinations in a list
  - file_modifications: List of files created, files deleted (full paths)
  - persistence: description or sub keys persistence methods used
  - pipes: list of any named pipes
  - process_relations: process trees based on your analysis
- Indicators of compromise (hashes, IPs, domains, URLs)

RESULTS: Return all results in YAML format with the following keys: description, date, authors, attribution, malware_families, TTPs, IOCs

Additional requirements:
Do not make up information. Do not summarize TTPs. Only return relevant data that is explicitly present in the report. if no TTPs, ignore and provide empty tags
If the publication contains little useful data, lots of empty fields are acceptable
Be very detailed (e.g: include ALL and FULL command line arguements)
Never truncate outputs (e.g: ...), include full command line and URLs
Provide only technical data, for example, don't describe TTPs, IOCs and URLs. Only provide raw commands, URLs, etc where appropriate
For any key or subkey that contains no data, do not include the key or subkey in the YAML.
Use single quotes for YAML syntax.

Context:
{text}
"""

def merge_yamls(yaml_texts):
    merged = {}
    for yml in yaml_texts:
        try:
            parsed = yaml.safe_load(yml)
            for key, value in parsed.items():
                if key not in merged:
                    merged[key] = value
                elif isinstance(value, list):
                    merged[key] = list({*merged.get(key, []), *value})
                elif isinstance(value, dict):
                    merged[key] = merged.get(key, {})
                    for subkey, subval in value.items():
                        if subkey not in merged[key]:
                            merged[key][subkey] = subval
                        elif isinstance(subval, list):
                            merged[key][subkey] = list({*merged[key][subkey], *subval})
                        else:
                            merged[key][subkey] = subval
                else:
                    merged[key] = value  # Last one wins
        except Exception:
            continue
    return merged

def clean_text(text):
    # Normalize and strip bad Unicode
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    # Remove nulls, non-printables, and weird long dashes or symbols
    text = re.sub(r"[\x00-\x1F\x7F-\x9F\u2000-\u206F\u2190-\u21FF]", "", text)
    return text


def read_cached_urls():
    if not os.path.exists(CACHE_FILE):
        return set()
    with open(CACHE_FILE, "r") as f:
        return set(line.strip() for line in f)

def append_to_cache(url):
    from urllib.parse import urlparse
    bad_patterns = [
        r"/faq", r"/platform", r"/news", r"/industry", r"/category", r"/tag",
        r"/features", r"/services", r"/page", r"/newsletter", r"\\?paged=\\d+",
        r"\\?_paged=\\d+", r"/about", r"guide", r"howto", r"how-to", r"/feed"
    ]
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
    keywords = ["cve", "malware", "exploit", "ransomware", "backdoor", "apt", "payload", "command", "persistence", "ttps", "threat", "advisory", "campaign", "malicious", "attack"]
    score = sum(1 for kw in keywords if kw in text.lower())
    if re.search(r"CVE-\\d{4}-\\d{4,7}", text):
        score += 2
    if re.search(r"T1[0-9]{3}", text):
        score += 2
    if re.search(r"/author/|/team/|/experts/|/page/", url.lower()):
        return False
    return score >= 2

def fetch_html_content(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    }
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

def ask_llm(text):
    import json
    from math import ceil

    estimated_tokens = ceil(len(text) / 3.5)  # crude approximation: 1 token ≈ 3.5 chars
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
        match = re.search(r"```(?:yaml)?\s*(.*?)\s*```", raw_response, re.DOTALL)
        if match:
            return match.group(1).strip()

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

def main():
    MAX_ARTICLES_PER_SOURCE = 3
    cached = read_cached_urls()
    with open(URLS_FILE, "r") as f:
        base_urls = [u.strip() for u in f if u.strip()]

    for base in base_urls:
        print(f"Scanning: {base}")
        try:
            links = []
            if base.endswith(".xml") or "rss" in base:
                feed = feedparser.parse(base)
                for entry in feed.entries:
                    if hasattr(entry, 'published_parsed'):
                        pub_date = datetime(*entry.published_parsed[:6])
                        if pub_date.date() == datetime.utcnow().date():
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
                handle_article(article_url, cached)
        except Exception as e:
            print(f"  Failed to scan {base}: {e}")

if __name__ == "__main__":
    main()
