# TTP-Threat-Feeds

![TTP-Threat-Feeds](assets/ttp-threat-feeds-header.png)

**TTP-Threat-Feeds** is a script-powered threat feed generator designed to extract adversarial TTPs and IOCs using ✨AI✨

The purpose of this project is to automate the discovery and parsing of threat actor behavior from published security research. By scraping posts from trusted vendors and blogs listed in `urls.txt`, the tool identifies relevant content, extracts observable adversary behaviors (TTPs) and then outputs structured, human-readable YAML files. These YAML files are designed to help detection engineers and threat researchers quickly derive detection opportunities and correlation logic.

---

## ⚙️ How It Works

- Scrapes URLs from vetted threat intel sources (`urls.txt`)
- Extracts the text of each publication including embedded image OCR for screenshots
- Feeds content into a local LLM with a purpose-built prompt
- Extracts:
  - Summary
  - Attribution
  - Malware families
  - MITRE ATT&CK techniques
  - Full command lines
  - Process relationships
  - Persistence and lateral movement artifacts
  - IOCs (domains, IPs, hashes and URLs)
- Saves results as structured YAML files, sorted by date and source
- Each file includes a timestamp, source domain, and top malware family name (if found).

---

## LLM Setup

This project assumes a locally hosted LLM compatible with the OpenAI chat completion format.

**Recommended model:**

- [`gemma-3-12b-it@q8_0`](https://huggingface.co/Triangle104/gemma-3-12b-it-Q8_0-GGUF)
- Served locally via [LM Studio](https://lmstudio.ai)

To change the endpoint or model, edit the `LLM_ENDPOINT` and `MODEL_NAME` variables in `ttp_extractor.py`.

---

## OCR Support for Image Text

Some vendors embed command-line samples or TTPs in screenshots. This tool includes OCR functionality via `pytesseract` to extract and append this content to the LLM input, ensuring no critical insight is missed.

---

## 🛠 Requirements

```bash
pip install -r requirements.txt
```

## 💬 Contributing
Pull requests are welcome for improvements, especially new URL sources, parser fixes or enhancements to the LLM prompt.

---

## ⚠️ Disclaimer

This **vibe-coded** project generates results via LLM which can be prone to make mistakes. While it produces highly useful results, because of this it is not designed for ingestion into automated pipelines or alerting systems.

Please **do not treat these YAMLs as canonical ground truth**. Always verify extracted data with the original publication. The LLM is helpful but it is not infallible.
