# Changelog

## [2.0.0] - Multi-Provider LLM Support

### 🚀 Major Features Added

#### Multi-Provider Architecture
- **New LLM Provider System**: Abstraction layer supporting multiple LLM backends
- **5 Supported Providers**:
  - **LM Studio** (local) - Default, OpenAI-compatible
  - **Ollama** (local) - Easy deployment and model management
  - **OpenAI** (cloud) - GPT-4o and other models
  - **Anthropic Claude** (cloud) - Claude 3.5 Sonnet and family
  - **Google Gemini** (cloud) - Gemini 2.0 Flash and Pro

#### Command-Line Interface
- **New CLI Arguments**:
  - `--lmstudio` - Use LM Studio (default)
  - `--ollama` - Use Ollama
  - `--openai` - Use OpenAI API
  - `--claude` - Use Anthropic Claude API
  - `--gemini` - Use Google Gemini API
  - `--model` - Specify model name
  - `--endpoint` - Custom API endpoint
  - `--api-key` - API key for cloud providers
  - `--help` - Show detailed usage information

### 📁 New Files

1. **`llm_providers.py`** - LLM provider abstraction layer
   - Base `LLMProvider` class
   - 5 provider implementations
   - Factory function for provider creation

2. **`test_providers.py`** - Test suite for all providers
   - Connectivity testing
   - Response validation
   - Automated testing script

3. **`PROVIDERS.md`** - Comprehensive provider documentation
   - Setup guides for each provider
   - Cost comparisons
   - Troubleshooting tips
   - Best practices

4. **`.env.example`** - Environment configuration template
   - API key setup examples
   - Configuration options

5. **`CHANGELOG.md`** - This file

### 🔧 Modified Files

1. **`ttp_extractor.py`**
   - Added argument parsing with `argparse`
   - Integrated provider abstraction
   - Removed hard-coded LLM configuration
   - Added `initialize_llm_provider()` function
   - Updated `ask_llm()` to use provider interface
   - Added `parse_args()` function

2. **`requirements.txt`**
   - Added comments for optional cloud provider SDKs
   - Maintained backward compatibility

3. **`README.md`**
   - Added Quick Start section
   - Added provider comparison table
   - Added usage examples for all providers
   - Added link to PROVIDERS.md
   - Updated setup instructions

### 🔄 Breaking Changes

**None** - Fully backward compatible!
- Running `python ttp_extractor.py` without arguments uses LM Studio (same as before)
- Default model and endpoint remain the same
- Existing configurations continue to work

### 🎯 Migration Guide

**From v1.x to v2.0:**

**No changes required!** The tool works exactly as before by default.

**To use new providers:**
```bash
# Ollama
python ttp_extractor.py --ollama

# OpenAI
export OPENAI_API_KEY="sk-..."
python ttp_extractor.py --openai

# Claude
export ANTHROPIC_API_KEY="sk-ant-..."
python ttp_extractor.py --claude

# Gemini
export GOOGLE_API_KEY="..."
python ttp_extractor.py --gemini
```

### 📊 Technical Details

**Architecture:**
- Clean abstraction using Abstract Base Class (ABC)
- Each provider implements `generate()` method
- Consistent interface across all providers
- Error handling and validation
- Provider-specific optimizations

**API Compatibility:**
- LM Studio: OpenAI-compatible `/v1/chat/completions`
- Ollama: Native `/api/chat` endpoint
- OpenAI: Official REST API v1
- Claude: Messages API (Anthropic)
- Gemini: GenerativeLanguage API v1beta

### 🧪 Testing

**Test Coverage:**
- Provider initialization
- Response generation
- Error handling
- API key validation
- Endpoint connectivity

**Run tests:**
```bash
python test_providers.py
```

### 📝 Documentation

**New Documentation:**
- [PROVIDERS.md](PROVIDERS.md) - Complete provider guide
- [.env.example](.env.example) - Configuration template
- Updated [README.md](README.md) - Quick start and examples

**Help Command:**
```bash
python ttp_extractor.py --help
```

### 🎓 Usage Examples

**Local Providers:**
```bash
# LM Studio (default)
python ttp_extractor.py

# Ollama with custom model
python ttp_extractor.py --ollama --model llama3.1:70b

# Custom endpoint
python ttp_extractor.py --lmstudio --endpoint http://192.168.1.100:1234/v1/chat/completions
```

**Cloud Providers:**
```bash
# OpenAI
export OPENAI_API_KEY="sk-..."
python ttp_extractor.py --openai --model gpt-4o-mini

# Claude
export ANTHROPIC_API_KEY="sk-ant-..."
python ttp_extractor.py --claude

# Gemini
export GOOGLE_API_KEY="..."
python ttp_extractor.py --gemini --model gemini-2.0-flash-exp
```

### 🔒 Security Notes

- API keys can be passed via environment variables (recommended)
- API keys can be passed via `--api-key` flag (less secure, visible in process list)
- Local providers (LM Studio, Ollama) keep data on-premises
- Cloud providers send data to third-party APIs

### 🚧 Known Limitations

1. Cloud providers require internet connectivity
2. API rate limits apply to cloud providers
3. Cloud providers have costs associated with usage
4. Local providers require sufficient GPU/CPU resources

### 🔮 Future Enhancements

Potential additions for future versions:
- Additional providers (Cohere, Mistral AI, etc.)
- Streaming response support
- Automatic provider fallback
- Batch processing optimizations
- Cost tracking and reporting
- Response caching layer

### 🙏 Credits

Original project maintained with LM Studio support.
Multi-provider support added to enable broader deployment options.

---

## [1.0.0] - Initial Release

- LM Studio support
- TTP and IOC extraction
- YAML output format
- OCR support for screenshots
- RSS feed parsing
- Threat intelligence blog scraping
