#!/usr/bin/env python3
"""
Test script for LLM providers
Tests basic connectivity and response generation for each provider
"""

import sys
from llm_providers import create_provider


def test_provider(provider_type, **config):
    """Test a specific LLM provider"""
    print(f"\n{'='*60}")
    print(f"Testing {provider_type.upper()} Provider")
    print(f"{'='*60}")

    try:
        # Create provider
        provider = create_provider(provider_type, **config)
        print(f"✓ Provider initialized: {provider.get_provider_name()}")
        print(f"  Model: {provider.model_name}")
        if hasattr(provider, 'endpoint'):
            print(f"  Endpoint: {provider.endpoint}")

        # Simple test prompt
        system_prompt = "You are a helpful cybersecurity assistant."
        user_prompt = "What is a MITRE ATT&CK technique? Answer in one sentence."

        print(f"\nSending test prompt...")
        response = provider.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=0.2,
            max_tokens=100
        )

        print(f"\n✓ Response received:")
        print(f"  {response[:200]}{'...' if len(response) > 200 else ''}")
        print(f"\n✅ {provider_type.upper()} test PASSED")
        return True

    except Exception as e:
        print(f"\n❌ {provider_type.upper()} test FAILED: {e}")
        return False


def main():
    print("LLM Provider Test Suite")
    print("=" * 60)

    results = {}

    # Test LM Studio (if running)
    print("\n[1/5] Testing LM Studio...")
    print("Note: Requires LM Studio running on localhost:1234")
    results['lmstudio'] = test_provider('lmstudio')

    # Test Ollama (if running)
    print("\n[2/5] Testing Ollama...")
    print("Note: Requires Ollama running on localhost:11434")
    results['ollama'] = test_provider('ollama')

    # Test OpenAI (if API key set)
    print("\n[3/5] Testing OpenAI...")
    print("Note: Requires OPENAI_API_KEY environment variable")
    try:
        results['openai'] = test_provider('openai')
    except ValueError as e:
        print(f"⏩ Skipped: {e}")
        results['openai'] = None

    # Test Claude (if API key set)
    print("\n[4/5] Testing Claude...")
    print("Note: Requires ANTHROPIC_API_KEY environment variable")
    try:
        results['claude'] = test_provider('claude')
    except ValueError as e:
        print(f"⏩ Skipped: {e}")
        results['claude'] = None

    # Test Gemini (if API key set)
    print("\n[5/5] Testing Gemini...")
    print("Note: Requires GOOGLE_API_KEY environment variable")
    try:
        results['gemini'] = test_provider('gemini')
    except ValueError as e:
        print(f"⏩ Skipped: {e}")
        results['gemini'] = None

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for r in results.values() if r is True)
    failed = sum(1 for r in results.values() if r is False)
    skipped = sum(1 for r in results.values() if r is None)

    for provider, result in results.items():
        status = "✅ PASSED" if result is True else "❌ FAILED" if result is False else "⏩ SKIPPED"
        print(f"{provider.ljust(15)}: {status}")

    print(f"\nTotal: {passed} passed, {failed} failed, {skipped} skipped")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
