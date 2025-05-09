# TTP-Threat-Feeds
Threat feeds designed to extract adversarial TTPs and IOCs, using: ✨AI✨

The goal of this project is simply to automate the gathering of published threat actor TTPs and IOcs.

This mostly vibe coded project simply scours the internet based on trusted threat research publishers (urls.txt) and scrapes blog posts for recent publications. It then instructs the local LLM based on specific prompts to generate a YAML report of relevant details detection engineers and threat researchers might need in order to build detection rules.

Right now there is no automation around running and publishing these YAML reports, however I'll try to be regular about pushing updates. That being said, I highly recommend you clone the project locally, connect it to your own LLM and make tweaks and adjustments as needed.

One particular capability this script performs is the ability to extract text from images. Sometimes vendors will take screenshots of code such as command line, rather than pasting it in plain text. This script (mostly successfully) extracts text from images, and adds it to the appropriate YAML if relevant.

## Disclaimer:
Please do not bake these results into automated threat feeds. As these reports are generated via LLM, there could be mistakes and inaccuracies. Rather use it as a resource for quickly extracting, identifying and associating indicators as needed. Always fact check against the source.

## LLM Setup
Much of the setup details can be found in the ttp_extractor.py file, however I had great luck with the model "gemma-3-12b-it@q8_0" found here: https://huggingface.co/Triangle104/gemma-3-12b-it-Q8_0-GGUF. To serve the model I used LM Studio to host it locally.
