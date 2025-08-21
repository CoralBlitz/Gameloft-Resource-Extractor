# Gameloft Resource Extractor
A fast and user-friendly GUI tool to extract **resources** (MIDI, images, audio, texts, ZIP) from **Gameloft JAR games**.  
Supports XOR decryption, automatic detection of embedded files, and preview.

## Features

- Extracts from `.jar` files used in Gameloft mobile games
- Supports extraction of:
- MIDI music (`.mid`)
- Images (`.png`, `.jpg`, `.gif`, `.bmp`)
- Audio (`.mp3`, `.wav`, `.amr`)
- Text resources (`.txt`, `.xml`, `.json`, etc.)
- Embedded ZIP files
- XOR decryption with auto key detection
- Built-in audio player
- Preview for images and text
- Multi-threaded extraction for speed
- Detailed log output with throttled UI rendering
- uilt using [Flet](https://flet.dev) for modern cross-platform GUI

## How to Run

- git clone https://github.com/Coralblitz/gameloft-resource-extractor.git
- pip install -r requirements.txt
- python extractor.py
