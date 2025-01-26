# ExtensionHound 🔍

ExtensionHound is a powerful Python tool that analyzes network connections made by Chrome extensions. It helps users monitor and understand the network activity of their installed Chrome extensions, with optional VirusTotal integration for domain reputation checking.

## Features

- 🔍 Scans Chrome profiles for extension network activity
- 📊 Provides detailed analysis of network connections
- 🕒 Includes timestamp information for connections
- 🌐 Optional VirusTotal integration for domain reputation checking
- 📁 Multiple output formats (Console, CSV, JSON)
- 🖥️ Cross-platform support (Windows, macOS, Linux)

## Prerequisites

- Python 3.6 or higher
- Google Chrome browser
- VirusTotal API key (optional, for domain reputation checking)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/chrome-domain-extractor.git
cd chrome-domain-extractor
```

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

4. (Optional) Set up VirusTotal integration:
   - Create a `.env` file in the project root
   - Add your VirusTotal API key:
     ```
     VT_API_KEY=your_api_key_here
     RATE_LIMIT_PER_MINUTE=4
     ```

## Usage

Basic usage:
```bash
python extensionhound.py
```

Advanced options:
```bash
python extensionhound.py --help
```

Common flags:
- `--chrome-dir PATH`: Specify custom Chrome directory
- `--virustotal`: Enable VirusTotal domain checking
- `--output FORMAT`: Choose output format (csv/json)
- `--output-file PATH`: Specify output file path

## Example Output

The tool provides a detailed view of network connections:
```
Profile: Default
└── Extension: Extension Name
    ├── Domain: example.com
    │   └── Last accessed: 2023-01-01 12:00:00
    └── Domain: another-example.com
        └── Last accessed: 2023-01-01 12:05:00
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Thanks to VirusTotal for providing domain reputation services
- Built with Python and various open-source libraries

## Security Notes

- This tool only reads Chrome's existing network state files
- No active network monitoring or modification is performed
- API keys should be kept secure and never committed to version control
