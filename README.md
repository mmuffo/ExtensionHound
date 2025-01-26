 [═══════════════════════ 🔍 EXTENTION HOUND 🔍 ═══════════════════════]

# ExtensionHound 🔍

## The Challenge: Chrome Extension DNS Forensics

As a security investigator, you've encountered a common frustration: Chrome extensions making suspicious DNS requests, but they're nearly impossible to trace back to their source. Why? Because all DNS requests appear to come from the chrome.exe process, making it extremely difficult to determine which extension is responsible for what network activity.

Traditional network monitoring tools show:
```
Process: chrome.exe
DNS Query: suspicious-domain.com
```
But which extension made that request? The trail goes cold... until now.

ExtensionHound is purpose-built to solve this forensic challenge by:
1. Analyzing Chrome's internal network state
2. Correlating DNS requests with specific extensions
3. Revealing the hidden connections between extensions and their network activities

## What ExtensionHound Does

ExtensionHound is a powerful forensic tool that breaks through the chrome.exe attribution barrier, allowing you to:
- 🔍 Map DNS requests back to their originating extensions
- 📊 Track historical network connections per extension
- 🕒 Provide temporal analysis of extension activities
- 🌐 Integrate with VirusTotal for reputation checking
- 📁 Export findings in multiple formats (Console, CSV, JSON)
- 🖥️ Work across all major platforms (Windows, macOS, Linux)

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
git clone https://github.com/yourusername/extension-hound.git
cd extension-hound
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

## Usage Examples

Here are some practical examples of how to use ExtensionHound:

### Basic Security Audit
```bash
# Run a basic scan with VirusTotal check and save results
python ExtensionHound.py --vt --output csv --output-file audit_results.csv

# Generate a dated security report
python ExtensionHound.py --vt --output json --output-file "audits/$(date +%Y-%m-%d)_security_report.json"
```

### Profile-Specific Analysis
```bash
# Analyze a specific Chrome profile
python ExtensionHound.py --chrome-dir "/path/to/Chrome User Data/Profile 1"

# Deep dive into the Default profile with reputation checks
python ExtensionHound.py --chrome-dir "/path/to/Chrome User Data/Default" --vt
```

### Continuous Monitoring
```bash
# Create an hourly monitoring script
while true; do
    python ExtensionHound.py --vt --output json --output-file "logs/$(date +%Y-%m-%d_%H).json"
    sleep 3600
done

# Monitor and alert on suspicious domains
python ExtensionHound.py --vt | grep "Malicious" | notify-send "Suspicious Extension Activity"
```

## How It Works

ExtensionHound dives deep into Chrome's internal network state, accessing the data that traditional network monitoring tools can't see. It correlates DNS requests with extension activities by:
1. Analyzing Chrome's internal network state files
2. Mapping network sockets to extension IDs
3. Building a comprehensive timeline of extension network activities
4. Providing clear, actionable intelligence about extension behaviors

This gives investigators the missing link between network activity and the extensions responsible for it.

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
