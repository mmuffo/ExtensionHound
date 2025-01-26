# ExtensionHound 🔍
![2025012701061-ezgif com-video-to-gif-converter](https://github.com/user-attachments/assets/c6ad484f-9c1a-40de-a669-882c245be6ee)

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
- 🔍 Scans Chrome profiles for extension network activity
- 📊 Provides detailed analysis of network connections
- 🌐 Optional VirusTotal integration for domain reputation checking
- 📁 Multiple output formats (Console, CSV, JSON)
- 🖥️ Cross-platform support (Windows, macOS, Linux)

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

Common flags:
- `--chrome-dir PATH`: Specify custom Chrome directory
- `--virustotal`: Enable VirusTotal domain checking
- `--output FORMAT`: Choose output format (csv/json)
- `--output-file PATH`: Specify output file path

## Usage Examples

Here are some practical examples of how to use ExtensionHound:

### Basic Security Audit
```bash
# Run a basic scan and save results to csv
python ExtensionHound.py --output csv --output-file audit_results.csv

# Run a basic scan with VirusTotal and save results to json
python ExtensionHound.py --vt --output json --output-file "audits/$(date +%Y-%m-%d)_security_report.json"
```

### Profile-Specific Analysis
```bash
# Analyze a specific Chrome profile
python ExtensionHound.py --chrome-dir "/path/to/Chrome User Data/Profile 1"

# Deep dive into the Default profile with reputation checks
python ExtensionHound.py --chrome-dir "/path/to/Chrome User Data/Default" --vt
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
