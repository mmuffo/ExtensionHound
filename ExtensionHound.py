#!/usr/bin/env python3
"""
ExtensionHound - Chrome Extension Network Activity Analyzer
Version: 1.1.0

A forensic tool for analyzing Chrome extension DNS activity and network connections.
"""

import os
import json
import base64
import platform
import requests
import time
import argparse
import csv
from pathlib import Path
from prettytable import PrettyTable
from datetime import datetime, timedelta

try:
    from dotenv import load_dotenv
    # Load environment variables from .env file
    load_dotenv()
except ImportError:
    # If python-dotenv is not installed, continue without it
    pass

# Get configuration from environment variables
VT_API_KEY = os.getenv('VT_API_KEY')
SECUREANNEX_API_KEY = os.getenv('SECUREANNEX_API_KEY')
RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', '4'))

last_vt_check = time.time() - 60  # Initialize to allow first check immediately
checked_domains = {}  # Cache for domain reputation results

def get_chrome_path():
    """Get the default Chrome User Data directory path based on OS"""
    if platform.system() == "Windows":
        return os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data')
    elif platform.system() == "Darwin":
        return os.path.expanduser('~/Library/Application Support/Google/Chrome')
    else:
        return os.path.expanduser('~/.config/google-chrome')

def load_chrome_profiles(chrome_dir=None):
    """Load Chrome profiles from specified directory or default location"""
    try:
        # Use provided directory or get default
        chrome_path = chrome_dir if chrome_dir else get_chrome_path()
        
        if not os.path.exists(chrome_path):
            print(f"❌ Chrome directory not found: {chrome_path}")
            return []
            
        profiles = [os.path.join(chrome_path, item) for item in os.listdir(chrome_path) 
                   if item.startswith('Profile ') or item == 'Default']
        return profiles
    except Exception as e:
        print(f"❌ Error accessing Chrome profiles: {str(e)}")
        return []

def decode_anonymization(anon_str):
   try:
       decoded = base64.b64decode(anon_str).decode('utf-8')
       if 'chrome-extension://' in decoded:
           return decoded.split('chrome-extension://')[-1]
       return None
   except:
       return None

def convert_timestamp(timestamp):
    """Convert timestamp to readable format, return None if invalid"""
    try:
        # Check if timestamp is valid (not 0 or very old date)
        if not timestamp or int(timestamp) < 1577836800:  # Jan 1, 2020
            return None
        return datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception as e:
        return None

def check_domain_reputation(domain, indent=""):
    global last_vt_check, checked_domains
    
    # Return cached result if available
    if domain in checked_domains:
        rep = checked_domains[domain]
        detections = rep['detections']
        total = rep['total_vendors']
        if detections == 0:
            print(f"{indent}✅ {domain}: Clean (0/{total})")
        elif detections < 3:
            print(f"{indent}⚠️  {domain}: Low Risk ({detections}/{total})")
        elif detections < 10:
            print(f"{indent}🚨 {domain}: Medium Risk ({detections}/{total})")
        else:
            print(f"{indent}⛔ {domain}: High Risk ({detections}/{total})")
        return rep
    
    # Rate limiting
    current_time = time.time()
    time_since_last_check = current_time - last_vt_check
    if time_since_last_check < (60 / RATE_LIMIT_PER_MINUTE):
        wait_time = (60 / RATE_LIMIT_PER_MINUTE) - time_since_last_check
        print(f"{indent}⏳ Rate limit reached. Waiting {wait_time:.1f} seconds...")
        time.sleep(wait_time)
    
    try:
        url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        headers = {
            "accept": "application/json",
            "x-apikey": VT_API_KEY
        }
        response = requests.get(url, headers=headers)
        last_vt_check = time.time()
        
        if response.status_code == 200:
            result = response.json()
            
            if 'data' in result and 'attributes' in result['data']:
                attrs = result['data']['attributes']
                
                # Get last_analysis_stats which contains the detection summary
                stats = attrs.get('last_analysis_stats', {})
                
                detected = stats.get('malicious', 0) + stats.get('suspicious', 0)
                total_vendors = sum(stats.values()) if stats else 0
                
                reputation = {
                    'detections': detected,
                    'total_vendors': total_vendors,
                    'clean_vendors': total_vendors - detected
                }
                checked_domains[domain] = reputation
                
                # Print immediate result with status indicators
                if detected == 0:
                    print(f"{indent}✅ {domain}: Clean (0/{total_vendors})")
                elif detected < 3:
                    print(f"{indent}⚠️  {domain}: Low Risk ({detected}/{total_vendors})")
                elif detected < 10:
                    print(f"{indent}🚨 {domain}: Medium Risk ({detected}/{total_vendors})")
                else:
                    print(f"{indent}⛔ {domain}: High Risk ({detected}/{total_vendors})")
                
                return reputation
            else:
                print(f"{indent}❌ Unexpected API response format for {domain}")
        else:
            print(f"{indent}❌ Error checking reputation for {domain}: {response.status_code}")
    
    except Exception as e:
        print(f"{indent}❌ Error checking reputation for {domain}: {str(e)}")
    
    return None

def format_reputation(reputation):
    if not reputation:
        return "No data"
    detections = reputation['detections']
    total = reputation.get('total_vendors', 0)
    
    if detections == 0:
        return f"✅ Clean (0/{total})"
    elif detections < 3:
        return f"⚠️  Low Risk ({detections}/{total})"
    elif detections < 10:
        return f"🚨 Medium Risk ({detections}/{total})"
    else:
        return f"⛔ High Risk ({detections}/{total})"

def get_extension_details(extension_id):
    """Get extension details from Secure Annex API"""
    if not SECUREANNEX_API_KEY:
        print("\nError: SECUREANNEX_API_KEY not set")
        return None
        
    # Remove any null bytes from the extension ID
    extension_id = extension_id.replace('\x00', '')
        
    url = "https://api.secureannex.com/v0/extensions"
    headers = {'x-api-key': SECUREANNEX_API_KEY}
    params = {'extension_id': extension_id}
    
    try:
        # First try the extensions endpoint
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('result') and len(data['result']) > 0:
                return data['result'][0]
            
            # If no results, try direct URL format
            direct_url = f"{url}/{extension_id}"
            response = requests.get(direct_url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('result') and len(data['result']) > 0:
                    return data['result'][0]
                
    except Exception as e:
        print(f"\nError fetching extension details: {str(e)}")
    return None

def get_extension_signatures(extension_id):
    """Get Yara signatures from Secure Annex API for a specific extension"""
    if not SECUREANNEX_API_KEY:
        return None
        
    # Remove any null bytes from the extension ID
    extension_id = extension_id.replace('\x00', '')
        
    url = f"https://api.secureannex.com/v0/signatures"
    headers = {'x-api-key': SECUREANNEX_API_KEY}
    params = {'extension_id': extension_id}
    
    try:
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('result'):
                return data['result']
                
    except Exception as e:
        print(f"\nError fetching signatures: {str(e)}")
    return None

def parse_arguments():
    parser = argparse.ArgumentParser(
        description=get_help_text(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    
    parser.add_argument('--chrome-dir',
                      help='Path to Chrome User Data directory to analyze. If not specified, uses local Chrome directory.')
    
    parser.add_argument('--vt', 
                      action='store_true',
                      help='Enable VirusTotal reputation check for discovered domains')

    parser.add_argument('--secure-annex',
                      action='store_true',
                      help='Enable Secure Annex integration to show extension details')
    
    parser.add_argument('--output', 
                      choices=['csv', 'json'],
                      help='Save results to a file in CSV or JSON format')
    
    parser.add_argument('--output-file',
                      help='Custom filename for output. If not specified, will use: chrome_extensions_analysis_TIMESTAMP.[csv/json]')
    
    return parser.parse_args()

def print_step(message, delay=0.5):
    """Print a step with a delay"""
    print(message)
    time.sleep(delay)

def print_with_delay(message, delay=0.5):
    print(message)
    time.sleep(delay)

def analyze_network_state(profile_path):
    try:
        profile_name = os.path.basename(profile_path)
        # Network Persistent State file is in the Network subdirectory on both Windows and macOS
        state_file = os.path.join(profile_path, 'Network', 'Network Persistent State')
        
        if not os.path.exists(state_file):
            # Try alternate path (just in case)
            alt_state_file = os.path.join(profile_path, 'Network Persistent State')
            if os.path.exists(alt_state_file):
                state_file = alt_state_file
            else:
                return []
        
        connections = []
        with open(state_file, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                if 'net' in data and 'http_server_properties' in data['net']:
                    properties = data['net']['http_server_properties']
                    
                    # Process active connections
                    for server in properties.get('servers', []):
                        if server.get('anonymization') and len(server['anonymization']) > 0:
                            ext_id = decode_anonymization(server['anonymization'][0])
                            if ext_id:
                                domain = server['server'].replace('https://', '').split(':')[0]
                                timestamp = convert_timestamp(server.get('supports_spdy', 0))
                                connections.append({
                                    'profile': profile_name,
                                    'extension_id': ext_id,
                                    'domain': domain,
                                    'type': 'Active',
                                    'timestamp': timestamp if timestamp else 'No timestamp'
                                })
                    
                    # Process broken connections
                    for broken in properties.get('broken_alternative_services', []):
                        if broken.get('anonymization') and len(broken['anonymization']) > 0:
                            ext_id = decode_anonymization(broken['anonymization'][0])
                            if ext_id:
                                timestamp = convert_timestamp(broken.get('broken_until', 0))
                                connections.append({
                                    'profile': profile_name,
                                    'extension_id': ext_id,
                                    'domain': broken['host'],
                                    'type': 'Broken',
                                    'timestamp': timestamp if timestamp else 'No timestamp'
                                })
                
                return connections
            
            except json.JSONDecodeError:
                print(f"❌ Error parsing network state for profile {profile_name}")
                return []
                
    except Exception as e:
        print(f"❌ Error processing profile {profile_path}: {str(e)}")
        return []

def organize_connections(connections):
    """Organize connections by profile -> extension -> domains"""
    organized = {}
    for conn in connections:
        profile = conn['profile']
        ext_id = conn['extension_id']
        if profile not in organized:
            organized[profile] = {}
        if ext_id not in organized[profile]:
            organized[profile][ext_id] = []
        organized[profile][ext_id].append(conn)
    return organized

def format_timestamp(timestamp_str):
    """Format timestamp string to a readable format"""
    if timestamp_str == 'No timestamp' or timestamp_str == '-':
        return '-'
    try:
        # Convert epoch time to datetime
        timestamp = float(timestamp_str)
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return timestamp_str

def print_aggregated_view(all_connections, include_vt=False, include_secure_annex=False):
    if not all_connections:
        return
        
    print("=" * 100)
    print("🔍 AGGREGATED EXTENSION ANALYSIS")
    print("=" * 100)
    print()
    
    # First, organize connections by extension
    extensions = {}
    signatures_found = False  # Track if we found any signatures
    
    for conn in all_connections:
        ext_id = conn['extension_id']
        domain = conn['domain']
        profile = conn['profile']
        
        if ext_id not in extensions:
            extensions[ext_id] = {
                'domains': set(),
                'profiles': set(),
                'signatures': []  # Add signatures list
            }
            if include_secure_annex:
                ext_details = get_extension_details(ext_id)
                if ext_details:
                    extensions[ext_id]['name'] = ext_details.get('name', ext_details.get('owner', 'Not Found'))
                    extensions[ext_id]['users'] = f"{ext_details.get('users', 0):,}" if ext_details.get('users') else 'N/A'
                    extensions[ext_id]['rating'] = ext_details.get('rating', 'N/A')
                    
                    # Get signatures if we have extension details
                    signatures = get_extension_signatures(ext_id)
                    if signatures:
                        extensions[ext_id]['signatures'] = signatures
                        signatures_found = True
                else:
                    extensions[ext_id]['name'] = 'Not Found'
                    extensions[ext_id]['users'] = 'N/A'
                    extensions[ext_id]['rating'] = 'N/A'
        
        extensions[ext_id]['domains'].add(domain)
        extensions[ext_id]['profiles'].add(profile)
    
    if not extensions:
        print("\n❌ No extensions found with DNS activity.")
        return
        
    print("\n✓ Found {} unique extensions".format(len(extensions)))
    
    # Create and populate the extensions table
    table = PrettyTable()
    if include_secure_annex:
        table.field_names = ["Extension ID", "Name", "Users", "Rating", "Domains", "Profiles"]
        table._max_width = {"Extension ID": 40, "Name": 30, "Users": 12, "Rating": 8, "Domains": 60, "Profiles": 25}
    else:
        table.field_names = ["Extension ID", "Domains", "Profiles"]
        table._max_width = {"Extension ID": 40, "Domains": 60, "Profiles": 25}
    
    table.align = "l"
    table.border = True
    table.header_style = "upper"
    table.hrules = True
    
    # Add rows to extensions table
    for ext_id, data in sorted(extensions.items()):
        domains_text = "\n".join(sorted(data['domains']))
        profiles = ", ".join(sorted(data['profiles']))
        
        if include_secure_annex:
            row = [
                ext_id,
                data['name'],
                data['users'],
                data['rating'],
                domains_text,
                profiles
            ]
        else:
            row = [ext_id, domains_text, profiles]
            
        table.add_row(row)
    
    print(table)
    
    # Print Yara signatures table if we found any
    if signatures_found:
        print("\n" + "=" * 100)
        print("🔍 YARA SIGNATURE MATCHES")
        print("=" * 100)
        
        signatures_table = PrettyTable()
        signatures_table.field_names = ["Extension Name", "Extension ID", "Rule", "Severity", "File Path"]
        signatures_table._max_width = {
            "Extension Name": 30,
            "Extension ID": 40,
            "Rule": 30,
            "Severity": 10,
            "File Path": 40
        }
        signatures_table.align = "l"
        signatures_table.border = True
        signatures_table.header_style = "upper"
        signatures_table.hrules = True
        
        for ext_id, data in sorted(extensions.items()):
            if 'signatures' in data and data['signatures']:
                ext_name = data.get('name', 'Unknown')
                for sig in data['signatures']:
                    severity = sig.get('meta', {}).get('severity', 'unknown')
                    severity_icon = {
                        'high': '🔴',
                        'medium': '🟡',
                        'low': '🟢'
                    }.get(severity.lower(), '⚪')
                    
                    signatures_table.add_row([
                        ext_name,
                        ext_id,
                        sig.get('rule', 'Unknown'),
                        f"{severity_icon} {severity.title()}",
                        sig.get('file_path', 'Unknown')
                    ])
        
        print(signatures_table)
    
    # Print detailed connections table
    print("\n" + "=" * 100)
    print("🔍 DETAILED NETWORK CONNECTIONS")
    print("=" * 100)
    
    # Create detailed table
    detailed_table = PrettyTable()
    if include_vt:
        detailed_table.field_names = ["Profile", "Extension ID", "Domain", "Type", "Timestamp", "VT Status"]
    else:
        detailed_table.field_names = ["Profile", "Extension ID", "Domain", "Type", "Timestamp"]
    
    detailed_table.align = "l"
    detailed_table.border = True
    detailed_table.header_style = "upper"
    detailed_table.hrules = True
    
    # Group connections by extension for better readability
    for ext_id in sorted(extensions.keys()):
        ext_connections = [c for c in all_connections if c['extension_id'] == ext_id]
        
        for conn in sorted(ext_connections, key=lambda x: x['domain']):
            row = [
                conn['profile'],
                conn['extension_id'],
                conn['domain'],
                conn.get('type', 'Active'),
                conn.get('timestamp', 'No timestamp')
            ]
            
            if include_vt:
                if 'reputation' in conn:
                    rep = conn['reputation']
                    detections = rep['detections']
                    total = rep['total_vendors']
                    
                    # Add emoji based on severity
                    if detections == 0:
                        vt_status = f"✅ 0/{total}"
                    elif detections < 3:
                        vt_status = f"⚠️  {detections}/{total}"
                    elif detections < 10:
                        vt_status = f"🚨 {detections}/{total}"
                    else:
                        vt_status = f"⛔ {detections}/{total}"
                else:
                    vt_status = "No data"
                row.append(vt_status)
            
            detailed_table.add_row(row)
    
    print(detailed_table)

def clean_text(text):
    """Clean text by replacing Unicode characters with ASCII equivalents"""
    replacements = {
        '\u2013': '-',  # en-dash
        '\u2014': '-',  # em-dash
        '\u00ae': '(R)',  # registered trademark
        '\u2122': '(TM)',  # trademark
        '\u2019': "'",  # right single quotation mark
        '\u2018': "'",  # left single quotation mark
        '\u201c': '"',  # left double quotation mark
        '\u201d': '"',  # right double quotation mark
    }
    for unicode_char, ascii_char in replacements.items():
        text = text.replace(unicode_char, ascii_char)
    return text

def save_to_csv(connections, filename, include_vt=False, include_secure_annex=False):
    """Save connections to CSV file in an aggregated format by extension"""
    fieldnames = ['extension_id', 'name', 'users', 'rating', 'domains', 'profiles']
    
    # First, organize connections by extension
    extensions = {}
    for conn in connections:
        ext_id = conn['extension_id'].replace('\x00', '')  # Clean null bytes
        domain = conn['domain']
        profile = conn['profile']
        
        if ext_id not in extensions:
            extensions[ext_id] = {
                'domains': set(),
                'profiles': set(),
                'name': 'Not Found',
                'users': 'N/A',
                'rating': 'N/A'
            }
            if include_secure_annex:
                ext_details = get_extension_details(ext_id)
                if ext_details:
                    extensions[ext_id]['name'] = clean_text(ext_details.get('name', ext_details.get('owner', 'Not Found')))
                    extensions[ext_id]['users'] = ext_details.get('users', 'N/A')
                    extensions[ext_id]['rating'] = ext_details.get('rating', 'N/A')
        
        extensions[ext_id]['domains'].add(domain)
        extensions[ext_id]['profiles'].add(profile)
    
    # Write to CSV
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for ext_id, data in sorted(extensions.items()):
            row = {
                'extension_id': ext_id,
                'name': data['name'],
                'users': data['users'],
                'rating': data['rating'],
                'domains': '; '.join(sorted(data['domains'])),
                'profiles': ', '.join(sorted(data['profiles']))
            }
            writer.writerow(row)
    
    print(f"\n✅ Results saved to {filename}")

def save_to_json(connections, filename, include_vt=False, include_secure_annex=False):
    """Save connections to JSON file in an aggregated format by extension"""
    # First, organize connections by extension
    extensions = {}
    for conn in connections:
        ext_id = conn['extension_id'].replace('\x00', '')  # Clean null bytes
        domain = conn['domain']
        profile = conn['profile']
        
        if ext_id not in extensions:
            extensions[ext_id] = {
                'extension_id': ext_id,
                'domains': set(),
                'profiles': set(),
                'name': 'Not Found',
                'users': 'N/A',
                'rating': 'N/A'
            }
            if include_secure_annex:
                ext_details = get_extension_details(ext_id)
                if ext_details:
                    extensions[ext_id]['name'] = clean_text(ext_details.get('name', ext_details.get('owner', 'Not Found')))
                    extensions[ext_id]['users'] = ext_details.get('users', 'N/A')
                    extensions[ext_id]['rating'] = ext_details.get('rating', 'N/A')
        
        extensions[ext_id]['domains'].add(domain)
        extensions[ext_id]['profiles'].add(profile)
    
    # Convert sets to sorted lists for JSON serialization
    output_extensions = []
    for ext_id, data in sorted(extensions.items()):
        ext_data = {
            'extension_id': ext_id,
            'name': data['name'],
            'users': data['users'],
            'rating': data['rating'],
            'domains': sorted(data['domains']),
            'profiles': sorted(data['profiles'])
        }
        output_extensions.append(ext_data)
        
    with open(filename, 'w') as f:
        json.dump(output_extensions, f, indent=2)
    
    print(f"\n✅ Results saved to {filename}")

def get_chrome_profiles():
    chrome_path = get_chrome_path()
    try:
        profiles = [item for item in os.listdir(chrome_path) 
                   if item.startswith('Profile ') or item == 'Default']
        return profiles
    except Exception as e:
        print(f"❌ Error accessing Chrome profiles: {str(e)}")
        return []

def scan_profile(profile_path):
    return analyze_network_state(profile_path)

def print_banner():
    banner = '''
███████╗██╗  ██╗████████╗███████╗███╗   ██╗███████╗██╗ ██████╗ ███╗   ██╗
██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝████╗  ██║██╔════╝██║██╔═══██╗████╗  ██║
█████╗   ╚███╔╝    ██║   █████╗  ██╔██╗ ██║███████╗██║██║   ██║██╔██╗ ██║
██╔══╝   ██╔██╗    ██║   ██╔══╝  ██║╚██╗██║╚════██║██║██║   ██║██║╚██╗██║
███████╗██╔╝ ██╗   ██║   ███████╗██║ ╚████║███████║██║╚██████╔╝██║ ╚████║
╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ 
██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ 
════════════════════════════════════════════════════
🔍 Chrome Extension DNS Forensics
🛡️  By Amram Englander 
════════════════════════════════════════════════════'''
    return banner

def print_initial_info(args):
    """Print initial program info without delays"""
    print("\n🔍 STARTING CHROME NETWORK STATE ANALYSIS")
    modes = []
    if args.vt:
        modes.append("VirusTotal Reputation Check")
    if args.secure_annex:
        modes.append("Secure Annex Extension Details")
    print("📊 Mode: " + (" + ".join(modes) if modes else "Basic Analysis"))
    if args.chrome_dir:
        print(f"📁 Chrome Directory: {args.chrome_dir}")
    print("=" * 100)

def get_help_text():
    return f'''{print_banner()}

Description:
    Analyze Chrome browser's Network State to identify and track DNS queries made by extensions.
    Helps security teams investigate suspicious extension behavior.

Features:
    - Extract all domains contacted by extensions
    - Check domain reputation using VirusTotal (optional)
    - Track broken connections and their retry times
    - Export results to CSV or JSON format
    - Analyze local Chrome or a copied Chrome User Data directory

Usage Examples:
    Basic Analysis:
        %(prog)s
        
    Analysis with VirusTotal Check:
        %(prog)s --vt
        
    Analyze Custom Chrome Directory:
        %(prog)s --chrome-dir "/path/to/Chrome User Data"
        %(prog)s --chrome-dir "/path/to/Chrome User Data" --vt
        
    Save Results as CSV:
        %(prog)s --output csv
        %(prog)s --vt --output csv --output-file my_analysis.csv
        
    Save Results as JSON:
        %(prog)s --output json
        %(prog)s --vt --output json --output-file my_analysis.json

Note: When using --vt, make sure to set your VirusTotal API key in the .env file:
    VT_API_KEY=your_api_key_here
    RATE_LIMIT_PER_MINUTE=4  # Adjust based on your API quota
'''

def main():
    args = parse_arguments()
    
    # Print banner and initial info immediately
    print(print_banner())
    print_initial_info(args)
    
    # Now start the numbered steps with delays
    print_step("\nStep 1/4: 📂 Loading Chrome Profiles")
    profiles = load_chrome_profiles(args.chrome_dir)
    
    if not profiles:
        print_step("❌ No Chrome profiles found!")
        return
    
    print_step(f"✓ Found {len(profiles)} Chrome profiles")
    
    # Pre-scan phase
    print_step("\nStep 2/4: ⚡ Pre-scanning profiles for extension activity")
    all_connections = []
    total_domains = set()
    
    for profile_path in profiles:
        connections = scan_profile(profile_path)
        if connections:
            all_connections.extend(connections)
            for conn in connections:
                total_domains.add(conn['domain'])
    
    if not all_connections:
        print_step("❌ No extension network activity found!")
        return
        
    print_step(f"✓ Found {len(total_domains)} unique domains")
    
    # VT reputation check if enabled
    if args.vt:
        print_step("\nStep 3/4: 🛡️  Checking domain reputation")
        for domain in sorted(total_domains):
            reputation = check_domain_reputation(domain)
            # Store reputation data in all connections with this domain
            if reputation:
                for conn in all_connections:
                    if conn['domain'] == domain:
                        conn['reputation'] = reputation
    else:
        print_step("\nStep 3/4: 🛡️  Skipping domain reputation check (use --vt to enable)")
    
    print_step("\nStep 4/4: 📊 Generating analysis report")
    
    # Print summary with VT data if available
    print_aggregated_view(all_connections, include_vt=args.vt, include_secure_annex=args.secure_annex)
    
    # Save results if requested
    if args.output:
        print_step("\n💾 Saving results...")
        if not args.output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            args.output_file = f'chrome_extensions_analysis_{timestamp}.{args.output}'
        
        if args.output == 'csv':
            save_to_csv(all_connections, args.output_file, include_vt=args.vt, include_secure_annex=args.secure_annex)
        else:  # json
            save_to_json(all_connections, args.output_file, include_vt=args.vt, include_secure_annex=args.secure_annex)
    
    print_step("\n✅ Analysis complete!", delay=1)

if __name__ == "__main__":
    main()
