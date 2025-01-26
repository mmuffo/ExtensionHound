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
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get configuration from environment variables
VT_API_KEY = os.getenv('VT_API_KEY')
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
        url = f'https://www.virustotal.com/vtapi/v2/domain/report'
        params = {'apikey': VT_API_KEY, 'domain': domain}
        response = requests.get(url, params=params)
        last_vt_check = time.time()
        
        if response.status_code == 200:
            result = response.json()
            
            # Count clean vendors
            clean_vendors = 0
            total_vendors = 0
            
            for key in result:
                if key.endswith('_detected'):
                    vendor_name = key.replace('_detected', '')
                    if not result[key]:  # If vendor says it's clean
                        clean_vendors += 1
                    total_vendors += 1
            
            detected = total_vendors - clean_vendors if total_vendors > 0 else 0
            
            reputation = {
                'detections': detected,
                'total_vendors': total_vendors,
                'clean_vendors': clean_vendors
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

def parse_arguments():
    parser = argparse.ArgumentParser(
        description=get_help_text(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    
    parser.add_argument('--chrome-dir',
                      help='Path to Chrome User Data directory to analyze. If not specified, uses local Chrome directory.')
    
    parser.add_argument('--vt', 
                      action='store_true',
                      help='Enable VirusTotal reputation check for discovered domains')
    
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
        state_file = os.path.join(profile_path, 'Network Persistent State')
        
        if not os.path.exists(state_file):
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

def print_aggregated_view(all_connections, include_vt=False):
    if not all_connections:
        return
        
    print("\n" + "=" * 100)
    print("🔍 AGGREGATED EXTENSION ANALYSIS")
    print("=" * 100)
    
    # First, organize connections by extension
    extensions = {}
    for conn in all_connections:
        ext_id = conn['extension_id']
        domain = conn['domain']
        profile = conn['profile']
        
        if ext_id not in extensions:
            extensions[ext_id] = {
                'domains': set(),
                'profiles': set()
            }
        
        extensions[ext_id]['domains'].add(domain)
        extensions[ext_id]['profiles'].add(profile)
    
    if not extensions:
        print("\n❌ No extensions found with DNS activity.")
        return
        
    # Create and populate the table
    table = PrettyTable()
    table.field_names = ["Extension ID", "Domains", "Profiles"]
    table.align = "l"
    
    # Set specific column widths and styling
    table._max_width = {"Extension ID": 40, "Domains": 60, "Profiles": 25}
    table.border = True
    table.header_style = "upper"
    table.hrules = True  # Add horizontal lines between all rows
    
    # Add rows
    for ext_id, data in sorted(extensions.items()):
        # Put each domain on a new line
        domains_text = "\n".join(sorted(data['domains']))
        
        # Format profiles as comma-separated list
        profiles = ", ".join(sorted(data['profiles']))
        
        table.add_row([ext_id, domains_text, profiles])
    
    print(table)
    
    # Print detailed connections table
    print("\n" + "=" * 100)
    print("🔍 DETAILED NETWORK CONNECTIONS")
    print("=" * 100 + "\n")
    
    # Create detailed table
    detailed_table = PrettyTable()
    if include_vt:
        detailed_table.field_names = ["Profile", "Extension ID", "Domain", "Type", "Last Seen", "VT Status"]
    else:
        detailed_table.field_names = ["Profile", "Extension ID", "Domain", "Type", "Last Seen"]
    
    detailed_table.align = "l"
    detailed_table.border = True
    detailed_table.header_style = "upper"
    
    # Organize connections by profile and extension
    organized = {}
    for conn in all_connections:
        profile = conn['profile']
        ext_id = conn['extension_id']
        if profile not in organized:
            organized[profile] = {}
        if ext_id not in organized[profile]:
            organized[profile][ext_id] = []
        organized[profile][ext_id].append(conn)
    
    # Add rows to detailed table
    for profile in sorted(organized.keys()):
        for ext_id in sorted(organized[profile].keys()):
            connections = sorted(organized[profile][ext_id], 
                              key=lambda x: (x['domain'], x['timestamp'] if x['timestamp'] != 'No timestamp' else ''))
            
            for conn in connections:
                timestamp = format_timestamp(conn['timestamp'])
                
                row = [
                    os.path.basename(profile),  # Show only profile name, not full path
                    ext_id,
                    conn['domain'],
                    conn['type'],
                    timestamp
                ]
                
                if include_vt:
                    if conn.get('reputation'):
                        detections = f"{conn['reputation']['detections']}/{conn['reputation']['total_vendors']}"
                        if conn['reputation']['detections'] == 0:
                            detections = f"✅ {detections}"
                        elif conn['reputation']['detections'] < 3:
                            detections = f"⚠️  {detections}"
                        elif conn['reputation']['detections'] < 10:
                            detections = f"🚨 {detections}"
                        else:
                            detections = f"⛔ {detections}"
                    else:
                        detections = "No data"
                    row.append(detections)
                
                detailed_table.add_row(row)
            
            # Add separator between extensions
            separator = ["-" * 10] * (6 if include_vt else 5)
            detailed_table.add_row(separator)
    
    print(detailed_table)

def save_to_csv(connections, filename, include_vt=False):
    """Save connections to CSV file"""
    fieldnames = ['profile', 'extension_id', 'domain', 'type', 'timestamp']
    if include_vt:
        fieldnames.extend(['vt_detections', 'vt_total_vendors'])
        
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for conn in connections:
            row = {
                'profile': conn['profile'],
                'extension_id': conn['extension_id'],
                'domain': conn['domain'],
                'type': conn['type'],
                'timestamp': conn['timestamp']
            }
            if include_vt and 'reputation' in conn and conn['reputation']:
                row['vt_detections'] = conn['reputation']['detections']
                row['vt_total_vendors'] = conn['reputation']['total_vendors']
            writer.writerow(row)
    print(f"\n✅ Results saved to {filename}")

def save_to_json(connections, filename, include_vt=False):
    """Save connections to JSON file"""
    output_connections = []
    for conn in connections:
        connection_data = {
            'profile': conn['profile'],
            'extension_id': conn['extension_id'],
            'domain': conn['domain'],
            'type': conn['type'],
            'timestamp': conn['timestamp']
        }
        if include_vt and 'reputation' in conn and conn['reputation']:
            connection_data['reputation'] = conn['reputation']
        output_connections.append(connection_data)
        
    with open(filename, 'w') as f:
        json.dump(output_connections, f, indent=2)
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
    return """
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
🔍 Extension Hound | Version 1.0.0
🛡️  By Amram Englander
════════════════════════════════════════════════════"""

def print_initial_info(args):
    """Print initial program info without delays"""
    print("\n🔍 STARTING CHROME NETWORK STATE ANALYSIS")
    print("📊 Mode: " + ("Full Analysis with VirusTotal Reputation Check" if args.vt else "Basic Analysis"))
    if args.chrome_dir:
        print(f"📁 Chrome Directory: {args.chrome_dir}")
    print("=" * 100)

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
        profile_name = os.path.basename(profile_path)
        print_step(f"  📁 Scanning {profile_name}...", delay=0.2)
        connections = scan_profile(profile_path)
        all_connections.extend(connections)
        total_domains.update(conn['domain'] for conn in connections)
    
    if not total_domains:
        print_step("\n❌ No extension DNS activity found in the Chrome profiles.")
        print_step("\n✅ Analysis complete!")
        return
        
    print_step(f"✓ Found {len(total_domains)} unique domains")
    
    # VirusTotal scanning phase
    if args.vt:
        print_step("\nStep 3/4: 🔍 Starting VirusTotal reputation checks")
        est_time = (len(total_domains) * (60 / RATE_LIMIT_PER_MINUTE)) / 60
        print_step(f"⏱️  Estimated scan time: {int(est_time)} minutes and {int((est_time % 1) * 60)} seconds")
        print_step(f"⚡ Rate limit: {RATE_LIMIT_PER_MINUTE} requests per minute")
        
        # Process profile by profile
        organized = organize_connections(all_connections)
        for profile_idx, (profile, extensions) in enumerate(organized.items(), 1):
            print_step(f"\n  📁 Profile {profile_idx}/{len(organized)}: {profile}")
            
            for ext_id, connections in extensions.items():
                print_step(f"    📦 Extension: {ext_id}")
                domains = {conn['domain'] for conn in connections}
                
                for domain in sorted(domains):
                    if domain not in checked_domains:
                        reputation = check_domain_reputation(domain, indent="      ")
                        if reputation:
                            for conn in connections:
                                if conn['domain'] == domain:
                                    conn['reputation'] = reputation
    
    # Results phase
    print_step("\nStep 4/4: 📊 Generating analysis report")
    
    # Print summary with VT data if available
    print_aggregated_view(all_connections, include_vt=args.vt)
    
    # Save results if requested
    if args.output:
        print_step("\n💾 Saving results...")
        if not args.output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            args.output_file = f'chrome_extensions_analysis_{timestamp}.{args.output}'
        
        if args.output == 'csv':
            save_to_csv(all_connections, args.output_file, include_vt=args.vt)
        else:  # json
            save_to_json(all_connections, args.output_file, include_vt=args.vt)
    
    print_step("\n✅ Analysis complete!", delay=1)

if __name__ == "__main__":
    main()