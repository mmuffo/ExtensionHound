import os
import json
from datetime import datetime, timedelta
import platform

def get_chrome_path():
    if platform.system() == "Windows":
        return os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data')
    elif platform.system() == "Darwin":
        return os.path.expanduser('~/Library/Application Support/Google/Chrome')
    else:
        return os.path.expanduser('~/.config/google-chrome')

def convert_timestamp(timestamp):
    try:
        # Try using Unix epoch (1970-01-01) instead of Windows epoch
        unix_epoch = datetime(1970, 1, 1)
        
        # Convert timestamp to float and treat it as seconds since Unix epoch
        seconds = float(timestamp)
        
        # Calculate the final time
        result_time = unix_epoch + timedelta(seconds=seconds)
        
        return {
            'original': timestamp,
            'converted': result_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'year': result_time.year
        }
    except Exception as e:
        print(f"Error converting timestamp {timestamp}: {str(e)}")
        return {
            'original': timestamp,
            'converted': 'N/A',
            'year': 'N/A'
        }

def extract_timestamps(profile_path):
    timestamps = []
    network_state_path = os.path.join(profile_path, 'Network Persistent State')
    
    if not os.path.exists(network_state_path):
        print(f"No Network Persistent State file found in {profile_path}")
        return timestamps

    try:
        with open(network_state_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        if 'net' in data and 'http_server_properties' in data['net']:
            properties = data['net']['http_server_properties']
            
            # Extract timestamps from broken_alternative_services
            for broken in properties.get('broken_alternative_services', []):
                broken_until = broken.get('broken_until')
                if broken_until:
                    converted = convert_timestamp(broken_until)
                    timestamps.append({
                        'profile': os.path.basename(profile_path),
                        'host': broken.get('host', 'unknown'),
                        **converted
                    })
                    
    except Exception as e:
        print(f"Error processing {profile_path}: {str(e)}")
    
    return timestamps

def main():
    chrome_path = get_chrome_path()
    all_timestamps = []
    
    # Check default and numbered profiles
    profiles = ['Default']
    profiles.extend([f'Profile {i}' for i in range(1, 10)])
    
    for profile in profiles:
        profile_path = os.path.join(chrome_path, profile)
        if os.path.exists(profile_path):
            print(f"\nChecking profile: {profile}")
            profile_timestamps = extract_timestamps(profile_path)
            all_timestamps.extend(profile_timestamps)
    
    # Sort timestamps by year
    all_timestamps.sort(key=lambda x: str(x['year']))
    
    # Print results in a formatted way
    print("\nAll Timestamps Found:")
    print("-" * 80)
    print(f"{'Profile':<15} {'Host':<30} {'Original':<20} {'Converted':<25} {'Year'}")
    print("-" * 80)
    
    for ts in all_timestamps:
        print(f"{ts['profile']:<15} {ts['host'][:30]:<30} {str(ts['original']):<20} {ts['converted']:<25} {ts['year']}")

if __name__ == "__main__":
    main()
