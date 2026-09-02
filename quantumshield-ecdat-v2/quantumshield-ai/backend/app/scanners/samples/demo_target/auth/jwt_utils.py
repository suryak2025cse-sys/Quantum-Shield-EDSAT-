import jwt

def verify_token(token, allow_insecure=False):
    # BUG: allows algorithm confusion / none-alg bypass
    algorithms = ["RS256"]
    if allow_insecure:
        algorithms = ["none"]
    return jwt.decode(token, options={"verify_signature": False}, algorithms=algorithms)

