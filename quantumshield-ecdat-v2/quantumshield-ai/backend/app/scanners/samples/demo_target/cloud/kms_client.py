import boto3

def encrypt_payment_token(plaintext):
    client = boto3.client("kms")
    return client.encrypt(KeyId="alias/payments-key", Plaintext=plaintext)
