# Generate pem file with public key
public-key:
	echo "-----BEGIN PUBLIC KEY-----\n$(PUBLIC_KEY)\n-----END PUBLIC KEY-----" > public_key.pem