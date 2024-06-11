# # users/crypto_utils.py

# # from Crypto.Cipher import DES, AES, PKCS1_OAEP
# # from Crypto.PublicKey import RSA, ElGamal
# # from Crypto.Hash import MD5, SHA1, SHA256, HMAC
# # from Crypto import Random

# # DES encryption and decryption
# def des_encrypt(data, key):
#     cipher = DES.new(key.ljust(8)[:8], DES.MODE_ECB)
#     padded_data = data.ljust(8 * ((len(data) + 7) // 8))
#     encrypted_data = cipher.encrypt(padded_data.encode('utf-8'))
#     return encrypted_data

# def des_decrypt(data, key):
#     cipher = DES.new(key.ljust(8)[:8], DES.MODE_ECB)
#     decrypted_data = cipher.decrypt(data)
#     return decrypted_data.rstrip().decode('utf-8')

# # AES encryption and decryption
# def aes_encrypt(data, key):
#     cipher = AES.new(key.ljust(32)[:32], AES.MODE_ECB)
#     padded_data = data.ljust(16 * ((len(data) + 15) // 16))
#     encrypted_data = cipher.encrypt(padded_data.encode('utf-8'))
#     return encrypted_data

# def aes_decrypt(data, key):
#     cipher = AES.new(key.ljust(32)[:32], AES.MODE_ECB)
#     decrypted_data = cipher.decrypt(data)
#     return decrypted_data.rstrip().decode('utf-8')

# # RSA encryption and decryption
# def rsa_encrypt(data, public_key):
#     cipher = PKCS1_OAEP.new(public_key)
#     encrypted_data = cipher.encrypt(data.encode('utf-8'))
#     return encrypted_data

# def rsa_decrypt(data, private_key):
#     cipher = PKCS1_OAEP.new(private_key)
#     decrypted_data = cipher.decrypt(data)
#     return decrypted_data.decode('utf-8')

# # ElGamal encryption and decryption (simplified for illustration purposes)
# def elgamal_encrypt(data, public_key):
#     k = Random.new().read(public_key.size() // 8)
#     encrypted_data = public_key.encrypt(data.encode('utf-8'), k)
#     return encrypted_data

# def elgamal_decrypt(data, private_key):
#     decrypted_data = private_key.decrypt(data)
#     return decrypted_data.decode('utf-8')

# # Hashing functions
# def generate_md5(data):
#     h = MD5.new()
#     h.update(data.encode('utf-8'))
#     return h.hexdigest()

# def generate_sha1(data):
#     h = SHA1.new()
#     h.update(data.encode('utf-8'))
#     return h.hexdigest()

# def generate_sha256(data):
#     h = SHA256.new()
#     h.update(data.encode('utf-8'))
#     return h.hexdigest()

# # HMAC generation
# def generate_hmac(key, data):
#     h = HMAC.new(key.encode('utf-8'), digestmod=SHA256)
#     h.update(data.encode('utf-8'))
#     return h.hexdigest()
