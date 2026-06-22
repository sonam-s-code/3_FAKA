from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import json
import base64

def generate_key():
    return get_random_bytes(16)

def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC, iv=get_random_bytes(16))
    padded_data = pad(json.dumps({"data": data}).encode("utf-8"), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(cipher.iv + encrypted_data).decode("utf-8")

def decrypt(key, encrypted_data):
    encrypted_data = base64.b64decode(encrypted_data)
    cipher = AES.new(key, AES.MODE_CBC, iv=encrypted_data[:16])
    try:
        decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size).decode("utf-8")
    except:
        pass
        # print(encrypted_data)
    return json.loads(decrypted_data)["data"]

def bytes_to_int(byte_string):
    return int.from_bytes(byte_string, byteorder='big')

def int_to_bytes(num):
    # 計算需要多少位元組才能表示這個數字
    num_bytes = (num.bit_length() + 7) // 8
    # 使用 to_bytes() 方法將整數轉換成位元組序列
    return num.to_bytes(num_bytes, byteorder='big')
