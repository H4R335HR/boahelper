#!/usr/bin/env python3
import requests
import re
import subprocess
import argparse
from urllib.parse import quote
import platform

# Constants
HOST = '192.168.1.1'
USERNAME = 'admin'
DEFAULT_PASSWORD = 'DEADBEEFCAFE'

# Function to calculate the checksum
def calculate_checksum(inputVal):
    # Initialize checksum variable
    csum = 0

    # Loop through inputVal characters and calculate checksum
    for i in range(0, len(inputVal), 4):
        # Calculate the ASCII value for each group of 4 characters
        char1 = ord(inputVal[i]) << 24 if i < len(inputVal) else 0
        char2 = ord(inputVal[i + 1]) << 16 if i + 1 < len(inputVal) else 0
        char3 = ord(inputVal[i + 2]) << 8 if i + 2 < len(inputVal) else 0
        char4 = ord(inputVal[i + 3]) if i + 3 < len(inputVal) else 0

        # Add the calculated values to csum
        csum += (char1 + char2 + char3 + char4)

    # Finalize the checksum
    csum = (csum & 0xffff) + (csum >> 16)
    csum = csum & 0xffff
    csum = (~csum) & 0xffff

    return csum

# Function to get BSSID based on OS
def get_bssid():
    if platform.system() == 'Windows':
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True, check=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if 'BSSID' in line:
                    return line.split('BSSID')[1].strip()
        except subprocess.CalledProcessError as e:
            print("Error:", e)
    elif platform.system() == 'Linux' or platform.system() == 'Darwin':
        try:
            result = subprocess.run(['iwconfig', 'wlan0'], capture_output=True, text=True, check=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Access Point' in line:
                    return line.split('Access Point: ')[1].split()[0]
        except subprocess.CalledProcessError as e:
            print("Error:", e)

# Function to parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description='Script to perform certain actions based on command-line arguments.')
    parser.add_argument('-u', '--username', help='Specify the username')
    parser.add_argument('-p', '--password', help='Specify the password')
    parser.add_argument('-H', '--host', help='Specify the host', default=HOST)
    return parser.parse_args()

# Parse command-line arguments
args = parse_arguments()

# Set default values
username = args.username if args.username else USERNAME
password = args.password if args.password else ''

# If password is not specified, use the BSSID method or default password
if not password:
    bssid = get_bssid()
    if bssid:
        password = bssid.replace(':', '').upper().strip()
    else:
        password = DEFAULT_PASSWORD

HOST = args.host

# Step 1: Fetch /admin/login.asp to get captcha value
response = requests.get(f'http://{HOST}/admin/login.asp')
if response.ok:
    html = response.text
    # Extract captcha value from the page HTML
    captchaMatch = re.search(r'code\s*=\s*"([^"]+)"', html)
    if captchaMatch:
        captchaValue = captchaMatch.group(1)
        print('Captcha code extracted successfully:', captchaValue)

        # Encode captcha value
        encodedCaptchaValue = quote(captchaValue, safe='')
        encodedCaptchaValue = encodedCaptchaValue.replace('!', '%21')

        # Step 2: Calculate postSecurityFlag value using the calculateChecksum function
        inputVal = f'challenge=&username={username}&password={password}&captchaTextBox={encodedCaptchaValue}&save=Login&submit-url=%2Fadmin%2Flogin.asp&'
        postSecurityFlag = calculate_checksum(inputVal)

        # Step 3: Construct POST request with necessary parameters
        formData = {
            'challenge': '',
            'username': username,
            'password': password,
            'captchaTextBox': captchaValue,
            'save': 'Login',
            'submit-url': '/admin/login.asp',
            'postSecurityFlag': postSecurityFlag
        }

        # Log the POST request being sent
        print('POST Request:', formData)

        # Step 4: Send POST request
        response = requests.post(f'http://{HOST}/boaform/admin/formLogin', data=formData)
        print('Status Code:', response.status_code)
        print('Status:', response.reason)
        # Check if the request was successful
        if response.status_code == 200:
            # Check if the response content contains an error message
            error_match = re.search(r'<h4>(.*?)</h4>', response.text)
            if error_match:
                error_message = error_match.group(1)
                print(f'{error_message}')
            else:
                print('Login attempt successful!')
        else:
            print('Error:', response.status_code)
    else:
        print('Captcha value not found on /admin/login.asp')
else:
    print('Error fetching /admin/login.asp:', response.status_code)
