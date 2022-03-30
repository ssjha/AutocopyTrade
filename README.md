# AutocopyTrade
Zerodha Kite trade replicator
The program allow the trades in one account to be replicated to mutliple accounts

# Getting started

Download the code in a new folder and install the requirements using
pip install -r requirements.txt

rename the file configTemplate.json to config.json. Populate the config.json with master and child accounts
To popualate the encrypted fields password and TOTPSecret, use the encryptpwd.py to generate encrypted values

D:\autocopytrade>python encryptpwd.py

run the program using the command below

D:\autocopytrade>python AutocopyTrade.py

To get the TOTP secret for zerodha, refer to the article
https://support.zerodha.com/category/your-zerodha-account/login-credentials/login-credentials-of-trading-platforms/articles/time-based-otp-setup

![image](https://user-images.githubusercontent.com/35311/160857289-b64fc532-f8cf-4e2e-a572-94e4f54fd18c.png)

click on "can't scan? copy the code" link to get the TOPT secret

reference
1. Kite api https://kite.trade/
2. Kite connect Python apis https://kite.trade/docs/pykiteconnect/v4/
