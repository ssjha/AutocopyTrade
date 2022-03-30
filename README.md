# AutocopyTrade
Zerodha Kite trade replicator
The program allow the trades in one account to be replicated to mutliple accounts

getting started

download the code in a new folder and install the requirements using
pip install -r requirements.txt

rename the file configTemplate.json to config.json. Populate the config.json with master and child accounts
To popualate the encrypted fields password and TOPTSecret, use the encryptpwd.py to generate encrypted values

D:\autocopytrade>python encryptpwd.py

run the program using the command below

D:\autocopytrade>python AutocopyTrade.py
