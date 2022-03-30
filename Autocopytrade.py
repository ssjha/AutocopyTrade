import time
import os
import traceback
import logging
import json
import dotenv
import sys
from urllib import parse
from kiteconnect import KiteTicker
from kiteconnect import  KiteConnect
from selenium import webdriver
from selenium.webdriver.common.by import By
import onetimepass as otp
from cryptography.fernet import Fernet

#set logger

logging.basicConfig(filename='logcopytrade.log',format='%(asctime)s-%(process)d-%(levelname)s-%(message)s',level=logging.DEBUG)

logging.info("Program Copytrader started")

sourceOrders={}
childaccts={}
orderlookup={}
kitemaster=None
configFile='config.json'
cwd = os.getcwd()
with open(configFile, 'r') as f:
    config = json.load(f)

dotenv.load()
if (dotenv.get('key')):
    mysecret = dotenv.get('key').encode()
    #print(mysecret)
else:
    print('Environment file not found. Exiting')
    sys.exit()

def getRequestToken(loginConfig):
    
    logging.info("Getting the request token for : {}".format(loginConfig['userid']))
    options = webdriver.ChromeOptions()
    options.headless = True
    driver = webdriver.Chrome('chromedriver',options=options)
    driver.delete_all_cookies()
#    driver.delete_cookie('kite.zerodha.com')
    driver.implicitly_wait(2)
    driver.get(loginConfig['loginURL'])
    driver.implicitly_wait(5)
    driver.find_element(by=By.ID,value='userid').send_keys(loginConfig['userid'])
    driver.find_element(by=By.ID,value='password').send_keys(deCryptPwd(loginConfig['password']))
    driver.find_element(by=By.XPATH,value='/html/body/div[1]/div/div[2]/div[1]/div/div/div[2]/form/div[4]/button').click()

    # Get and enter TOPT
    myToken = otp.get_totp(deCryptPwd(loginConfig['TOPTSecret']))
    driver.find_element(by=By.ID,value='totp').send_keys(myToken)
    driver.find_element(by=By.XPATH,value='/html/body/div[1]/div/div[2]/div[1]/div/div/div[2]/form/div[3]/button').click()
    time.sleep(5)
    url=driver.current_url
    requestToken = parse.parse_qs(parse.urlparse(url).query)['request_token'][0]
    driver.quit()
    logging.info("Successfully logged in for  : {}".format(loginConfig['userid']))
    print(loginConfig['userid'] + ' successfully logged in')
    return(requestToken)

def deCryptPwd(encodedPwd):
    f = Fernet(mysecret)
    enc =encodedPwd.encode()
    dec= f.decrypt(enc)
    return(dec.decode())

# Callback for tick reception.
def on_ticks(ws, ticks):
    if len(ticks) > 0:
        test=1
        #logging.info("Current mode: {}".format(ticks[0]["mode"]))

tokens = [260105] # dummy sensex token. Add tokens based 
# Callback for successful connection.
def on_connect(ws, response):
    logging.info("Successfully connected. Response: {}".format(response))
    ws.subscribe(tokens)
    ws.set_mode(ws.MODE_FULL, tokens)
    logging.info("Subscribe to tokens in Full mode: {}".format(tokens))

# Callback when current connection is closed.
def on_close(ws, code, reason):
    logging.info("Connection closed: {code} - {reason}".format(code=code, reason=reason))


# Callback when connection closed with error.
def on_error(ws, code, reason):
    logging.info("Connection error: {code} - {reason}".format(code=code, reason=reason))


# Callback when reconnect is on progress
def on_reconnect(ws, attempts_count):
    logging.info("Reconnecting: {}".format(attempts_count))


# Callback when all reconnect failed (exhausted max retries)
def on_noreconnect(ws):
    logging.info("Reconnect failed.")
    
def on_order_update(ws, data):
    logging.info("Order alert received : {}".format(data))
    copyTrade(data)
    
    
def copyTrade(data):
    logging.debug('starting copy trade')
    if data['status'] == 'CANCELLED':
        cancelTargetOrders(data)
    else:
        logging.debug('copy trade open and update')
        
        #ignore UPDATE messages as it is resulting in out of sequence order updates
        if (data['status'] == 'OPEN') or (data['status']=='TRIGGER PENDING'):
            if (data['order_id'] in sourceOrders):
                updateTargetOrders(data)
            else: 
                createTargetOrders(data)
    showMarginsAvailable()

# extract order parameters
# Validate if there is a change in order
# if new order create the target orders
# if update, update target orders 
# if cancelled, cancel target order


def getTargetOrder(orderid, userid):
    key = orderid + '|' + userid
    return orderlookup[key]
    
# store the child orders in lookup dictionary
def storeTargetOrder(parent_oid, userid,child_oid):
    key = parent_oid + '|' + userid
    orderlookup[key] = child_oid


def createTargetOrders(data):
    logging.info('inside create orders')
    for childacct in childaccts:
        accDetail = childaccts[childacct]
       # logging.info("Updated order {userid} - {cldorder}".format(userid=accDetail['userid'], cldorder=accDetail['multiplier']))
        createTargetOrder(data,accDetail['userid'], accDetail['kiteobj'], accDetail['multiplier'])
    
def createTargetOrder(orderdata, userid,targetAccnt,multiplier):
    logging.info('creating order{}'.format(orderdata['order_id']))

    try:
        order_id = targetAccnt.place_order(
            variety=orderdata['variety'],
            exchange=orderdata['exchange'],
            tradingsymbol=orderdata['tradingsymbol'],
            order_type=orderdata['order_type'],
            transaction_type=orderdata['transaction_type'],
            validity=orderdata['validity'],
            product=orderdata['product'],
            quantity=int(round(int(orderdata['quantity']) * float(multiplier),0)),
            price=orderdata['price'],
            trigger_price= orderdata['trigger_price']
        )
        sourceOrders[orderdata['order_id']] = orderdata
        storeTargetOrder(orderdata['order_id'], userid, order_id)
        logging.info("Created order {userid} - {cldorder}".format(userid=userid, cldorder=order_id))
    except Exception as e:
        stacktrace=traceback.format_exc()
        logging.error("***** ERROR Order create error {exception} - {stacktrace}".format(exception=e, stacktrace=stacktrace))
        print("Child order not created for parent order"+orderdata['order_id']+" for user id " + userid)
        
def showMarginsAvailable():
    print('-----------------Margins----------------------------')
    showMargin(kite=kitemaster,userid=masterconfig['userid'])
    for childacct in childaccts:
        accDetail = childaccts[childacct]
       # logging.info("Updated order {userid} - {cldorder}".format(userid=accDetail['userid'], cldorder=accDetail['multiplier']))
        showMargin(kite=accDetail['kiteobj'],userid=accDetail['userid'])
    print('----------------------------------------------------')

    

def showMargin(kite,userid):
    margin = kite.margins(segment="equity")
    logging.debug("Margin: {}".format(margin))
    print ("{0} : {1:12,.0f}  {2:12,.0f}  {3:12,.0f}".format(userid,margin['net'],margin['utilised']['debits'],margin['available']['live_balance']))
    #print(userid + " margin: {0:12,.0f} ".format(margin['net']))


def checkifupdate(orderdata):
    origorder = sourceOrders[orderdata['order_id']]
    if (origorder['variety']== orderdata['variety'] and
        origorder['order_type']== orderdata['order_type'] and 
        origorder['quantity']== orderdata['quantity'] and
        origorder['price']== orderdata['price'] and
        origorder['trigger_price']== orderdata['trigger_price'] ):
        
        return False
    else:
        return True

#Update target order for each child account after checking if the order parameters have changed. 
#Show error if the it is an old order that doesn't have any mapping
def updateTargetOrders(data):
    logging.info('inside update orders')
    try:
        if checkifupdate(data):
            for childacct in childaccts:
                accDetail = childaccts[childacct]
                updateTargetOrder(data,accDetail['userid'], accDetail['kiteobj'], accDetail['multiplier'])
                sourceOrders[data['order_id']] = data
            else:
                logging.info("Order id {} not changed. Not updated to child accounts".format(data['order_id']))
    except Exception as e:
        stacktrace=traceback.format_exc()
        logging.error("***** ERROR Order update error {exception} - {stacktrace}".format(exception=e, stacktrace=stacktrace))
        print("Order mapping not found " + data['order_id'])
        
def updateTargetOrder(orderdata, userid, targetAccnt,multiplier):
    logging.info('Updating order{}'.format(orderdata['order_id']))

    try:
        targetorder= getTargetOrder(orderdata['order_id'], userid)
        order_id = targetAccnt.modify_order(
                order_id = targetorder,
                variety=orderdata['variety'],
                order_type=orderdata['order_type'],
                validity=orderdata['validity'],
                quantity=int(round(int(orderdata['quantity'])* float(multiplier),0)),
                price=orderdata['price'],
                trigger_price= orderdata['trigger_price']
            )
        logging.info("Updated order {userid} - {cldorder}".format(userid=userid, cldorder=order_id))
    except Exception as e:
        stacktrace=traceback.format_exc()
        logging.error("***** ERROR Order update error {exception} - {stacktrace}".format(exception=e, stacktrace=stacktrace))
        print("Child order not updated for parent order"+orderdata['order_id']+" for user id " + userid)
        
        
def cancelTargetOrders(data):
    for childacct in childaccts:
        accDetail = childaccts[childacct]
        cancelTargetOrder(data,accDetail['userid'], accDetail['kiteobj'])
        
def cancelTargetOrder(orderdata,userid, targetAccnt): 
    logging.info('Cancelling order{}'.format(orderdata['order_id']))
    try:
        targetorder= getTargetOrder(orderdata['order_id'], userid)
        targetAccnt.cancel_order(variety = orderdata['variety'], order_id=targetorder)
    except Exception as e:
        stacktrace=traceback.format_exc()
        logging.error("Order cancel error {exception} - {stacktrace}".format(exception=e, stacktrace=stacktrace))
    
    logging.info("Cancelled order {userid} - {cldorder}".format(userid=userid, cldorder=targetorder))
    
# Master account login
masterconfig = config['MASTER']

logging.info('Logging into Master account')

try:
    kitemaster= KiteConnect (api_key=masterconfig['APIKey'])
    requestToken = getRequestToken(masterconfig)
    data = kitemaster.generate_session(request_token=requestToken, api_secret=masterconfig['APISecret'])
    kws = KiteTicker(masterconfig['APIKey'], data["access_token"])        
except Exception as e:
    stacktrace=traceback.format_exc()
    logging.error("Connection Error {exception} - {stacktrace}".format(exception=e, stacktrace=stacktrace))
    print("Connection error for master user id:",masterconfig['userid'],". Exiting program!!!")
    raise

# Assign the callbacks.
kws.on_ticks = on_ticks
kws.on_close = on_close
kws.on_error = on_error
kws.on_connect = on_connect
kws.on_reconnect = on_reconnect
kws.on_noreconnect = on_noreconnect
kws.on_order_update = on_order_update

logging.info('Logging into target accounts')

for childacct in config['CHILD']:
    child = {}
    childconfig = config['CHILD'][childacct]
    if ( childconfig['enabled'] == 'Y'):
        child['userid']= childconfig['userid']
        child['api_key']= childconfig['APIKey']
        child['api_secret'] = childconfig['APISecret'] 
        child['multiplier'] = childconfig['multiplier']
        child['request_token'] =    getRequestToken(childconfig)
        try:
            kite= KiteConnect (api_key=child['api_key'])
            data = kite.generate_session(request_token=child['request_token'], api_secret=child['api_secret'])
            kite.set_access_token(data["access_token"])
        
        except Exception as e:
            stacktrace=traceback.format_exc()
            logging.error("Connection Error {exception} - {stacktrace}".format(exception=e, stacktrace=stacktrace))
            print("Connection error for user id: ",child['userid'],". Exiting program!!!")
            raise
        child['access_token']  = data["access_token"]
        child['kiteobj']  = kite
        logging.info("Kite session created: {}".format(data))
        childaccts[child['userid']]=child

showMarginsAvailable()
#Connect for subscribing to order updates in master account
kws.connect()