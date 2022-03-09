import cherrypy
import json
import base64
import urllib.request
import nacl.signing
import nacl.encoding
import time

"""This file contain the functions relating to the apis from other servers
"""

def ping(headers):
    """Ping the server to authenticate the user"""
    payload = {
    }
    return request("ping",payload, headers)["authentication"]

def pingkey(pubkey, signature, headers):
    """Used to test key with the server"""
    payload = {
		"pubkey": pubkey,
        "signature": signature
    }
    return request("ping", payload, headers)["signature"]

def pingServer():
    """Returns and "ok" message. Used to check if the login server is online"""
    url = "http://cs302.kiwi.land/api/ping"
    req = urllib.request.Request(url)
    response = urllib.request.urlopen(req)
    data = response.read() # read the received bytes
    encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
    response.close()
    
def load_new_apikey(headers):
    """Returns a new API key for the purposes of authentication for the rest of this
    session."""
    return request("load_new_apikey",{},headers)["api_key"]

def loginserver_pubkey(headers):
    """Return the public key of the login server"""
    return request("loginserver_pubkey",{},headers)["pubkey"]

def list_users(headers):
    """Load the connection details for all active users who have done a
    report in the last five minutes to the login server"""
    return request("list_users",{},headers)['users']

def list_apis():
    payload = {
	}
    return payload

def add_pubkey(username,pubkey,signature,headers):
    """Associate a public key with your account
    signature: pubkey+username"""
    payload = {
        "username": username,
        "pubkey" : pubkey,
        "signature": signature
    }
    request("add_pubkey",payload,headers)

def report(connectionAddress,connectionLocation, pubkey, status, headers):
    """Inform the login server about connection information for a user on a
    client. """
    payload = {
		"connection_address" : connectionAddress,
		"connection_location": connectionLocation,
		"incoming_pubkey": pubkey,
		"status" : status
	}
    return request("report",payload, headers)
	
def get_loginserver_record(headers):
    """Load your current loginserver_record for use in creating
    point-to-point messages"""
    return request("get_loginserver_record",{},headers)["loginserver_record"]

def check_pubkey(pubkey,headers):
    """Load the loginserver_record for a given Ed25519 public key"""
    url = "check_pubkey?pubkey=" + pubkey
    return request(url,{},headers)['loginserver_record']

def add_privatedata(privatedata,privatekey,headers):
    """Save symmetrically encrypted private data
    signature : privatedata+loginserver_record+client_saved_at"""
    loginserver_record = get_loginserver_record(headers)
    currentTime = str(time.time())
    message_bytes = bytes(privatedata+loginserver_record+currentTime, encoding='utf-8')
    signed = privatekey.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')
    payload = {
        "privatedata":privatedata,
        "login_server_record":loginserver_record,
        "client_saved_at":currentTime,
        "signature":signature_hex_str
	}
    request("add_privatedata",payload,headers)

def get_privatedata(headers):
    """Load the saved symmetrically encrypted private data"""
    return request("get_privatedata",{},headers)

def rx_broadcast(message,privatekey,headers):
    """sends a broadcast to everyone"""
    loginserver_record = get_loginserver_record(headers)
    currentTime = str(time.time())
    message_bytes = bytes(loginserver_record+message+currentTime, encoding='utf-8')
    signed = privatekey.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')
    payload = {
        "loginserver_record":loginserver_record,
        "message": message,
        "sender_created_at" : currentTime,
        "signature": signature_hex_str
    }
    listofusers = list_users(headers)
    accepted_users=["mpat750" , "gwon383" , "ksae900" , "rgos933"]
    for i in listofusers:
        if i['username'] == 'admin':
            request("rx_broadcast",payload,headers)
        elif i['username'] in accepted_users:
            try:
                url = "http://" + i['connection_address'] + "/api/rx_broadcast"
                req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers = {"Content-Type": 'application/json; charset=utf-8'})
                response = urllib.request.urlopen(req)
                data = response.read() # read the received bytes
                encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
                response.close()
                JSON_object = json.loads(data.decode(encoding))
            except Exception as e:
                print(e)
                continue

def offlineprivatemessage(pubkey_hex,user,message,privatekey,headers):
    """Transmit a secret message between users who are offline
    signature : loginserver_record+target_pubkey+target_username+encrypted_message+sender_created_at"""
    try:
        loginserver_record = get_loginserver_record(headers)
        pubkey_hex_str = str(pubkey_hex)
        currentTime = str(time.time())
        verifykey = nacl.signing.VerifyKey(pubkey_hex, encoder=nacl.encoding.HexEncoder) 
        publickey = verifykey.to_curve25519_public_key() 
        sealed_box = nacl.public.SealedBox(publickey) 
        encrypted = sealed_box.encrypt(bytes(message,encoding='utf-8'), encoder=nacl.encoding.HexEncoder) 
        encrypted_message = encrypted.decode('utf-8')
        message_bytes = bytes(loginserver_record+pubkey_hex_str+user+encrypted_message+currentTime, encoding='utf-8')
        signed = privatekey.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')
    except Exception as e:
        print(e)
        return
        
    payload = {
        "loginserver_record": loginserver_record,
        "target_pubkey": pubkey_hex_str,
        "target_username": user,
        "encrypted_message": encrypted_message,
        "sender_created_at" : currentTime,   
        "signature" : signature_hex_str
    } 
    listofusers = list_users(headers)
    accepted_users=["mpat750" , "gwon383" , "ksae900" , "rgos933"]
    for i in listofusers:
        if i['username'] in accepted_users:
            try:
                url = "http://" + i['connection_address'] + "/api/rx_privatemessage"
                req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers = {"Content-Type": 'application/json; charset=utf-8'})
                response = urllib.request.urlopen(req)
                data = response.read() # read the received bytes
                encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
                response.close()
                JSON_object = json.loads(data.decode(encoding))
            except Exception as e:
                print(e)
                continue


def rx_privatemessage(pubkey_hex,user,message,privatekey,headers,address):
    """Transmit a secret message between users
    signature : loginserver_record+target_pubkey+target_username+encrypted_message+sender_created_at"""
    try:
        loginserver_record = get_loginserver_record(headers)
        pubkey_hex_str = str(pubkey_hex)
        currentTime = str(time.time())
        verifykey = nacl.signing.VerifyKey(pubkey_hex, encoder=nacl.encoding.HexEncoder) 
        publickey = verifykey.to_curve25519_public_key() 
        sealed_box = nacl.public.SealedBox(publickey) 
        encrypted = sealed_box.encrypt(bytes(message,encoding='utf-8'), encoder=nacl.encoding.HexEncoder) 
        encrypted_message = encrypted.decode('utf-8')
        message_bytes = bytes(loginserver_record+pubkey_hex_str+user+encrypted_message+currentTime, encoding='utf-8')
        signed = privatekey.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')
    except Exception as e:
        print(e)
        
    payload = {
        "loginserver_record": loginserver_record,
        "target_pubkey": pubkey_hex_str,
        "target_username": user,
        "encrypted_message": encrypted_message,
        "sender_created_at" : currentTime,   
        "signature" : signature_hex_str
    } 

    if user == "admin":
        request("rx_privatemessage",payload,headers)
    else:
        url = "http://" + address + "/api/rx_privatemessage"
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers = {"Content-Type": 'application/json; charset=utf-8'})
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
        JSON_object = json.loads(data.decode(encoding))

def ping_check(tarconnectionAddress, tarconnectionLocation,connectionAddress, connectionLocation):
    """Check if another client is active"""
    currentTime = str(time.time())
    payload = {
        'my_time' : currentTime,
		"connection_address" : connectionAddress,
		"connection_location": connectionLocation,
    }
    client_url = "http://" + tarconnectionAddress + "/api/ping_check"
    req = urllib.request.Request(client_url, data=json.dumps(payload).encode('utf-8'), headers = {"Content-Type": 'application/json; charset=utf-8'})
    response = urllib.request.urlopen(req)
    data = response.read() # read the received bytes
    encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
    response.close()
    JSON_object = json.loads(data.decode(encoding))
    return JSON_object


def request(url, payload, headers):
    """Performs the api request
    url : the loginservers url endpoint
    payload : the data that will get encoded and sent
    headers : used for authentication
    """
    try:
        url = "http://cs302.kiwi.land/api/" + url
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
        JSON_object = json.loads(data.decode(encoding))
        return JSON_object
    except Exception as e:
        print(e)