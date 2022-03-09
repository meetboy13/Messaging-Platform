import cherrypy
import json
import base64
import urllib.request
import nacl.signing
import nacl.encoding
import time
import api
import socket
import threading
import sqlite3
from html.parser import HTMLParser


#set global variables
sta = "online"
event = threading.Event()

#Start of an html page
startHTML = """
<html>

    <head>
        <title>Antisocial Messaging</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/css/bootstrap.min.css">
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.0/jquery.min.js"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/js/bootstrap.min.js"></script> 
        <link rel='stylesheet' href='/static/style.css' />
    </head>
 
    <body>
        <nav class="navbar navbar-inverse navbar-fixed-top">
        <div class="container-fluid">
            <div class="navbar-header">
            <a class="navbar-brand" >CS302</a>
            </div>
        <ul class="nav navbar-nav">
            <li><a href="/">Home</a></li>
            <li><a href='/sendtoall'>Message everyone</a></li>
            <li><a href='/message'>Message the admin</a></li>
            <li><a href='/users'>Users</a></li>
            <li><a href='/pms'>PMs</a></li>
        </ul>
            <ul class="nav navbar-nav navbar-right">

        """

#logged in portion of the navbar
loggedinHTML = """   
    <ul class="nav navbar-nav navbar-right">
            <li class="dropdown">
            <a class="dropdown-toggle" data-toggle="dropdown">"""
        
loggedinHTML1 = """
        <span class="caret"></span></a>
        <ul class="dropdown-menu">
          <li><a href="status?status=online">Online</a></li>
          <li><a href="status?status=away" >Away</a></li>
          <li><a href="status?status=busy" >Busy</a></li>
        </ul>
      </li>
        <li><a href='/signout'><span class="glyphicon glyphicon-log-out"></span> Signout</a></li>
        </ul>
        </div>
        </nav>
        <br/><br/>"""

#signed out portion of the navbar
signedoutHTML = """
        <li class="nav-item"><a href="login"><span class="glyphicon glyphicon-log-in"></span> Login</a></li>
        </ul>
        </div>
        </nav>
        <br/><br/>"""

class MainApp(object):

	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       

	# If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "<div class='container'>I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = startHTML 
        #identify if user is logged in
        try:
            username = cherrypy.session['username']
            Page += loggedinHTML + username + loggedinHTML1
        except:
            Page += signedoutHTML
        #page header
        Page += """<div class="container"<br/>
                <div id="welcome-header">
                <div class="page-header text-center">
                <h1 id="timeline" class="countryname">Antisocial Messenger</h1>
                <h3>Welcome</h3>
                </div>
                </div>"""
        try:
            #check if you can connect to the login server
            api.pingServer()
            try:
                Page += "Hello " + cherrypy.session['username'] + "!<br/>"
                global sta
                Page += "You are currently " + sta + "<br/>"
            except KeyError: #There is no username
                Page += "You are not logged in<br/>"
        except:
            Page += "Cannot connect to login server."
        return Page
    
    #login page
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        #indicate that previous login attempt was wrong
        try:
            username = cherrypy.session['username']
            logged = 1
        except:
            logged = 0
        
        if logged is 1:
            raise cherrypy.HTTPRedirect('/')

        Page = startHTML
        Page += signedoutHTML + "<br/><br/><br/><div class='container'><br/> <br/> <br/> "
        Page += """<div id="welcome-header">
                <div class="page-header text-center">
                <h3>Login to do stuff</h3>
                </div>
                </div>"""

        if bad_attempt != 0:
            Page += """<font color='red'>Invalid username/password!</font>"""
        #login form
        Page += """  <form class="form-horizontal" action="/signin" method="post" enctype="multipart/form-data">
                <div class="form-group">
                <label class="control-label col-sm-2" for="username">Username:</label>
                <div class="col-sm-10">
                    <input type="username" class="form-control" id="username" placeholder="Enter username" name="username">
                </div>
                </div>
                <div class="form-group">
                <label class="control-label col-sm-2" for="password">Password:</label>
                <div class="col-sm-10">          
                    <input type="password" class="form-control" id="password" placeholder="Enter password" name="password">
                </div>
                </div>
                <div class="form-group">        
                <div class="col-sm-offset-2 col-sm-10">
                    <button type="submit" class="btn btn-default">Login</button>
                </div>
                </div>
            </form>
            </div>
            </body>
            </html>"""
        return Page
    
    #sets the status of the user
    @cherrypy.expose
    def status(self,status=None):
        try:
            global sta
            sta = status
            setStatus(cherrypy.session['header'],sta)
        except:
            raise cherrypy.HTTPRedirect('/')
        raise cherrypy.HTTPRedirect('/')

    #broadcast page that displays messages
    @cherrypy.expose
    def sendtoall(self, user = None):
        Page = startHTML 

        try:
            username = cherrypy.session['username']
            Page += """<ul class="nav navbar-nav navbar-right">
                <form class="navbar-form navbar-left" action="/sendtoall">
                <div class="form-group">
                    <input type="text" class="form-control" name ="user" placeholder="Search user">
                </div>
                <button type="submit" class="btn btn-default">Submit</button>
                </form>
                <li class="dropdown">
                <a class="dropdown-toggle" data-toggle="dropdown">"""
            Page += username +  loggedinHTML1

            Page += """
                <div class="container"<br/>
                <div id="welcome-header">
                <div class="page-header text-center">
                <h1 id="timeline" class="countryname">Messages</h1>
                <h3>Public Broadcast Messages</h3>
                </div>
                </div>
                <br/>"""
            Page += '<form action="/sendall" method="post" enctype="multipart/form-data">'
            Page += """<br/>
                <div class="form-group">
                <label for="message">Message to send to everyone:</label>
                <textarea class="form-control" rows="5" id="message" name="message"></textarea>
                </div> """
            Page += '<input type="submit" value="send"/></form><br/><br/><br/>'
            #get messages from the database
            conn = sqlite3.connect('static/public.db')
            c = conn.cursor()
            c.execute("SELECT message, username FROM messages ORDER BY id DESC LIMIT 0, 200")
            messages = c.fetchall()
            for i in messages:
                if user == None or i[1].find(user) > -1:
                    #hide meta messages
                    if i[0].find('!Meta') == -1:
                        Page += '<div class="panel panel-info"><div class="panel-heading">' + i[1] +  '</div><div class="panel-body">' + strip_tags(i[0]) + '</div></div>'
                    else:
                        continue
                else:
                    continue
        except KeyError: #There is no username
            raise cherrypy.HTTPRedirect('/login')
        return Page

    #look at private messages sent to the user
    @cherrypy.expose
    def pms(self):
        Page = startHTML 

        try:
            username = cherrypy.session['username']
            Page += loggedinHTML + username + loggedinHTML1

            Page += """
                <div class="container"<br/>
                <div id="welcome-header">
                <div class="page-header text-center">
                <h1 id="timeline" class="countryname">Private Messages to """
            Page += username +"</h1></div></div>"
            #get private messages from database
            conn = sqlite3.connect('static/private.db')
            c = conn.cursor()
            c.execute("SELECT encrypted_message, target_username, sent_user FROM primessages ORDER BY id DESC LIMIT 0, 50")
            messages = c.fetchall()
            for i in messages:
                try:
                    #attemp to decrypt and display message
                    plaintext = decryptPrivateMessage(i[0])
                    Page += '<div class="panel panel-info"><div class="panel-heading">' + i[2] + '</div><div class="panel-body">' + strip_tags(plaintext) + '</div></div>'
                except:
                    continue

        except KeyError: #There is no username
            raise cherrypy.HTTPRedirect('/login')
        return Page

    #Prompt for sending a private message to the login server
    @cherrypy.expose
    def message(self):
        Page = startHTML 

        try:
            username = cherrypy.session['username']
            Page += loggedinHTML + username + loggedinHTML1
            Page += """<div class="container"<br/>
                <div id="welcome-header">
                <div class="page-header text-center">
                <h1 id="timeline" class="countryname">Private message the admin</h1></div></div><br/>"""
            Page += '<form action="/send" method="post" enctype="multipart/form-data">'
            Page += """<br/>
                <div class="form-group">
                <label for="message">Message to send to the admin:</label>
                <textarea class="form-control" rows="5" id="message" name="message"></textarea>
                </div> """
            Page += '<input type="submit" value="send"/></form><br/><br/><br/>'
            """Page += '<input type="submit" value="send"/></form><br/><br/><br/>'
            Page += '<form action="/send" method="post" enctype="multipart/form-data">'
            Page += 'Message: <br/> <input type="text" name="message"/><br/>'
            Page += '<input type="submit" value="send"/></form>'"""
        except KeyError: #There is no username
            raise cherrypy.HTTPRedirect('/login')
        return Page

    #send the message to the login server
    @cherrypy.expose
    def send(self, message = None):
        try:
            username = cherrypy.session['username']
        except:
            raise cherrypy.HTTPRedirect('/login')
        #refresh page if there is no message
        if message is None or message is "":
            raise cherrypy.HTTPRedirect('/message')
        else:
            #send to the login server
            user = "admin"
            pubkey_hex_str = api.loginserver_pubkey(cherrypy.session['header'])
            api.rx_privatemessage(pubkey_hex_str,user,message,getPrivateKey(),cherrypy.session['header'],None)
        raise cherrypy.HTTPRedirect('/')

    #check the message being sent and send to every server
    @cherrypy.expose
    def sendall(self, message = None):
        try:
            username = cherrypy.session['username']
        except:
            raise cherrypy.HTTPRedirect('/login')
        #send a message to every server if a message exists
        if message is None or message is "":
            pass
        else:
            api.rx_broadcast(message,getPrivateKey(),cherrypy.session['header'])
        raise cherrypy.HTTPRedirect('/sendtoall')
        
    #list users and thier status
    @cherrypy.expose
    def users(self):
        Page = startHTML
        try:
            username = cherrypy.session['username']
            Page += loggedinHTML + username + loggedinHTML1
        except:
            raise cherrypy.HTTPRedirect('/login')
            
        try: 
            Page += """<div class="container"<br/>
                <div id="welcome-header">
                <div class="page-header text-center">
                <h1 id="timeline" class="countryname">Users</h1>
                </div>
                </div>"""
            listofusers = api.list_users(cherrypy.session['header'])
            for i in listofusers:
                Page += "<a href='messageuser?username=" + i['username'] + "&status=" + i['status'] + "&pubkey=" + i['incoming_pubkey'] + "&connectionaddress=" + i['connection_address'] + "'>"
                Page += i['username'] + " : " + i['status'] + "</a><br/>"
                
        except Exception as e:
            print(e)
            Page += "Connection interuptted<br/>"
        return Page

    #prompt for sending a private message to a user
    @cherrypy.expose
    def messageuser(self, username = None, status = None, pubkey = None, connectionaddress = None):
        Page = startHTML
        try:
            user = cherrypy.session['username']
            Page += loggedinHTML + user + loggedinHTML1
        except:
            raise cherrypy.HTTPRedirect("/")

        Page += '<div class="container"><form autocomplete="off" action="/privatemessage" method="post" enctype="multipart/form-data">'
        Page += '<input type = "hidden" name="username" value=' + username + '>'
        Page += '<input type = "hidden" name="status" value=' + status + '>'
        Page += '<input type = "hidden" name="pubkey" value=' + pubkey + '>'
        Page += '<input type = "hidden" name="connectionaddress" value=' + connectionaddress + '>'
        Page += 'Send a message to ' + username + '<br/> <input type="text" name="message"/><br/>'
        Page += '<input type="submit" value="send"/></form>'

        return Page

    #send private message
    @cherrypy.expose
    def privatemessage(self, username, status, pubkey, connectionaddress, message):
        try:
            user = cherrypy.session['username']
            if status != "offline":
                #send directly to target user's server
                api.rx_privatemessage(pubkey,username, message,getPrivateKey(),cherrypy.session["header"],connectionaddress)
            else:
                #send to everyone available
                api.offlineprivatemessage(pubkey,username,message, getPrivateKey(),cherrypy.session["header"] )
        except Exception as e:
            print(e)
            raise cherrypy.HTTPRedirect("/")
        
        raise cherrypy.HTTPRedirect("/")
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        try:
            #add api key header to session
            cherrypy.session['header'] = authoriseUserLogin(username, password)
            authorised = 1
        except Exception as e:
            print(e)
            authorised = 0
        try:
            if authorised is 1:
                error = authoriseUserKeys(username,cherrypy.session['header'])
                if error is 0:
                    #add username to session
                    cherrypy.session['username'] = username
                    backgroundStuff(cherrypy.session['header'])
                    raise cherrypy.HTTPRedirect('/')
                else:
                    cherrypy.lib.sessions.expire()
                    raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
            else:
                raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
        except:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            #ends thread
            event.set()
            t.join()
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')


###
### Functions only after here
###    

def authoriseUserLogin(username, password):
    """create HTTP BASIC authorization header and get api key for apikey header"""
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    #get api key and make header from it
    apikey = api.load_new_apikey(headers)
    
    APIKeyHeader = {
        'X-username': username,
        'X-apikey': apikey,
        'Content-Type' : 'application/json; charset=utf-8',
    }
    return APIKeyHeader

def authoriseUserKeys(username,headers):
    """perform key checks and generation when nessicary"""
    try:
        try:
            #load keys
            prikey = getPrivateKey()
            pubkey_hex = bytes(getPublicKey())
            pubkey_hex_str = pubkey_hex.decode('utf-8')
            message_bytes = bytes(pubkey_hex_str, encoding='utf-8')
            signed = prikey.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
            signature_hex_str = signed.signature.decode('utf-8')
            try:
                #ping key to server
                keycheck = api.pingkey(pubkey_hex_str,signature_hex_str, headers)
            except:
                return 1
        except:
            #when no key exists, make new keys and add it to the login server
            generateKeys()
            prikey = getPrivateKey()
            pubkey_hex = bytes(getPublicKey())
            pubkey_hex_str = pubkey_hex.decode('utf-8')
            message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
            signed = prikey.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
            signature_hex_str = signed.signature.decode('utf-8')
            try:
                api.add_pubkey(username,pubkey_hex_str,signature_hex_str,headers)
            except:
                return 1
        if keycheck != "ok": #when keys are not right, make new keys and add it to login server
            generateKeys()
            prikey = getPrivateKey()
            pubkey_hex = bytes(getPublicKey())
            pubkey_hex_str = pubkey_hex.decode('utf-8')
            message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
            signed = prikey.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
            signature_hex_str = signed.signature.decode('utf-8')
            api.add_pubkey(username,pubkey_hex_str,signature_hex_str,headers)
        #set status to online
        global sta
        sta = "online"
        setStatus(headers,"online")
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
        return 1

def getIP():
    """get the ip address"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    IPAddr = s.getsockname()[0]
    s.close()
    return IPAddr

def setStatus(headers,status):
    """sets users status by reporting to login server"""
    pubkey_hex = bytes(getPublicKey())
    pubkey_hex_str = pubkey_hex.decode('utf-8')
    IPAddr = getIP()    
    api.report(IPAddr + ":10001",0,pubkey_hex_str,status,headers)

def generateKeys():
    """Create and save private and public keys
    """
    # Generate a new random signing key
    private_key = nacl.signing.SigningKey.generate()
    # Obtain the verify key for a given signing key
    public_key = private_key.verify_key
    pubkey_hex = public_key.encode(encoder=nacl.encoding.HexEncoder)
    private_key_hex = private_key.encode(encoder=nacl.encoding.HexEncoder)
    with open("PrivateKey.txt",'wb') as file:
        file.write(private_key_hex)
    with open("PublicKey.txt",'wb') as file:
        file.write(pubkey_hex)
    return

def getPrivateKey():
    """retrive private key from file"""
    with open("PrivateKey.txt",'rb') as file:
        key = file.read()
    return nacl.signing.SigningKey(key, encoder=nacl.encoding.HexEncoder)

def getPublicKey():
    """retrieve public key from file"""
    with open("PublicKey.txt","rb") as file:
        key = file.read()
    return key

def decryptPrivateMessage(message):
    """attempt to decrypt private messages"""
    try:
        private_key = getPrivateKey()
        prikey= private_key.to_curve25519_private_key()
        unseal_box = nacl.public.SealedBox(prikey)
        plaintext = unseal_box.decrypt(message,encoder=nacl.encoding.HexEncoder).decode('utf-8')
        return plaintext
    except Exception as e:
        print(e)

def updatepublicdatabase(message, timestamp, username):
    """add broadcasts to database"""
    conn = sqlite3.connect('static/public.db')
    c = conn.cursor()
    messagedata = (message, timestamp, username)
    c.execute("INSERT INTO 'messages' (message, timestamp, username) VALUES (?,?,?)", messagedata)
    conn.commit()
    conn.close()

def updateprivatedatabase(time,tarpubkey,tarusername,senusername,encrypted_message):
    """add encrypted private messages to database"""
    conn = sqlite3.connect('static/private.db')
    c = conn.cursor()
    messagedata = (time,tarpubkey,tarusername,encrypted_message, senusername)
    c.execute("INSERT INTO 'primessages' (time,target_pubkey,target_username,encrypted_message, sent_user) VALUES (?,?,?,?,?)", messagedata)

    conn.commit()
    conn.close()

def report_user(headers):
    """thread to periodically report user"""
    global event
    while not event.wait(timeout=200):
        global sta
        setStatus(headers,sta)
    
def backgroundStuff(headers):
    """threads"""
    global t
    global event

    event.clear()
    t=threading.Thread(target=report_user, args=(headers,))
    t.daemon=True
    t.start()


class ApiApp(object):
    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def ping(self):
        """ping endpoint"""
        payload = {
            'response' : 'ok'
        }
        return json.dumps(payload).encode('utf-8')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_groupinviter(self):
        try:
            payload = {
                'response' : 'error',
                'message' : '/api/rx_groupinvite not implemented'
            }
        except Exception as e:
            payload = {
                'response' : 'error',
                'message' : e
            }
        return json.dumps(payload).encode('utf-8')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_groupmessage(self):
        try:
            payload = {
                'response' : 'error',
                'message' : '/api/rx_groupmessage not implemented'
            }
        except Exception as e:
            payload = {
                'response' : 'error',
                'message' : e
            }
        return json.dumps(payload).encode('utf-8')

	# If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def default(self, *args, **kwargs):
        payload = {
            "message": "Path not found.", 
            "response": "error", 
            "status": "404 Not Found"} 
        cherrypy.response.status = 404
        return json.dumps(payload).encode('utf-8')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def checkmessages(self):
        try:
            payload = {
                'response' : 'error',
                'message' : '/api/checkmessages not implemented'
            }
        except Exception as e:
            payload = {
                'response' : 'error',
                'message' : e
            }
        return json.dumps(payload).encode('utf-8')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_broadcast(self):
        """rx_broadcast endpoint, retrieves broadcasts sent to this server and stores to the database"""
        try:
            data = cherrypy.request.json
            message = data['message']
            login_record = data['loginserver_record']
            record = login_record.split(',')
            user = record[0]
            pubkey = record[1]
            time = record[2]
            updatepublicdatabase(message,time,user)
            payload = {
                'response' : 'ok'
            }
        except Exception as e:
            print(e)
            payload = {
                'response' : 'error',
                'message' : e
            }
        try:
            #because some error messages cannot be converted to JSON
            return json.dumps(payload).encode('utf-8')
        except:
            payload = {
                'response' : 'error',
                'message' : 'error, something went wrong'
            }
            return json.dumps(payload).encode('utf-8')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_privatemessage(self):
        """rx_privatemessage endpoint, takes encrypted private messsages that it recieves and stores it in the database"""
        data = cherrypy.request.json
        try:
            login_record = data['loginserver_record']
            pubkey = data['target_pubkey']
            username = data['target_username']
            record = login_record.split(',')
            user = record[0]
            #pubkey = record[1]
            time = record[2]
            encmessage = data['encrypted_message']
            payload = {
                'response' : 'ok'
            }
        except Exception as e:
            payload = {
                'response' : 'error',
                'message' : e
            }
        try:
            #because some error messages cannot be converted to JSON
            return json.dumps(payload).encode('utf-8')
        except:
            payload = {
                'response' : 'error',
                'message' : 'error message cannot be sent'
            }
            return json.dumps(payload).encode('utf-8')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def ping_check(self):
        """implement the ping_check endpoint for health checks, performs a pingcheck on the sender and generates response to return"""
        try:
            data = cherrypy.request.json
            connection_address = data['connection_address']
            connection_location = data['connection_location']
            IPAddr = getIP()    
            respo = api.ping_check(connection_address,connection_location,IPAddr + ":10001",0)
            currentTime = str(time.time())
            if (respo['response'] != 'error'):
                payload = {
                    'response' : 'ok',
                    'my_time' : currentTime
                }
            else:
                payload = {
                    'response' : 'error',
                    'my_time' : currentTime,
                    'message' : 'got an error in response'
                }
            return json.dumps(payload).encode('utf-8')
        except Exception as e:
            print(e)
            currentTime = str(time.time())
            payload = {
                'response' : 'error',
                'my_time' : currentTime,
                'message' : str(e)
            }
            return json.dumps(payload).encode('utf-8')

#used for stripping html tags
class MLStripper(HTMLParser):
    def __init__(self):
        self.reset()
        self.strict = False
        self.convert_charrefs= True
        self.fed = []
    def handle_data(self, d):
        self.fed.append(d)
    def get_data(self):
        return ''.join(self.fed)

def strip_tags(html):
    """strips html tags"""
    s = MLStripper()
    s.feed(html)
    return s.get_data()