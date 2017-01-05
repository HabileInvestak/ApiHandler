from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
import requests
import json
import hashlib
import urllib
import urllib2
import base64
from rest_example.wsgi import ReturnAllDict
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5


AllList=[]
ApiHomeDict={}
InputDict={}
SuccessDict={}
FailureDict={}
JsonDict={}
e = ReturnAllDict()
AllList = e.returnDict()
ApiHomeDict=AllList[0]
InputDict=AllList[1]
SuccessDict=AllList[2]
FailureDict=AllList[3]
JsonDict=AllList[4]


base_url='http://nestuat.tradesmartonline.in/NestHtml5Mobile/rest/'
global_user_id='UTEST3'
private_key2_pem=''
tomcat_count=''
BYTE_BOUNDARY = 8
BYTE_DIFFERENCE = 11
KEY_SIZE = 2048

@api_view(['POST'])

def get_initial_token(request):
    if request.method == 'POST':
        content=request.body
        url=base_url+'GetInitialKey'
        authorization = request.META.get('HTTP_AUTHORIZATION')
        user_id=''
        tomcat_count=''
       # print 'Before'
        jKey=''
        jData=''
        output=send_sequest(content,url,authorization,user_id,tomcat_count,jKey,jData)
        d = json.loads(output)
        public_key1=d['publicKey']
        tomcat_count=d['tomcatCount']
        return Response(output)

def get_login_2fa(request):
    if request.method == 'POST':
        content = request.body
        url = base_url+'Login2FA'
        authorization = request.META.get('HTTP_AUTHORIZATION')
        #user_id = ''
        tomcat_count = ''
        # print 'Before'
        jKey = ''
        jData = ''
        user_id=global_user_id
        output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
        return Response(output)

def send_sequest(body_content,url,authorization,user_id,tomcat_count,jKey,jData):
    print 'body_content='+body_content
    if isNotBlank (body_content):
        print 'if body_content='+body_content
        jsession_id=get_jsessionid(user_id)
        print jsession_id
        tomcat_count = get_tomcat_count(tomcat_count)
        print tomcat_count
        if isNotBlank (jsession_id):
            url=url+"?jsessionid="+jsession_id
        if isNotBlank (tomcat_count):
            url=url+ "."+tomcat_count
            values = {'jKey': jKey,'jData': jData}
    else:
        print 'else'
        values = {}
    print "1"
    print "values="+values
    data = urllib.urlencode(values)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    the_page = response.read()
    d = json.loads(the_page)
    return d

def get_cipher(key):
    cipher = PKCS1_v1_5.new(key)
    return cipher

def encrypt_block(key,data,start,end):
    data=data[start:end]
    cipher=get_cipher(key)
    encrypted_data=cipher.encrypt(data)
    encrypted_data = b64_encode(encrypted_data)
    encrypted_data = replace_text(encrypted_data,'\n','')
    return encrypted_data

def encrypt(data,key,key_size):
    encrypted_data=''
    number_of_bytes = (key_size / BYTE_BOUNDARY) - 11
    start = 0
    end = number_of_bytes

    if number_of_bytes > len(data):
        end=len(data)
    encrypted_data=encrypted_data+encrypt_block(key, data, start, end)
    start = end
    end += number_of_bytes
    if (end > len(data)):
        end = len(data)

    while not end < len(data):
        encrypted_data = encrypted_data + encrypt_block(key, data, start, end)
        encrypted_data = append_data(encrypted_data,'\n')
        start = end
        end += number_of_bytes
        if (end > len(data)):
            end = len(data)
    if(end - start > 0):
        encrypted_data = encrypted_data + encrypt_block(key, data, start, end)
        encrypted_data = append_data(encrypted_data,'\n')

    encrypted_data = b64_encode(encrypted_data)
    encrypted_data =  replace_text(encrypted_data,'\n','')
    return encrypted_data

def replace_text(orginal_data,old_text,new_text):
    orginal_data=orginal_data.replace(old_text,new_text)
    return orginal_data

def append_data(original_text,append_text):
    original_text=original_text+append_text
    return original_text

def decrypt(data,key):
    decrypted_data=''
    return decrypted_data

def b64_decode(data):
    decoded_data=base64.b64decode(data)
    return decoded_data

def b64_encode(data):
    encoded_data=data.encode("base64")
    return encoded_data

def generate_key_pair():
    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator)
    return key

def get_public_key_pem(key):
    publicKey2_PEM = key.publickey().exportKey("PEM")
    return publicKey2_PEM

def get_private_key_pem(key):
    privateKey2_PEM = key.exportKey()
    return privateKey2_PEM

def impoty_key(key_pem):
    key = RSA.importKey(key_pem)
    cipher = PKCS1_v1_5.new(key)

def get_jkey(decoded_public_key):
    hash_object = hashlib.sha256(decoded_public_key)
    jKey = hash_object.hexdigest()
    return jKey;

def get_jsessionid(user_id):
    jSessionId=''
    return jSessionId

def get_tomcat_count(tomcat_count):
    #tomcat_count=''
    return tomcat_count

def encrypt_data():
    encrypted_data=''
    return encrypted_data;

def decrtpt_data():
    encrypted_data=''
    return encrypted_data;

def data_type(data,datatype):
    return ''

def valid_values(data,valid_values):
    return ''

def optional(data,is_optional):
    return ''

def default(data,is_default):
    return ''

def transformation(data,transform_value):
    return ''

def isBlank (myString):
    if myString and myString.strip():
        #myString is not None AND myString is not empty or blank
        return False
    #myString is None OR myString is empty or blank
    return True

def isNotBlank (myString):
    if myString and myString.strip():
        #myString is not None AND myString is not empty or blank
        return True
    #myString is None OR myString is empty or blank
    return False