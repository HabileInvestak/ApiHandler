from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

import requests
import json
import hashlib
import urllib
import urllib2
import base64
import xlrd

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from rest_example.wsgi import ReturnAllDict

AllList = []
ApiHomeDict = {}
InputDict = {}
SuccessDict = {}
FailureDict = {}
JsonDict = {}

e = ReturnAllDict()
AllList = e.returnDict()
ApiHomeDict = AllList[0]
InputDict = AllList[1]
SuccessDict = AllList[2]
FailureDict = AllList[3]
JsonDict = AllList[4]

base_url = "http://nestuat.tradesmartonline.in/NestHtml5Mobile/rest/"
global_user_id = "UTEST3"
private_key2_pem = ""
tomcat_count = ""
BYTE_BOUNDARY = 8
BYTE_DIFFERENCE = 11
KEY_SIZE = 2048


@api_view(["POST"])
def get_initial_token(request):
    if request.method == "POST":
        content = request.body
        url = base_url + "GetInitialKey"
        authorization = request.META.get('HTTP_AUTHORIZATION')
        user_id = ""
        tomcat_count = ""
        jKey = ""
        jData = ""
        output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
        d = json.loads(output)
        initial_public_key1 = d["publicKey"]
        tomcat_count = d["tomcatCount"]
        # print "public_key1=" + public_key1
        # print "tomcat_count=" + tomcat_count
        public_key1_pem = b64_decode(initial_public_key1)
        # print "publick_key1_pem=" + public_key1_pem+"="
        key_pair = generate_key_pair()
        public_key2_pem = get_public_key_pem(key_pair)
        # print "="+public_key2_pem+"="
        # print "publick_key2_pem="+ public_key2_pem+"="
        private_key2_pem = get_private_key_pem(key_pair)
        # print "private_key2_pem=" + private_key2_pem
        public_key1 = import_key(public_key1_pem)
        # print "Before encryption"
        jData = encrypt(public_key2_pem, public_key1, 2048)
        # print "After encryption"
        # print "jData=" + jData
        jKey = get_jkey(public_key1_pem)
        # print "jKey=" + jKey
        user_id = global_user_id
        jSessionId = get_jsessionid(user_id)
        # print "jSessionId=" + jSessionId
        # print "tomcat_count"+ tomcat_count
        url = base_url + "GetPreAuthenticationKey"
        # print "url=" + url
        content = 'Pre'
        output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
        initial_public_key3 = output['publicKey3']
        private_key2 = import_key(private_key2_pem)
        decrypted_public_key3 = decrypt(initial_public_key3, private_key2)
        print "=" + decrypted_public_key3 + "="
        #encoded_data = b64_encode(encrypted_data)
        # print "encoded=" + encoded_data
        #replace_data = replace_text(encoded_data, "\n", "")
        intial_token = replace_text(b64_encode(private_key2_pem),"\n","") + "-" \
                       + replace_text(b64_encode(decrypted_public_key3),"\n","") + "-" \
                       + replace_text(b64_encode(tomcat_count),"\n","")
        print intial_token
        #intial_token = intial_token.split("-")
        # for t_data in intial_token:
        #    print "i"
        #    print "="+b64_decode(t_data)+"="
        output = {'initial_token': intial_token}
        return Response(output)

@api_view(["POST"])
def get_login_2fa(request):
    if request.method == 'POST':
        content = request.body
        url = base_url+'Login2FA'
        authorization = request.META.get('HTTP_AUTHORIZATION')
        print "authorization"
        print authorization
        authorization=authorization.split("-")
        print authorization
        print "private key"
        print authorization[0]
        private_key2_pem=b64_decode(authorization[0].replace("\n",""))
        print private_key2_pem
        print "public key"
        print authorization[1]
        print authorization[1].replace("\n","")
        public_key3_pem = b64_decode(authorization[1].replace("\n",""))
        tomcat_count= b64_decode(authorization[2].replace("\n",""))
        print ApiHomeDict.get('Login2FA')[0].url
        print InputDict.get('Login2FA').get('uid')[0].description
        jKey = get_jkey(public_key3_pem)
        userJSON=content = request.body
        print "userJSON"+userJSON
        public_key3=import_key(public_key3_pem)
        jData = encrypt(userJSON,public_key3, 2048)
        tomcat_count=get_tomcat_count(tomcat_count)
        user_id=global_user_id
        output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
        return Response(output)

@api_view(["POST"])
def get_valid_pwd(request):
    print 'valid pwd'
    if request.method == 'POST':
        content = request.body
        url = base_url+'ValidPwd'
        authorization = request.META.get('HTTP_AUTHORIZATION')
        print "authorization"
        print authorization
        authorization=authorization.split("-")
        print authorization
        print "private key"
        print authorization[0]
        private_key2_pem=b64_decode(authorization[0].replace("\n",""))
        print private_key2_pem
        print "public key"
        print authorization[1]
        print authorization[1].replace("\n","")
        public_key3_pem = b64_decode(authorization[1].replace("\n",""))
        tomcat_count= b64_decode(authorization[2].replace("\n",""))
        jKey = get_jkey(public_key3_pem)
        userJSON=content = request.body
        jsonObject = json.loads(userJSON)
        data = {}
        for key in jsonObject:
            value = jsonObject[key]
            if key == "pwd":
                value=password_hash(value)

            print("The key and value are ({}) = ({})".format(key, value))
            data[key] = value
        json_data = json.dumps(data)
        print "userJSON123"+json_data
        public_key3=import_key(public_key3_pem)
        jData = encrypt(json_data,public_key3, 2048)
        tomcat_count=get_tomcat_count(tomcat_count)
        user_id=global_user_id
        output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
        return Response(output)


@api_view(["POST"])
def get_valid_ans(request):
    print 'valid pwd'
    if request.method == 'POST':
        content = request.body
        url = base_url+'ValidAns'
        authorization = request.META.get('HTTP_AUTHORIZATION')
        print "authorization"
        print authorization
        authorization=authorization.split("-")
        print authorization
        print "private key"
        print authorization[0]
        private_key2_pem=b64_decode(authorization[0].replace("\n",""))
        print private_key2_pem
        print "public key"
        print authorization[1]
        print authorization[1].replace("\n","")
        public_key3_pem = b64_decode(authorization[1].replace("\n",""))
        tomcat_count= b64_decode(authorization[2].replace("\n",""))
        jKey = get_jkey(public_key3_pem)
        userJSON=content = request.body
        jsonObject = json.loads(userJSON)
        data = {}
        for key in jsonObject:
            value = jsonObject[key]
            #if key == "pwd":
            #    value=password_hash(value)

            print("The key and value are ({}) = ({})".format(key, value))
            data[key] = value
        json_data = json.dumps(data)
        print "userJSON123"+json_data
        public_key3=import_key(public_key3_pem)
        jData = encrypt(json_data,public_key3, 2048)
        tomcat_count=get_tomcat_count(tomcat_count)
        user_id=global_user_id
        output = send_sequest(content, url, authorization, user_id, tomcat_count, jKey, jData)
        print output
        print "Before loading data"
        json_object_output=json.loads(output)
        print "After loading data"
        encrypted_data=json_object_output["jEncResp"]
        print "encrypted_data="+encrypted_data
       # private_key2 = import_key(private_key2_pem)
       # decrypted_data=decrypt(encrypted_data,private_key2)
       # return Response(decrypted_data)
        return Response(output)


def password_hash(password):
    for num in range(0, 999):
        password = hashlib.sha256(password).digest()
    password_hash = hashlib.sha256(password).hexdigest()
    return password_hash


def send_sequest(body_content, url, authorization, user_id, tomcat_count, jKey, jData):
    #print 'body_content=' + body_content
    if isNotBlank(body_content):
     #   print 'if body_content=' + body_content
        jsession_id = get_jsessionid(user_id)
      #  print "jsession_id=" + jsession_id
        tomcat_count = get_tomcat_count(tomcat_count)
      #  print "tomcat_count=" + tomcat_count
        if isNotBlank(jsession_id):
            url = url + "?jsessionid=" + jsession_id.strip()
        if isNotBlank(tomcat_count):
            url = url + "." + tomcat_count.strip()
       # print url
       # print jKey
       # print jData
       # print "Before values"
        values = {'jKey': jKey,
                  'jData': jData}
       # print "After values"
        data = urllib.urlencode(values)
       # print "1"
        req = urllib2.Request(url, data)
       # print "2"
        response = urllib2.urlopen(req)
       # print "3"
        the_page = response.read()
       # print "4"
        d = json.loads(the_page)
       # print "5"
        return d
    else:
       # print 'else'
        resp = requests.post(url)
        # if resp.status_code != 200:
        #    raise ApiError('GET /tasks/ {}'.format(resp.status_code))
        # print resp.text
        # d = json.loads(resp.text)
        return resp.text


def get_cipher(key):
    cipher = PKCS1_v1_5.new(key)
    return cipher


def encrypt_block(key, data, start, end):
    #print "Start encrypt block"
    data = data[start:end]
    #print "partial length=" + str(len(data))
    # print "block data="+data
    # print key
    cipher = get_cipher(key)
    # print cipher
    encrypted_data = cipher.encrypt(data)
    # print "encrypted_data="+encrypted_data
    encoded_data = b64_encode(encrypted_data)
    # print "encoded=" + encoded_data
    replace_data = replace_text(encoded_data, "\n", "")
    # print "Replace data=" + replace_data
    #print "End encrypt block"
    return replace_data


def encrypt(data, key, key_size):
    #print 'encrypt method'
    # print key_size
    # print BYTE_BOUNDARY
    buffer = ""
    number_of_bytes = ((key_size / BYTE_BOUNDARY) - 11)
    start = 0
    end = number_of_bytes
    if (number_of_bytes > len(data)):
        end = len(data)
    #print str(len(data))
    #print data + "=" + str(start) + "=" + str(end)
    buffer = buffer + encrypt_block(key, data, start, end)
    #print "Buffer=" + buffer
    buffer = append_data(buffer, "\n")
    #print "After append=" + buffer
    start = end
    end += number_of_bytes
    if (end > len(data)):
        end = len(data)

    while (end < len(data)):
     #   print "inside while"
        buffer = buffer + encrypt_block(key, data, start, end)
      #  print "While buffer=" + buffer
        buffer = append_data(buffer, "\n")
       # print "While buffer append=" + buffer
        start = end
        end += number_of_bytes
        if (end > len(data)):
            end = len(data)
    if (end - start > 0):
        #print 'while if'
        #print str(start) + "=" + str(end)
        buffer = buffer + encrypt_block(key, data, start, end)
        #print "While if buffer=" + buffer
        buffer = append_data(buffer, "\n")
        #print "While if append buffer=" + buffer

    #print "End while"
    #print "buffer=" + buffer
    buffer = b64_encode(buffer)
    # print "encrypted_data final"+encrypted_data
    buffer = replace_text(buffer, "\n", "")
    #print "Replace data final" + buffer
    #print "encrypt end"
    return buffer


def replace_text(orginal_data, old_text, new_text):
    orginal_data = orginal_data.replace(old_text, new_text)
    return orginal_data


def append_data(original_text, append_text):
    original_text = original_text + append_text
    return original_text


def decrypt(data, private_key):
    data = b64_decode(data)
    data = unicode(data, "utf-8")
    data = data.strip().split("\n")
    final_data = ""
    for temp_data in data:
        temp_data = b64_decode(temp_data)
        cipher = get_cipher(private_key)
        temp_data = cipher.decrypt(temp_data, 'utf-8')
        final_data = append_data(final_data, temp_data)
    return final_data


def b64_decode(data):
    decoded_data = base64.b64decode(data)
    return decoded_data


def b64_encode(data):
    encoded_data = data.encode("base64")
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


def import_key(key_pem):
    key = RSA.importKey(key_pem)
    # cipher = PKCS1_v1_5.new(key)
    return key


def get_jkey(decoded_public_key):
    hash_object = hashlib.sha256(decoded_public_key)
    jKey = hash_object.hexdigest()
    return jKey


def get_jsessionid(user_id):
    jSessionId = b64_encode(user_id)
    return jSessionId


def get_tomcat_count(tomcat_count):
    # tomcat_count=''
    return tomcat_count


def decrtpt_data():
    encrypted_data = ''
    return encrypted_data;


def data_type(data, datatype):
    return ''


def valid_values(data, valid_values):
    return ''


def optional(data, is_optional):
    return ''


def default(data, is_default):
    return ''


def transformation(data, transform_value):
    return ''


def isBlank(myString):
    if myString and myString.strip():
        # myString is not None AND myString is not empty or blank
        return False
    # myString is None OR myString is empty or blank
    return True


def isNotBlank(myString):
    if myString and myString.strip():
        # myString is not None AND myString is not empty or blank
        return True
    # myString is None OR myString is empty or blank
    return False
