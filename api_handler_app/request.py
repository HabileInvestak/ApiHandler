class RequestClass():
    
    '''This method is used to send a request to TSO server and get response'''
def send_request(body_content, url, authorization, user_id, tomcat_count, jKey, jData):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if isNotBlank(body_content):
            jsession_id = get_jsessionid(user_id)
            tomcat_count = get_tomcat_count(tomcat_count)
            if isNotBlank(jsession_id):
                url = url + "?jsessionid=" + jsession_id.strip()
            if isNotBlank(tomcat_count):
                url = url + "." + tomcat_count.strip()
            values = {'jKey': jKey,
                      'jData': jData}
            data = urllib.urlencode(values)
            req = urllib2.Request(url, data)
            response = urllib2.urlopen(req)
            the_page = response.read()
            d = json.loads(the_page)
            logger.info(readProperty("EXITING_METHOD"))  
            return d
        else:
            resp = requests.post(url)
            logger.info(readProperty("EXITING_METHOD"))  
            return resp.text
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))


'''This method is used to get cipher key'''
def get_cipher(key):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        cipher = PKCS1_v1_5.new(key)
    except Exception as e:
        raise e   
    logger.info(readProperty("EXITING_METHOD"))  
    return cipher


'''This method is used to encrypt  data block'''
def encrypt_block(key, data, start, end):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        data = data[start:end]
        cipher = get_cipher(key)
        encrypted_data = cipher.encrypt(data)
        encoded_data = b64_encode(encrypted_data)
        replace_data = replace_text(encoded_data, "\n", "")
    except Exception as e:
        raise e   
    logger.info(readProperty("EXITING_METHOD"))  
    return replace_data


'''This method is used to encrypt a data'''
def encrypt(data, key, key_size):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        buffer = ""
        number_of_bytes = ((int(readProperty ('KEY_SIZE')) / int(readProperty('BYTE_BOUNDARY'))) - int(readProperty('BYTE_DIFFERENCE')))
        start = 0
        end = number_of_bytes
        if (number_of_bytes > len(data)):
            end = len(data)
        buffer = buffer + encrypt_block(key, data, start, end)
        buffer = append_data(buffer, "\n")
        start = end
        end += number_of_bytes
        if (end > len(data)):
            end = len(data)
    
        while (end < len(data)):
            buffer = buffer + encrypt_block(key, data, start, end)
            buffer = append_data(buffer, "\n")
            start = end
            end += number_of_bytes
            if (end > len(data)):
                end = len(data)
        if (end - start > 0):
            buffer = buffer + encrypt_block(key, data, start, end)
            buffer = append_data(buffer, "\n")
        buffer = b64_encode(buffer)
        buffer = replace_text(buffer, "\n", "")
    except Exception as e:
        raise e   
    logger.info(readProperty("EXITING_METHOD"))  
    return buffer


'''This method is used to get decrypt data'''
def decrypt(data, private_key):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        data = b64_decode(data)
        data = unicode(data, "utf-8")
        data = data.strip().split("\n")
        final_data = ""
        for temp_data in data:
            temp_data = b64_decode(temp_data)
            cipher = get_cipher(private_key)
            temp_data = cipher.decrypt(temp_data, 'utf-8')
            final_data = append_data(final_data, temp_data)
    except Exception as e:
        raise e           
    logger.info(readProperty("EXITING_METHOD"))      
    return final_data


'''This method is used to get decode'''
def b64_decode(data):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        decoded_data = base64.b64decode(data)
    except Exception as e:
        raise e       
    logger.info(readProperty("EXITING_METHOD"))  
    return decoded_data


'''This method is used to get encode'''
def b64_encode(data):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        encoded_data = data.encode("base64")
    except Exception as e:
        raise e   
    logger.info(readProperty("EXITING_METHOD"))  
    return encoded_data


'''This method is used to generate key pair'''
def generate_key_pair():
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        random_generator = Random.new().read
        #print "Key size",readProperty('KEY_SIZE')
        key = RSA.generate(int(readProperty('KEY_SIZE')), random_generator)
    except Exception as e:
        raise e   
    logger.info(readProperty("EXITING_METHOD"))  
    return key


'''This method is used to get publicKey2'''
def get_public_key_pem(key):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        publicKey2_PEM = key.publickey().exportKey("PEM")
    except Exception as e:
        raise e   
    logger.info(readProperty("EXITING_METHOD"))  
    return publicKey2_PEM


'''This method is used to get privateKey2'''
def get_private_key_pem(key):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        privateKey2_PEM = key.exportKey()
    except Exception as e:
        raise e           
    logger.info(readProperty("EXITING_METHOD"))  
    return privateKey2_PEM


'''This method is used to get import_key'''
def import_key(key_pem):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        key = RSA.importKey(key_pem)
        # cipher = PKCS1_v1_5.new(key)
    except Exception as e:
        raise e   
    logger.info(readProperty("EXITING_METHOD"))  
    return key


'''This method is used to get jKey'''
def get_jkey(decoded_public_key):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        hash_object = hashlib.sha256(decoded_public_key)
        jKey = hash_object.hexdigest()
    except Exception as e:
        raise e   
    logger.info(readProperty("EXITING_METHOD"))  
    return jKey


'''This method is used to encode a userId'''
def get_jsessionid(user_id):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        jSessionId = b64_encode(user_id)
    except Exception as e:
        raise e   
    logger.info(readProperty("EXITING_METHOD"))  
    return jSessionId


def get_tomcat_count(tomcat_count):
    # tomcat_count=''
    return tomcat_count


'''This method is used to create error response'''
def errorResponse(errorList,stat):
    logger.info(readProperty("ENTERING_METHOD"))
    response_data = {}
    try:
        for error in errorList:
            response_data.setdefault(readProperty('ERROR_MSG'), [])
            response_data[readProperty('ERROR_MSG')].append(error)
            response_data[readProperty('STATUS')] = stat
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return response_data




'''This method will create error message using property file and place holder'''
def create_error_message(errorMessage,arrayValue):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        for index, item in enumerate (arrayValue):
            index = str(index)
            if type(item)==int:
                item = str (item)
            errorMessage = errorMessage.replace ('['+index+']',item)
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return  errorMessage


'''This method is used to create error response'''
def createErrorResponse(e):  
    logger.info(readProperty("ENTERING_METHOD"))  
    try:    
        stat = readProperty ("NOT_OK")
        errorList = []
        errorMsg = e
        errorList.append(errorMsg)
        response_data=errorResponse(errorList,stat)
    except Exception as e:
        raise e        
    logger.info(readProperty("EXITING_METHOD"))  
    return response_data