import logging

import requests
import json
import hashlib
import urllib
import urllib2
import base64

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5


from utils import UtilClass

logger = logging.getLogger('api_handler_app.request.py')
class RequestClass():

    
    '''This method is used to generate key pair'''
    def generate_key_pair(self):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            random_generator = Random.new().read
            #print "Key size",readProperty('KEY_SIZE')
            key = RSA.generate(int(utilClass.readProperty('KEY_SIZE')), random_generator)
        except Exception as e:
            raise e   
        #logger.info(utilClass.readProperty("EXITING_METHOD"))  
        return key


    '''This method is used to get publicKey2'''
    def get_public_key_pem(self,key):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            publicKey2_PEM = key.publickey().exportKey("PEM")
        except Exception as e:
            raise e   
        #logger.info(utilClass.readProperty("EXITING_METHOD"))  
        return publicKey2_PEM
    
    
    '''This method is used to get privateKey2'''
    def get_private_key_pem(self,key):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            privateKey2_PEM = key.exportKey()
        except Exception as e:
            raise e           
        #logger.info(utilClass.readProperty("EXITING_METHOD"))  
        return privateKey2_PEM
    
    
    '''This method is used to get import_key'''
    def import_key(self,key_pem):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            key = RSA.importKey(key_pem)
            # cipher = PKCS1_v1_5.new(key)
        except Exception as e:
            raise e   
        #logger.info(utilClass.readProperty("EXITING_METHOD"))  
        return key
    
    
    '''This method is used to get jKey'''
    def get_jkey(self,decoded_public_key):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            hash_object = hashlib.sha256(decoded_public_key)
            jKey = hash_object.hexdigest()
        except Exception as e:
            raise e   
        #logger.info(utilClass.readProperty("EXITING_METHOD"))  
        return jKey
    
    
    '''This method is used to encode a userId'''
    def get_jsessionid(self,user_id):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            jSessionId = RequestClass().b64_encode(user_id)
        except Exception as e:
            raise e   
        #logger.info(utilClass.readProperty("EXITING_METHOD"))  
        return jSessionId


    '''This method is used to send a request to TSO server and get response'''
    def send_request(self,body_content, url, authorization, user_id, tomcat_count, jKey, jData):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            if utilClass.isNotBlank(body_content):
                jsession_id = RequestClass().get_jsessionid(user_id)
                tomcat_count = RequestClass().get_tomcat_count(tomcat_count)
                if utilClass.isNotBlank(jsession_id):
                    url = url + "?jsessionid=" + jsession_id.strip()
                if utilClass.isNotBlank(tomcat_count):
                    url = url + "." + tomcat_count.strip()
                
                values = {'jKey': jKey,
                          'jData': jData}
                print "Before values",values
                data = urllib.urlencode(values)
                req = urllib2.Request(url, data)
                response = urllib2.urlopen(req)
                the_page = response.read()
                d = json.loads(the_page)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))  
                print "@@@@@@@@@@@@@@@@@@@@@@"
                print d
                return d
            else:
                resp = requests.post(url)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))  
                return resp.text
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
    
    
    '''This method is used to get cipher key'''
    def get_cipher(self,key):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            cipher = PKCS1_v1_5.new(key)
        except Exception as e:
            raise e   
        #logger.info(utilClass.readProperty("EXITING_METHOD"))  
        return cipher
    
    
    '''This method is used to encrypt  data block'''
    def encrypt_block(self,key, data, start, end):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            data = data[start:end]
            cipher = RequestClass().get_cipher(key)
            encrypted_data = cipher.encrypt(data)
            encoded_data = RequestClass().b64_encode(encrypted_data)
            replace_data = utilClass.replace_text(encoded_data, "\n", "")
        except Exception as e:
            raise e   
        #logger.info(utilClass.readProperty("EXITING_METHOD"))  
        return replace_data
    
    
    '''This method is used to encrypt a data'''
    def encrypt(self,data, key, key_size):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            buffer = ""
            number_of_bytes = ((int(utilClass.readProperty ('KEY_SIZE')) / int(utilClass.readProperty('BYTE_BOUNDARY'))) - int(utilClass.readProperty('BYTE_DIFFERENCE')))
            start = 0
            end = number_of_bytes
            if (number_of_bytes > len(data)):
                end = len(data)
            buffer = buffer + RequestClass().encrypt_block(key, data, start, end)
            buffer = utilClass.append_data(buffer, "\n")
            start = end
            end += number_of_bytes
            if (end > len(data)):
                end = len(data)
        
            while (end < len(data)):
                buffer = buffer + RequestClass().encrypt_block(key, data, start, end)
                buffer = utilClass.append_data(buffer, "\n")
                start = end
                end += number_of_bytes
                if (end > len(data)):
                    end = len(data)
            if (end - start > 0):
                buffer = buffer + RequestClass().encrypt_block(key, data, start, end)
                buffer = utilClass.append_data(buffer, "\n")
            buffer = RequestClass().b64_encode(buffer)
            buffer = utilClass.replace_text(buffer, "\n", "")
        except Exception as e:
            raise e   
        #logger.info(utilClass.readProperty("EXITING_METHOD"))  
        return buffer
    
    
    '''This method is used to get decrypt data'''
    def decrypt(self,data, private_key):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            data = RequestClass().b64_decode(data)
            data = unicode(data, "utf-8")
            data = data.strip().split("\n")
            final_data = ""
            for temp_data in data:
                temp_data = RequestClass().b64_decode(temp_data)
                cipher = RequestClass().get_cipher(private_key)
                temp_data = cipher.decrypt(temp_data, 'utf-8')
                final_data = utilClass.append_data(final_data, temp_data)
        except Exception as e:
            raise e           
        #logger.info(utilClass.readProperty("EXITING_METHOD"))      
        return final_data
    
    
    '''This method is used to get decode'''
    def b64_decode(self,data):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            decoded_data = base64.b64decode(data)
        except Exception as e:
            raise e       
        #logger.info(utilClass.readProperty("EXITING_METHOD"))  
        return decoded_data
    
    
    '''This method is used to get encode'''
    def b64_encode(self,data):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            encoded_data = data.encode("base64")
        except Exception as e:
            raise e   
        #logger.info(utilClass.readProperty("EXITING_METHOD"))  
        return encoded_data
    
    
    
    
    
    def get_tomcat_count(self,tomcat_count):
        # tomcat_count=''
        return tomcat_count    
