from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from properties.p import Property
from datetime import datetime
from rest_framework.views import exception_handler

import logging
import requests
import json
import hashlib
import urllib
import urllib2
import base64
import xlrd
import time

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from rest_example.wsgi import ReturnAllDict
from restapp.models import Audit

e = ReturnAllDict()
AllList = e.returnDict()
ApiHomeDict = AllList[0]
InputDict = AllList[1]
SuccessDict = AllList[2]
FailureDict = AllList[3]
JsonDict = AllList[4]
ListDict = AllList[5]


logger = logging.getLogger('restapp.views.py')

prop = Property ()
prop_obj = prop.load_property_files('D:\\InvestAK\\26-12-2016\\investak.properties')  #hari
#prop_obj = prop.load_property_files ('E:\\Investak\\investak\\investak.properties')  # ranjith


''' This method will read the configuration values from property file'''
def readProperty(name):
    try:
        data=prop_obj.get(name)
        return data
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        raise Exception(e)
    
    
'''Provides you with initial token for Login '''
@api_view([readProperty("METHOD_TYPE")])
def get_initial_token(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty("METHOD_TYPE"):
            bodyContent = request.body
            url = ApiHomeDict.get(readProperty("GET_INITIAL_KEY"))[0].url
            apiName = readProperty ("GET_INITIAL_KEY")
            authorization = request.META.get(readProperty("AUTHORIZATION"))
            userId=""
            '''Store InvestAK request for audit trial purpose'''
            request_id = investak_request_audit (userId, bodyContent, apiName)
 
            print "Before check data"
            
            '''This method will check input availability and input format'''
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
          
            print "result=============",result 
            #print "Output data",data[readProperty('STATUS')]
            
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (request_id, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            
            jsonObject = json.loads (bodyContent)
            userId=jsonObject.get('uid')
            print "Before validation"
            result = validation_and_manipulation (jsonObject, apiName,InputDict)
            print "After validation",result
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit(request_id, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response(result)
            print 'after validate '
            request_id=api_request_audit(request_id, result, apiName,userId)
            output = send_request(bodyContent, url, authorization, user_id="", tomcat_count="", jKey="", jData="")
            print "output",output
            initial_public_key1 = output[readProperty('PUBLIC_KEY')]
            tomcat_count = output[readProperty('TOMCAT_COUNT')]
            public_key1_pem = b64_decode(initial_public_key1)
            key_pair = generate_key_pair()
            public_key2_pem = get_public_key_pem(key_pair)
            private_key2_pem = get_private_key_pem(key_pair)
            public_key1 = import_key(public_key1_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(public_key2_pem, public_key1, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))    
            jKey = get_jkey(public_key1_pem)
            user_id = userId

            url = ApiHomeDict.get(readProperty('GET_PRE_AUTHENTICATION_KEY'))[0].url
            content=readProperty('YES')
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            stat = output.get (readProperty ('STATUS'))
            emsg = output.get (readProperty ('ERROR'))
            print 'tomcat_count ',tomcat_count
            initial_public_key3 = output[readProperty('PUBLIC_KEY3')]
            private_key2 = import_key(private_key2_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                decrypted_public_key3 = decrypt(initial_public_key3, private_key2)
            else:
                raise Exception(readProperty("ALGORITHM"))
            print readProperty('SLASH_N')
            initial_token = replace_text(b64_encode(private_key2_pem),"\n","") + readProperty('HYPEN') + replace_text(b64_encode(decrypted_public_key3),"\n","") + readProperty('HYPEN') + replace_text(b64_encode(tomcat_count),"\n","") + readProperty('HYPEN') + replace_text(b64_encode(userId),"\n","")
            dictionary =tso_response_audit (request_id, output,apiName)
            if stat==readProperty('OK'):
                output = {readProperty('STATUS'):stat,readProperty('INITIAL_TOKEN'): initial_token,readProperty('TOMCAT_COUNT'):tomcat_count}
            else:
                output = {readProperty ('STATUS'): stat,readProperty ('ERROR'): emsg}
            print "Before validation"
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            print "After validation"
            print "output",output
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
            
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)
    

'''First step in login'''
@api_view([readProperty('METHOD_TYPE')])
def get_login_2fa(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("LOGIN_2FA"))[0].url
            apiName = readProperty ("LOGIN_2FA")
            print 'url',url
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            public_key3_pem = b64_decode(authorization[1].replace("\n",""))
            tomcat_count= b64_decode(authorization[2].replace("\n",""))
            userId= b64_decode(authorization[3].replace("\n",""))
            print 'userId',userId
            jKey = get_jkey(public_key3_pem)
            userJSON=content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data=dataArray[0]
            BodyIn=dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn==True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)

            print 'after validate'
            request_id =api_request_audit (request_id, data, apiName,userId)
            public_key3=import_key(public_key3_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(userJSON,public_key3, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))    
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)       
        
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Provide you with pre-authentication key for encryption'''
@api_view([readProperty ('METHOD_TYPE')])
def get_login(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("GET_PRE_AUTHENTICATION_KEY"))[0].url
            apiName = readProperty ("GET_PRE_AUTHENTICATION_KEY")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key3_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key3_pem)
            userJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)

            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key3 = import_key(public_key3_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key3, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)
   


'''Provide you with pre-authentication key for encryption'''
@api_view([readProperty ('METHOD_TYPE')])
def get_normal_login(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("GET_PRE_AUTHENTICATION_KEY"))[0].url
            apiName = readProperty ("GET_PRE_AUTHENTICATION_KEY")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            private_key2_pem=b64_decode(authorization[0].replace("\n",""))
            public_key3_pem = b64_decode(authorization[1].replace("\n",""))
            tomcat_count= b64_decode(authorization[2].replace("\n",""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key3_pem)
            userJSON=content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id = api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key3=import_key(public_key3_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key3, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            encrypted_data = output["jEncResp"]
            private_key2 = import_key(private_key2_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                decrypted_data = decrypt(encrypted_data,private_key2)
            else:
                raise Exception(readProperty("ALGORITHM"))
            decrypted_json = json.loads(decrypted_data)
            print decrypted_json
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)   
        

'''Gives you information about client enabled data'''
@api_view([readProperty ('METHOD_TYPE')])
def get_default_login(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("DEFAULT_LOGIN"))[0].url
            apiName = readProperty ("DEFAULT_LOGIN")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n",""))
            tomcat_count= b64_decode(authorization[2].replace("\n",""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON=content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id = api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4=import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data,public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)
    
'''Authenticates the user with password'''
@api_view([readProperty ('METHOD_TYPE')])
def get_valid_pwd(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("VALID_PASSWORD"))[0].url
            apiName = readProperty("VALID_PASSWORD")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            public_key3_pem = b64_decode(authorization[1].replace("\n",""))
            tomcat_count= b64_decode(authorization[2].replace("\n",""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key3_pem)
            userJSON=content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject,apiName,InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit(request_id,data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response(data)
    
            data = PasswordHash(data)
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps (data)
            public_key3=import_key(public_key3_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data,public_key3, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            #output=''
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary=tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName, dictionary)  #manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)    

'''Authenticates the answers in 2FA Q&A mode'''
@api_view([readProperty ('METHOD_TYPE')])
def get_valid_ans(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("VALID_ANSWER"))[0].url
            apiName = readProperty ("VALID_ANSWER")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            private_key2_pem=b64_decode(authorization[0].replace("\n",""))
            public_key3_pem = b64_decode(authorization[1].replace("\n",""))
            tomcat_count= b64_decode(authorization[2].replace("\n",""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key3_pem)
            userJSON=content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key3=import_key(public_key3_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data,public_key3, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            print 'output accesstoken',output
            stat = output.get (readProperty ('STATUS'))
            print 'stat',stat
            emsg = output.get (readProperty ('ERROR_MSG'))
            encrypted_data=output["jEncResp"]
            private_key2 = import_key(private_key2_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                 decrypted_data=decrypt(encrypted_data,private_key2)
            else:
                raise Exception(readProperty("ALGORITHM"))
            decrypted_json = json.loads(decrypted_data)
            print 'output accesstoken decrypted_json',decrypted_json
            dictionary =tso_response_audit (request_id, output,apiName)
            if decrypted_json[readProperty('STATUS')]==readProperty('OK'):
                access_token = replace_text(b64_encode(private_key2_pem), "\n", "") + "-" \
                               + replace_text(b64_encode(decrypted_json["sUserToken"]), "\n", "") + "-" \
                               + replace_text(b64_encode(tomcat_count), "\n", "") + "-" \
                               + replace_text(b64_encode(userId), "\n", "")
                decrypted_json[readProperty('ACCESS_TOKEN')] = access_token               
                #output = {readProperty('STATUS'): stat,readProperty('ACCESS_TOKEN'): access_token}
            else:
                decrypted_json = {readProperty('STATUS'): stat,readProperty('ERROR_MSG'): emsg}
            print 'output',decrypted_json   
            output = validation_and_manipulation (decrypted_json, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, decrypted_json,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(decrypted_json)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Provides you with account details'''
@api_view([readProperty ('METHOD_TYPE')])
def get_account_info(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("ACCOUNT_INFO"))[0].url
            apiName = readProperty ("ACCOUNT_INFO")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n",""))
            tomcat_count= b64_decode(authorization[2].replace("\n",""))
            userId= b64_decode(authorization[3].replace("\n",""))
            print 'userId',userId
            jKey = get_jkey(public_key4_pem)
            requestJSON=content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4=import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data,public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


@api_view([readProperty ('METHOD_TYPE')])
def get_login_by_pass(request):
    logger.info(readProperty("ENTERING_METHOD"))
    logger.info(readProperty("EXITING_METHOD"))
    return ''

'''Gives retention types for the particular exchange'''
@api_view([readProperty ('METHOD_TYPE')])
def get_load_retention_type(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("LOAD_RETENSION_TYPE"))[0].url
            apiName = readProperty ("LOAD_RETENSION_TYPE")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n",""))
            tomcat_count= b64_decode(authorization[2].replace("\n",""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON=content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4=import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data,public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Check circuit limt for the order price'''
@api_view([readProperty ('METHOD_TYPE')])
def get_check_crkt_price_range(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:  
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("CHECK_CORRECT_PRICE_RANGE"))[0].url
            apiName = readProperty ("CHECK_CORRECT_PRICE_RANGE")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''GTD validations are done if retention is selected '''
@api_view([readProperty ('METHOD_TYPE')])
def get_validate_GTD(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("VALIDATE_GTD"))[0].url
            apiName = readProperty ("VALIDATE_GTD")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)    

'''Validates Stop loss price'''
@api_view([readProperty ('METHOD_TYPE')])
def get_validate_SLM_price(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("VALIDATE_SLM_PRICE"))[0].url
            apiName = readProperty ("VALIDATE_SLM_PRICE")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id = api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Allows you to place order for selected scrip'''
@api_view([readProperty ('METHOD_TYPE')])
def get_place_order(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("PLACE_ORDER"))[0].url
            apiName = readProperty ("PLACE_ORDER")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id = api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)

'''Allows you to view the placed orders and their status'''
@api_view([readProperty ('METHOD_TYPE')])
def get_order_book(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("ORDER_BOOK"))[0].url
            apiName = readProperty ("ORDER_BOOK")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id = api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Allows you to modify open orders'''
@api_view([readProperty ('METHOD_TYPE')])
def get_modify_order(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("MODIFY_ORDER"))[0].url
            apiName = readProperty ("MODIFY_ORDER")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id = api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output) 

'''Allows you to cancel an open order'''
@api_view([readProperty('METHOD_TYPE')])
def get_cancel_order(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("CANCEL_ORDER"))[0].url
            apiName = readProperty ("CANCEL_ORDER")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)

'''Allows you to view the order history for the Order.'''
@api_view([readProperty ('METHOD_TYPE')])
def get_order_history(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("ORDER_HISTORY"))[0].url
            apiName = readProperty ("ORDER_HISTORY")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)

'''Allows you to view trade details'''
@api_view([readProperty('METHOD_TYPE')])
def get_trade_book(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("TRADE_BOOK"))[0].url
            apiName = readProperty ("TRADE_BOOK")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)

'''This Allows user to view the holdings'''
@api_view([readProperty ('METHOD_TYPE')])
def get_holding(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("HOLDING"))[0].url
            apiName = readProperty ("HOLDING")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Allows you to view segment w ise RMS limits'''
@api_view([readProperty ('METHOD_TYPE')])
def get_limits(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("LIMITS"))[0].url
            apiName = readProperty ("LIMITS")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Provides you w ith user details'''
@api_view([readProperty('METHOD_TYPE')])
def get_user_profile(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("USER_PROFILE"))[0].url
            apiName = readProperty ("USER_PROFILE")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Provides you with account details'''
@api_view([readProperty('METHOD_TYPE')])
def get_account_info(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method ==readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("ACCOUNT_INFO"))[0].url
            apiName = readProperty ("ACCOUNT_INFO")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)

'''Loads open order to set alerts based on trade.'''
@api_view([readProperty ('METHOD_TYPE')])
def get_open_orders(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("OPEN_ORDERS"))[0].url
            apiName = readProperty ("OPEN_ORDERS")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            print 'output',output
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)    



'''List of End of the Day holdings for clients'''
@api_view([readProperty('METHOD_TYPE')])
def get_bo_holdings(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method ==readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("BO_HOLDINGS"))[0].url
            apiName = readProperty ("BO_HOLDINGS")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''List of End of the day underlying Trades for holdings for the clients'''
@api_view([readProperty ('METHOD_TYPE')])
def get_bo_Ul_Trades(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("BO_UI_TRADES"))[0].url
            apiName = readProperty ("BO_UI_TRADES")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


'''Allows you to logout from the application'''
@api_view([readProperty ('METHOD_TYPE')])
def get_logout(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("LOG_OUT"))[0].url
            apiName=readProperty("LOG_OUT")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = b64_decode(authorization[2].replace("\n", ""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key4_pem)
            requestJSON = content = request.body
            jsonObject = content
            request_id = investak_request_audit (userId, jsonObject, apiName)
            dataArray = chk_input_availability_and_format (content, apiName, ApiHomeDict)
            data = dataArray[0]
            BodyIn = dataArray[1]
            if 'stat' in data:
                api_response_audit (request_id, data, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
            if BodyIn == True:
                jsonObject = json.loads (content)
            data = validation_and_manipulation (jsonObject, apiName, InputDict)
            print 'data ', data
            if 'stat' in data:
                api_response_audit (request_id, data,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (data)
    
            print 'after validate '
            request_id =api_request_audit (request_id, data, apiName,userId)
            json_data = json.dumps(data)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(content, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (request_id, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (request_id, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        print "exception is ",e
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (request_id, output,apiName)
        return Response(output)


def validation_and_manipulation(jsonObject,apiName,dict):
    logger.info(readProperty("ENTERING_METHOD"))
    result={}
    try:
        result = validation_parameter (jsonObject, apiName, dict)
        if not result:
            jsonObject = manipulation_default (jsonObject, apiName, dict)
            result = validation_all (jsonObject, apiName, dict)#see
        if not result:
            jsonObject = manipulation_transformation(jsonObject, apiName, dict)
            result=jsonObject
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return result


def manipulation_transformation(jsonObject, apiName, dict):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if jsonObject and  not dict==FailureDict and not dict==JsonDict:
            for param, value in jsonObject.items():
                transformation= dict.get(apiName).get(param)[0].transformation
                value = transformation_validation (transformation, value)
                jsonObject[param] = value
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return jsonObject


def manipulation_default(jsonObject, apiName, dict):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if jsonObject and dict==InputDict:
            for param, value in jsonObject.items():
                default= dict.get(apiName).get(param)[0].default
                value = default_validation (default, value)
                jsonObject[param]=value
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return jsonObject


def transformation_validation(transformation,Paramvalue):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if isBlank(transformation):
            pass
        else:
            if isNotBlank(Paramvalue):
                transformation=ListDict.get(transformation).get(Paramvalue)[0].targetValue
                Paramvalue=transformation
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return Paramvalue

def default_validation(default,paramvalue):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if isBlank(default):
            pass
        elif(isBlank(Paramvalue)):
            paramvalue=default
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return paramvalue


'''This method will check the input for availability and format'''
def chk_input_availability_and_format(jsonObject,apiName,dict):
    logger.info(readProperty("ENTERING_METHOD"))
    data = {}
    bodyIn=True
    try:
        if (dict == ApiHomeDict):
            param = check_input_body(jsonObject, apiName, ApiHomeDict)
            isError = param[0]
            errorList = param[1]
            if (isError == True):
                data = errorResponse (errorList, readProperty("NOT_OK"))
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))        
    return  data


def validation_parameter(jsonObject,apiName,Dict):
    logger.info(readProperty("ENTERING_METHOD"))
    result = {}
    try:
        if jsonObject:
            param = check_all_parameter (jsonObject, apiName, Dict)
            isErrorAvailable = param[0]
            errorList = param[1]
            if (isErrorAvailable == True):
                result = errorResponse (errorList, readProperty("NOT_OK"))
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))        
    return  result


def validation_all(jsonObject,apiName,Dict):
    logger.info(readProperty("ENTERING_METHOD"))
    result = {}
    try:
        if jsonObject:
            dataType = check_all (jsonObject, apiName, Dict)
            isErrorAvailable = dataType[0]
            errorList = dataType[1]
            if (isErrorAvailable == True):
                result = errorResponse (errorList, readProperty("NOT_OK"))
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return  result


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


def check_all(content,ApiName,dict):
    logger.info(readProperty("ENTERING_METHOD"))
    isErrorAvailale=False
    errorMsg=''
    errorList=[]
    errorListAll=[]
    try:
        for param, value in content.items():
            dataType= dict.get(ApiName).get(param)[0].dataType
            validValues= dict.get(ApiName).get(param)[0].validValues
            if not dict==FailureDict and not dict==JsonDict:
                optional= dict.get(ApiName).get(param)[0].optional
                errorList = optional_validation (optional, value, param)
                errorListAll.extend (errorList)
            if not errorList:
                errorList=dataType_validation(dataType,value,param,dict,validValues)
                errorListAll.extend (errorList)
            if not errorList:
                errorList = valid_values_validation (validValues, value, param,dataType)
                errorListAll.extend (errorList)
            errorList=[]
    
        if errorListAll:
            isErrorAvailale = True
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return isErrorAvailale,errorListAll



def valid_values_validation(validValues,paramValue,param,dataType):
    logger.info(readProperty("ENTERING_METHOD"))
    errorList = []
    errorMsg=''
    try:
        if not (dataType == readProperty('JSON')):
            if isBlank(validValues):
                pass
            else:
                check=1
                words = validValues.split (',')
                for word in words:
                    if (paramValue == word):
                        check = 0
                if isNotBlank(paramValue) and check==0:
                    pass
                else:
                    arrayValue=[param,validValues,paramValue]
                    errorMsg=create_error_message(readProperty("INVALID_VALUE"),arrayValue)
        if errorMsg:
            errorList.append (errorMsg)
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))    
    return errorList


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


def optional_validation(optional, Paramvalue, param):
    logger.info(readProperty("ENTERING_METHOD"))
    errorList = []
    errorMsg = ""
    try:
        if isBlank(optional):
            pass
        elif(optional == readProperty('YES')):
            if isBlank(Paramvalue) :
                if Paramvalue is not None:
                    arrayValue = [param]
                    errorMsg = create_error_message (readProperty ("MANDATORY_FIELD"), arrayValue)
        if errorMsg:
            errorList.append (errorMsg)
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return errorList

def dataType_validation(dataType,Paramvalue,param,dict,validValues):
    logger.info(readProperty("ENTERING_METHOD"))
    errorList = []
    errorMsg=''
    try:
        if (dataType == readProperty('STRING')):
            pass
        elif (dataType == readProperty('CHARACTER')):
            Valuelen = len(Paramvalue)
            if (Valuelen == 1):
                pass
            else:
                arrayValue = [param, dataType]
                errorMsg = create_error_message (readProperty ("INVALID_DATATYPE"), arrayValue)
        elif(dataType == readProperty('NUMBER')):
            if(Paramvalue.isdigit()):
                pass
            else:
                arrayValue = [param, dataType]
                errorMsg = create_error_message (readProperty ("INVALID_DATATYPE"), arrayValue)
        elif (dataType == readProperty('DECIMAL')):
            '''if (value.isdecimal()):
                pass
            else:
                errorMsg = param + " " + readProperty ("INVALID_DATATYPE") + " " + dataType
                print errorMsg'''
            splitNum=Paramvalue.split('.', 1)
            print splitNum[1].isdigit () and splitNum[0].isdigit ()
            if(splitNum[1].isdigit() and splitNum[0].isdigit ()):
                if (isinstance (json.loads (Paramvalue), (float))):
                    pass
                else:
                    arrayValue = [param, dataType]
                    errorMsg = create_error_message (readProperty ("INVALID_DATATYPE"), arrayValue)
            else:
                arrayValue = [param, dataType]
                errorMsg = create_error_message (readProperty ("INVALID_DATATYPE"), arrayValue)
        elif (dataType == readProperty('LIST')):
            if type(Paramvalue) is list:
                pass
            else:
                arrayValue = [param, dataType]
                errorMsg = create_error_message (readProperty ("INVALID_DATATYPE"), arrayValue)
        elif (dataType == readProperty('DATE_TIME') and dict==InputDict):
            timestamp = time.strftime ('%m/%d/%Y/%w/%H:%M:%S')
            Date=validateDate (Paramvalue)
            if Date:
                pass
            else:
                arrayValue = [param,dataType]
                errorMsg = create_error_message (readProperty ("INVALID_DATATYPE_DATE"), arrayValue)
        elif (dataType == readProperty ('URL')):
            if exist_Url(Paramvalue):
                pass
            else:
                arrayValue = [param, dataType]
                errorMsg = create_error_message (readProperty ("INVALID_DATATYPE"), arrayValue)
        elif (dataType == readProperty ('JSON')):
            data={}
            #data = validation_and_manipulation (jsonObject, apiName, InputDict)
            if type (Paramvalue) is list:
                Paramvalue = {k: '' for k in Paramvalue}
                data=validation_and_manipulation(Paramvalue, validValues, JsonDict)
                if readProperty('STATUS') in data:
                    List = data.get (readProperty ('ERROR_MSG'))
                    for errorMsg in List:
                        errorList.append (errorMsg)
            else:
                print 'not list',Paramvalue
        # SSBOETOD need write
        if errorMsg:
            errorList.append (errorMsg)
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))    
    return errorList


def exist_Url(path):
    logger.info(readProperty("ENTERING_METHOD"))
    r = requests.head (path)

    print r.status_code
    logger.info(readProperty("EXITING_METHOD"))
    return r.status_code == requests.codes.ok


def validateDate(date_text):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        time.strptime(date_text, '%m/%d/%Y/%w/%H:%M:%S')
        Date = True
    except ValueError:
        Date = False
    logger.info(readProperty("EXITING_METHOD"))    
    return Date

def check_all_parameter(content,ApiName,dict):
    logger.info(readProperty("ENTERING_METHOD"))
    isErrorAvailable=False
    #print dict.get(ApiName).get(ApiName)[0].parameter
    errorList=[]
    expectList=[]
    expectMsg=''
    stat = ''
    try:
        for k, v in dict.items():
            if k == ApiName:
                for k1, v1 in v.items():
                    for v2 in v1:
                        b = v2.parameter
                        expectList.append(b.lower())
        expectLen=len (expectList)
        contentLen=len (content)
        if (expectLen != contentLen) and not dict==JsonDict:
            arrayValue = [expectLen,contentLen]
            expectMsg = create_error_message (readProperty ("EXPECTED_AVAILABLE_PARAMETERS"), arrayValue)
            errorList.append (expectMsg)
        if not errorList:
            for param, v in content.items():
                if (param.lower() in expectList):
                    pass
                else:
                    arrayValue = [param]
                    errorMsg = create_error_message (readProperty ("INVALID_FIELD"), arrayValue)
                    errorList.append(errorMsg)
        if errorList:
            isErrorAvailable = True
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return isErrorAvailable,errorList


'''This method will check the input for availability and format'''
def check_input_body(content,ApiName,dict):
    logger.info(readProperty("ENTERING_METHOD"))
    errorAvailable=False
    errorList=[]
    stat = ''
    try:
        isInputAvailable=dict.get(ApiName)[0].inputApi
        print "isInputAvailable",isInputAvailable
        print "readProperty",readProperty("YES")
        if isInputAvailable==readProperty("YES"):
            if content:
                if(readProperty('INPUT_OUTPUT_TYPE')==readProperty ("JSON")):
                    result=checkJson(content)
                    print "result",result
                    if result==False:
                        arrayValue = [readProperty ("JSON")]
                        errorMsg = create_error_message (readProperty ("BODY_INPUT_INVALID_FORMAT"), arrayValue)
                        errorList.append (errorMsg)
                else:
                    pass#raise Exception(readProperty('111'))            
            else:
                arrayValue = []
                errorMsg = create_error_message (readProperty ("BODY_INPUT_REQUIRED"), arrayValue)
                errorList.append(errorMsg)
    
        else:
            if content:
                arrayValue = []
                errorMsg = create_error_message (readProperty ("BODY_INPUT_NOT_ALLOWED"), arrayValue)
                errorList.append (errorMsg)
    
        if errorList:
            errorAvailable = True
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    print "Before return"
    print errorAvailable
    print errorList
    return errorAvailable,errorList

'''This method will store the request from InvestAK for audit purpose'''
def investak_request_audit(userId,bodyContent,apiName):
    logger.info(readProperty("ENTERING_METHOD"))
    request_id=''
    try:
        dateNow = datetime.now ()
        logging = ApiHomeDict.get(apiName)[0].logging
        if (logging == readProperty ("YES") and readProperty ('INVESTAK_API_AUDIT_ENABLE') == readProperty ("YES")):
            Auditobj=Audit(user_id=userId, investak_request=request,investak_request_time_stamp=dateNow)
            Auditobj.save()
            request_id=Auditobj.request_id
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return request_id
    

def api_request_audit(request_id,request,apiName,userId):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        dateNow = datetime.now ()
        logging=ApiHomeDict.get(apiName)[0].logging
        if(logging==readProperty("YES") and readProperty('API_TSO_AUDIT_ENABLE')==readProperty("YES") and readProperty('INVESTAK_API_AUDIT_ENABLE')==readProperty("YES")):
            obj, created = Audit.objects.update_or_create (
                request_id=request_id,
                defaults={readProperty('API_REQUEST'): request,readProperty('API_REQUEST_TIME_STAMP'):dateNow,readProperty('USER_ID'):userId},
            )
        else:
            Auditobj = Audit (user_id=userId, api_request=request, api_request_time_stamp=dateNow)
            Auditobj.save ()
            request_id = Auditobj.request_id   
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return request_id

def api_response_audit(request_id,request,apiName):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        dateNow = datetime.now ()
        stat= request.get (readProperty('STATUS'))
        if stat== readProperty ('OK'):
            api_status=readProperty ('SUCCESS')
        else:
            api_status = readProperty ('FAILURE')
        logging = ApiHomeDict.get(apiName)[0].logging
        if (logging == readProperty ("YES") and readProperty ('INVESTAK_API_AUDIT_ENABLE') == readProperty ("YES")):
            obj, created = Audit.objects.update_or_create (
                request_id=request_id,
                defaults={readProperty('API_RESPONSE'): request,readProperty('API_RESPONSE_TIME_STAMP'):dateNow,readProperty('API_STATUS'):api_status},
            )
        logger.info(readProperty("EXITING_METHOD"))
    except Exception as e:
        raise e


def tso_response_audit(request_id,request,apiName):
    print 'request',request 
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        dateNow = datetime.now ()
        stat = request.get(readProperty('STATUS'))
        if stat == readProperty ('OK'):
            tso_status = readProperty('SUCCESS')
            dictionary=SuccessDict
        else:
            tso_status = readProperty('FAILURE')
            dictionary=FailureDict
        print  'tso_status ',tso_status
        logging = ApiHomeDict.get(apiName)[0].logging
        if (logging == readProperty ("YES") and readProperty ('API_TSO_AUDIT_ENABLE') == readProperty ("YES")):
            obj, created = Audit.objects.update_or_create (
                request_id=request_id,
                defaults={readProperty('TSO_RESPONSE'): request,readProperty('TSO_RESPONSE_TIME_STAMP'):dateNow,readProperty('TSO_STATUS'):tso_status},
            )
        print 'tso_response_audit ',request
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return dictionary


def password_hash(password):
    logger.info(readProperty("ENTERING_METHOD"))
    for num in range(0, 999):
        password = hashlib.sha256(password).digest()
    password_hash = hashlib.sha256(password).hexdigest()
    logger.info(readProperty("EXITING_METHOD"))
    return password_hash


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


def get_cipher(key):
    logger.info(readProperty("ENTERING_METHOD"))
    cipher = PKCS1_v1_5.new(key)
    logger.info(readProperty("EXITING_METHOD"))  
    return cipher


def encrypt_block(key, data, start, end):
    logger.info(readProperty("ENTERING_METHOD"))
    data = data[start:end]
    cipher = get_cipher(key)
    encrypted_data = cipher.encrypt(data)
    encoded_data = b64_encode(encrypted_data)
    replace_data = replace_text(encoded_data, "\n", "")
    logger.info(readProperty("EXITING_METHOD"))  
    return replace_data


def encrypt(data, key, key_size):
    logger.info(readProperty("ENTERING_METHOD"))
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
    logger.info(readProperty("EXITING_METHOD"))  
    return buffer


def replace_text(orginal_data, old_text, new_text):
    logger.info(readProperty("ENTERING_METHOD"))
    orginal_data = orginal_data.replace(old_text, new_text)
    logger.info(readProperty("EXITING_METHOD"))  
    return orginal_data


def append_data(original_text, append_text):
    logger.info(readProperty("ENTERING_METHOD"))
    original_text = original_text + append_text
    logger.info(readProperty("EXITING_METHOD"))  
    return original_text


def decrypt(data, private_key):
    logger.info(readProperty("ENTERING_METHOD"))
    data = b64_decode(data)
    data = unicode(data, "utf-8")
    data = data.strip().split("\n")
    final_data = ""
    for temp_data in data:
        temp_data = b64_decode(temp_data)
        cipher = get_cipher(private_key)
        temp_data = cipher.decrypt(temp_data, 'utf-8')
        final_data = append_data(final_data, temp_data)
    logger.info(readProperty("EXITING_METHOD"))      
    return final_data


def b64_decode(data):
    logger.info(readProperty("ENTERING_METHOD"))
    decoded_data = base64.b64decode(data)
    logger.info(readProperty("EXITING_METHOD"))  
    return decoded_data


def b64_encode(data):
    logger.info(readProperty("ENTERING_METHOD"))
    encoded_data = data.encode("base64")
    logger.info(readProperty("EXITING_METHOD"))  
    return encoded_data


def generate_key_pair():
    logger.info(readProperty("ENTERING_METHOD"))
    random_generator = Random.new().read
    #print "Key size",readProperty('KEY_SIZE')
    key = RSA.generate(int(readProperty('KEY_SIZE')), random_generator)
    logger.info(readProperty("EXITING_METHOD"))  
    return key


def get_public_key_pem(key):
    logger.info(readProperty("ENTERING_METHOD"))
    publicKey2_PEM = key.publickey().exportKey("PEM")
    logger.info(readProperty("EXITING_METHOD"))  
    return publicKey2_PEM


def get_private_key_pem(key):
    logger.info(readProperty("ENTERING_METHOD"))
    privateKey2_PEM = key.exportKey()
    logger.info(readProperty("EXITING_METHOD"))  
    return privateKey2_PEM


def import_key(key_pem):
    logger.info(readProperty("ENTERING_METHOD"))
    key = RSA.importKey(key_pem)
    # cipher = PKCS1_v1_5.new(key)
    logger.info(readProperty("EXITING_METHOD"))  
    return key


def get_jkey(decoded_public_key):
    logger.info(readProperty("ENTERING_METHOD"))
    hash_object = hashlib.sha256(decoded_public_key)
    jKey = hash_object.hexdigest()
    logger.info(readProperty("EXITING_METHOD"))  
    return jKey


def get_jsessionid(user_id):
    logger.info(readProperty("ENTERING_METHOD"))
    jSessionId = b64_encode(user_id)
    logger.info(readProperty("EXITING_METHOD"))  
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
    logger.info(readProperty("ENTERING_METHOD"))
    if myString and (part.strip() for part in myString):
        # myString is not None AND myString is not empty or blank
        logger.info(readProperty("EXITING_METHOD"))  
        return False
    # myString is None OR myString is empty or blank
    logger.info(readProperty("EXITING_METHOD"))  
    return True


def isNotBlank(myString):
    logger.info(readProperty("ENTERING_METHOD"))
    if myString and (part.strip() for part in myString):
        # myString is not None AND myString is not empty or blank
        logger.info(readProperty("EXITING_METHOD"))  
        return True
    # myString is None OR myString is empty or blank
    logger.info(readProperty("EXITING_METHOD"))  
    return False


'''This method will check whether the given input is in JSON format or not'''
def checkJson(text):
    logger.info(readProperty("ENTERING_METHOD"))
    result = False
    try:
        json.loads(text)
        result = True 
    except Exception as e:
        result = False
    logger.info(readProperty("EXITING_METHOD"))  
    return result


def PasswordHash(jsonObject):
    logger.info(readProperty("ENTERING_METHOD"))
    data={}
    for key in jsonObject:
        value = jsonObject[key]
        if key == readProperty ('PASSWORD'):
            value = password_hash (value)
        data[key] = value
    logger.info(readProperty("EXITING_METHOD"))      
    return data
    
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