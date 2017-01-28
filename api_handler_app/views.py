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
#prop_obj = prop.load_property_files('D:\\InvestAK\\26-12-2016\\investak.properties')  #hari
prop_obj = prop.load_property_files ('E:\\Investak\\investak\\investak.properties')  # ranjith


''' This method will read the configuration values from property file'''
def readProperty(name):
    try:
        data=prop_obj.get(name)
        return data
    except Exception as e:
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
            requestId = investak_request_audit (userId, bodyContent, apiName)
            '''This method will check input availability and input format'''
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            userId=jsonObject.get('uid')
            result = validation_and_manipulation (jsonObject, apiName,InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit(requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response(result)
            requestId=api_request_audit(requestId, result, apiName,userId)
            output = send_request(bodyContent, url, authorization, user_id="", tomcat_count="", jKey="", jData="")
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
            bodyContent=readProperty('YES')
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            stat = output.get (readProperty ('STATUS'))
            emsg = output.get (readProperty ('ERROR'))
            initial_public_key3 = output[readProperty('PUBLIC_KEY3')]
            private_key2 = import_key(private_key2_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                decrypted_public_key3 = decrypt(initial_public_key3, private_key2)
            else:
                raise Exception(readProperty("ALGORITHM"))
            initial_token = replace_text(b64_encode(private_key2_pem),"\n","") + readProperty('HYPEN') + replace_text(b64_encode(decrypted_public_key3),"\n","") + readProperty('HYPEN') + replace_text(b64_encode(tomcat_count),"\n","") + readProperty('HYPEN') + replace_text(b64_encode(userId),"\n","")
            dictionary =tso_response_audit (requestId, output,apiName)
            if stat==readProperty('OK'):
                output = {readProperty('STATUS'):stat,readProperty('INITIAL_TOKEN'): initial_token,readProperty('TOMCAT_COUNT'):tomcat_count}
            else:
                output = {readProperty ('STATUS'): stat,readProperty ('ERROR'): emsg}
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
            
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
        return Response(output)
    

'''First step in login'''
@api_view([readProperty('METHOD_TYPE')])
def get_login_2fa(request):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if request.method == readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(readProperty("LOGIN_2FA"))[0].url
            apiName = readProperty ("LOGIN_2FA")
            authorization = request.META.get(readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            public_key3_pem = b64_decode(authorization[1].replace("\n",""))
            tomcat_count= b64_decode(authorization[2].replace("\n",""))
            userId= b64_decode(authorization[3].replace("\n",""))
            jKey = get_jkey(public_key3_pem)
            userJSON=bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            
            requestId =api_request_audit (requestId, result, apiName,userId)
            public_key3=import_key(public_key3_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(userJSON,public_key3, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))    
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)       
        
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            userJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)

            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key3 = import_key(public_key3_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key3, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            userJSON=bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId = api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key3=import_key(public_key3_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key3, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            encrypted_data = output["jEncResp"]
            private_key2 = import_key(private_key2_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                decrypted_data = decrypt(encrypted_data,private_key2)
            else:
                raise Exception(readProperty("ALGORITHM"))
            decrypted_json = json.loads(decrypted_data)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON=bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId = api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4=import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data,public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            userJSON=bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject,apiName,InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit(requestId,result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response(result)
    
            result = PasswordHash(result)
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps (result)
            public_key3=import_key(public_key3_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data,public_key3, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            #output=''
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary=tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName, dictionary)  #manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            userJSON=bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key3=import_key(public_key3_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data,public_key3, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            stat = output.get (readProperty ('STATUS'))
            emsg = output.get (readProperty ('ERROR_MSG'))
            encrypted_data=output["jEncResp"]
            private_key2 = import_key(private_key2_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                 decrypted_data=decrypt(encrypted_data,private_key2)
            else:
                raise Exception(readProperty("ALGORITHM"))
            decrypted_json = json.loads(decrypted_data)
            dictionary =tso_response_audit (requestId, output,apiName)
            if decrypted_json[readProperty('STATUS')]==readProperty('OK'):
                access_token = replace_text(b64_encode(private_key2_pem), "\n", "") + "-" \
                               + replace_text(b64_encode(decrypted_json["sUserToken"]), "\n", "") + "-" \
                               + replace_text(b64_encode(tomcat_count), "\n", "") + "-" \
                               + replace_text(b64_encode(userId), "\n", "")
                decrypted_json[readProperty('ACCESS_TOKEN')] = access_token               
                #output = {readProperty('STATUS'): stat,readProperty('ACCESS_TOKEN'): access_token}
            else:
                decrypted_json = {readProperty('STATUS'): stat,readProperty('ERROR_MSG'): emsg}
            output = validation_and_manipulation (decrypted_json, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, decrypted_json,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(decrypted_json)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            jKey = get_jkey(public_key4_pem)
            requestJSON=bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4=import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data,public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON=bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4=import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data,public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId = api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId = api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId = api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)    
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId = api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
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
            requestJSON = bodyContent = request.body
            requestId = investak_request_audit (userId, bodyContent, apiName)
            result = chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result, apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if readProperty("STATUS") in result and result[readProperty("STATUS")]==readProperty("NOT_OK"):
                api_response_audit (requestId, result,apiName)
                logger.info(readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =api_request_audit (requestId, result, apiName,userId)
            json_data = json.dumps(result)
            public_key4 = import_key(public_key4_pem)
            if(readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName)
            output = validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            api_response_audit (requestId, output,apiName)
            logger.info(readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        api_response_audit (requestId, output,apiName)
        return Response(output)


'''This method used to check validation and manipulation of the data'''
def validation_and_manipulation(jsonObject,apiName,dict):
    logger.info(readProperty("ENTERING_METHOD"))
    result={}
    try:
        if(dict==InputDict):
            result = validation_parameter (jsonObject, apiName, dict)
            if not result:
                jsonObject = manipulation_default (jsonObject, apiName, dict)
                result = validation_all (jsonObject, apiName, dict)
        if not result:
            jsonObject = manipulation_transformation(jsonObject, apiName, dict)
            result=jsonObject
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return result


'''This method used to manipulate transformation of the data'''
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


'''This method used to manipulate the data to default value'''
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


'''This method used to transform the data'''
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


'''This method used to check  default validation'''
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
    result = {}
    bodyIn=True
    try:
        if (dict == ApiHomeDict):
            param = check_input_body(jsonObject, apiName, ApiHomeDict)
            isError = param[0]
            errorList = param[1]
            if (isError == True):
                result = errorResponse (errorList, readProperty("NOT_OK"))
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))        
    return  result


'''This method used to check  parameter validation'''
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


'''This method used to check all validation'''
def validation_all(jsonObject,apiName,Dict):
    logger.info(readProperty("ENTERING_METHOD"))
    result = {}
    try:
        if jsonObject:
            dataType = check_all_validate(jsonObject, apiName, Dict)
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


'''This method used to check  mandatory,data type,valid values validation'''
def check_all_validate(content,ApiName,dict):
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


'''This method used to check valid values validation'''
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


'''This method used to check  mandatory validation'''
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


'''This method used to check all data type validation'''
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
            result={}
            #result = validation_and_manipulation (jsonObject, apiName, InputDict)
            if type (Paramvalue) is list:
                Paramvalue = {k: '' for k in Paramvalue}
                result=validation_and_manipulation(Paramvalue, validValues, JsonDict)
                if readProperty('STATUS') in result:
                    List = result.get (readProperty ('ERROR_MSG'))
                    for errorMsg in List:
                        errorList.append (errorMsg)
            else:
                pass
                
        # SSBOETOD need write
        
        if errorMsg:
            errorList.append (errorMsg)
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))    
    return errorList


'''This method used to check url type validation'''
def exist_Url(path):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        r = requests.head (path)
    except Exception as e:
        raise e   
    logger.info(readProperty("EXITING_METHOD"))
    return r.status_code == requests.codes.ok


'''This method used to validate date time format'''
def validateDate(date_text):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        time.strptime(date_text, '%m/%d/%Y/%w/%H:%M:%S')
        Date = True
    except ValueError:
        Date = False
    logger.info(readProperty("EXITING_METHOD"))    
    return Date


'''This method will check the input field availability and compare length of input field to expected length'''
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
        if isInputAvailable==readProperty("YES"):
            if content:
                if(readProperty('INPUT_OUTPUT_TYPE')==readProperty ("JSON")):
                    result=checkJson(content)
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
    return errorAvailable,errorList


'''This method will store the request from InvestAK for audit purpose'''
def investak_request_audit(userId,bodyContent,apiName):
    logger.info(readProperty("ENTERING_METHOD"))
    requestId=''
    try:
        dateNow = datetime.now ()
        logging = ApiHomeDict.get(apiName)[0].logging
        if (logging == readProperty ("YES") and readProperty ('INVESTAK_API_AUDIT_ENABLE') == readProperty ("YES")):
            Auditobj=Audit(user_id=userId, investak_request=request,investak_request_time_stamp=dateNow)
            Auditobj.save()
            requestId=Auditobj.request_id
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return requestId
    

'''This method will store the request of api for audit purpose'''
def api_request_audit(requestId,request,apiName,userId):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        dateNow = datetime.now ()
        logging=ApiHomeDict.get(apiName)[0].logging
        if(logging==readProperty("YES") and readProperty('API_TSO_AUDIT_ENABLE')==readProperty("YES") and readProperty('INVESTAK_API_AUDIT_ENABLE')==readProperty("YES")):
            obj, created = Audit.objects.update_or_create (
                requestId=request_id,
                defaults={readProperty('API_REQUEST'): request,readProperty('API_REQUEST_TIME_STAMP'):dateNow,readProperty('USER_ID'):userId},
            )
        else:
            Auditobj = Audit (user_id=userId, api_request=request, api_request_time_stamp=dateNow)
            Auditobj.save ()
            requestId = Auditobj.request_id   
    except Exception as e:
        raise e
    logger.info(readProperty("EXITING_METHOD"))
    return requestId


'''This method will store the response of api for audit purpose'''
def api_response_audit(requestId,request,apiName):
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
                requestId=request_id,
                defaults={readProperty('API_RESPONSE'): request,readProperty('API_RESPONSE_TIME_STAMP'):dateNow,readProperty('API_STATUS'):api_status},
            )
        logger.info(readProperty("EXITING_METHOD"))
    except Exception as e:
        raise e


'''This method will store the response of tso for audit purpose'''
def tso_response_audit(requestId,request,apiName):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        print 'TSO request',request
        dateNow = datetime.now ()
        #find json array
        if type(request) is list:
            print 'list'
            print len(request)
            for dict in request:
                print dict
        else:
            print 'no list it is dict'
        stat = request.get(readProperty('STATUS'))
        if stat == readProperty ('OK'):
            tso_status = readProperty('SUCCESS')
            dictionary=SuccessDict
        else:
            tso_status = readProperty('FAILURE')
            dictionary=FailureDict
        logging = ApiHomeDict.get(apiName)[0].logging
        if (logging == readProperty ("YES") and readProperty ('API_TSO_AUDIT_ENABLE') == readProperty ("YES")):
            obj, created = Audit.objects.update_or_create (
                requestId=request_id,
                defaults={readProperty('TSO_RESPONSE'): request,readProperty('TSO_RESPONSE_TIME_STAMP'):dateNow,readProperty('TSO_STATUS'):tso_status},
            )
    except Exception as e:
        raise Exception(e)
    logger.info(readProperty("EXITING_METHOD"))
    return dictionary


'''This method is used to create PasswordHash'''
def password_hash(password):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        for num in range(0, 999):
            password = hashlib.sha256(password).digest()
        password_hash = hashlib.sha256(password).hexdigest()
    except Exception as e:
        raise e   
    logger.info(readProperty("EXITING_METHOD"))
    return password_hash


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


'''This method is used to replace a data'''
def replace_text(orginal_data, old_text, new_text):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        orginal_data = orginal_data.replace(old_text, new_text)
    except Exception as e:
        raise e   
    logger.info(readProperty("EXITING_METHOD"))  
    return orginal_data


'''This method is used to add data'''
def append_data(original_text, append_text):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        original_text = original_text + append_text
    except Exception as e:
        raise e   
    logger.info(readProperty("EXITING_METHOD"))  
    return original_text


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


'''This method will check whether the given string is Blank or not'''
def isBlank(myString):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if myString and (part.strip() for part in myString):
            # myString is not None AND myString is not empty or blank
            logger.info(readProperty("EXITING_METHOD"))  
            return False
            # myString is None OR myString is empty or blank
    except Exception as e:
        raise e   
    logger.info(readProperty("EXITING_METHOD"))  
    return True


'''This method will check whether the given string is not Blank or Blank'''
def isNotBlank(myString):
    logger.info(readProperty("ENTERING_METHOD"))
    try:
        if myString and (part.strip() for part in myString):
            # myString is not None AND myString is not empty or blank
            logger.info(readProperty("EXITING_METHOD"))  
            return True
        # myString is None OR myString is empty or blank
    except Exception as e:
        raise e    
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


'''This method is used to create PasswordHash'''
def PasswordHash(jsonObject):
    logger.info(readProperty("ENTERING_METHOD"))
    data={}
    try:
        for key in jsonObject:
            value = jsonObject[key]
            if key == readProperty ('PASSWORD'):
                value = password_hash (value)
            data[key] = value
    except Exception as e:
        raise e        
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