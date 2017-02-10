from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from properties.p import Property
from datetime import datetime
from rest_framework.views import exception_handler
from utils import UtilClass
from validate import Validate
from audit import AuditTrial
from request import RequestClass


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
from api_handler.wsgi import ReturnAllDict
from api_handler_app.models import Audit

e = ReturnAllDict()
AllList = e.returnDict()
ApiHomeDict = AllList[0]
InputDict = AllList[1]
SuccessDict = AllList[2]
FailureDict = AllList[3]
JsonDict = AllList[4]
ListDict = AllList[5]



logger = logging.getLogger('api_handler_app.views.py')

prop = Property ()
prop_obj = prop.load_property_files('D:\\InvestAK\\26-12-2016\\investak.properties')  #hari
#prop_obj = prop.load_property_files ('E:\\Investak\\investak\\investak.properties')  # ranjith


'''Provides you with initial token for Login '''
@api_view(["POST"])
def get_initial_token(request):
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    utilClass=UtilClass()
    ##logger.info(utilClass.readProperty("ENTERING_METHOD"))
    try:
        if request.method == utilClass.readProperty("METHOD_TYPE"):
            bodyContent = request.body
            url = ApiHomeDict.get(utilClass.readProperty("GET_INITIAL_KEY"))[0].url
            apiName = utilClass.readProperty ("GET_INITIAL_KEY")
            authorization = request.META.get(utilClass.readProperty("AUTHORIZATION"))
            userId=""
            '''Store InvestAK request for audit trial purpose'''
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            '''This method will check input availability and input format'''
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            userId=jsonObject.get('uid')
            result = validate.validation_and_manipulation (jsonObject, apiName,InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit(requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response(result)
            requestId= auditTrial.api_request_audit(requestId, result, apiName,userId,ApiHomeDict)
            user_id=""
            tomcat_count=""
            jKey=""
            jData=""
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            initial_public_key1 = output[utilClass.readProperty('PUBLIC_KEY')]
            tomcat_count = output[utilClass.readProperty('TOMCAT_COUNT')]
            public_key1_pem = requestObj.b64_decode(initial_public_key1)
            key_pair = requestObj.generate_key_pair()
            public_key2_pem = requestObj.get_public_key_pem(key_pair)
            private_key2_pem = requestObj.get_private_key_pem(key_pair)
            public_key1 = requestObj.import_key(public_key1_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(public_key2_pem, public_key1, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))    
            jKey = requestObj.get_jkey(public_key1_pem)
            user_id = userId
            url = ApiHomeDict.get(utilClass.readProperty('GET_PRE_AUTHENTICATION_KEY'))[0].url
            bodyContent= utilClass.readProperty('YES')
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            print output
            print "After send request"
            stat = output.get (utilClass.readProperty ('STATUS'))
            emsg = output.get (utilClass.readProperty ('ERROR'))
            initial_public_key3 = output[utilClass.readProperty('PUBLIC_KEY3')]
            private_key2 = requestObj.import_key(private_key2_pem)
            print "Before algo"
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                decrypted_public_key3 = requestObj.decrypt(initial_public_key3, private_key2)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            initial_token = utilClass.replace_text(requestObj.b64_encode(private_key2_pem),"\n","") + utilClass.readProperty('HYPEN') + utilClass.replace_text(requestObj.b64_encode(decrypted_public_key3),"\n","") + utilClass.readProperty('HYPEN') + utilClass.replace_text(requestObj.b64_encode(tomcat_count),"\n","") + utilClass.readProperty('HYPEN') + utilClass.replace_text(requestObj.b64_encode(userId),"\n","")
            dictionary =auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            if stat==utilClass.readProperty('OK'):
                output = {utilClass.readProperty('STATUS'):stat,utilClass.readProperty('INITIAL_TOKEN'): initial_token,utilClass.readProperty('TOMCAT_COUNT'):tomcat_count}
            else:
                output = {utilClass.readProperty ('STATUS'): stat,utilClass.readProperty ('ERROR'): emsg}
            print "#####################" 
            print output
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            print "output",output
            print "##"
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)            
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=validate.createErrorResponse(err)
        print auditTrial
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)
    
    
'''Get login mode'''
@api_view(["POST"])    
def get_login_mode(request):
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    try:
        if request.method == utilClass.readProperty("METHOD_TYPE"):
            bodyContent = request.body
            url = ApiHomeDict.get(utilClass.readProperty("LOGIN_MODE"))[0].url
            apiName = utilClass.readProperty ("LOGIN_MODE")
            authorization = request.META.get(utilClass.readProperty("AUTHORIZATION"))
            userId=""
            '''Store InvestAK request for audit trial purpose'''
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            '''This method will check input availability and input format'''
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            if bodyContent:
                jsonObject = json.loads (bodyContent)
                userId=jsonObject.get('uid')
                result = validate.validation_and_manipulation (jsonObject, apiName,InputDict)
                if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                    auditTrial.api_response_audit(requestId, result,apiName,ApiHomeDict)
                    #logger.info(utilClass.readProperty("EXITING_METHOD"))
                    return Response(result)
            requestId= auditTrial.api_request_audit(requestId, result, apiName,userId,ApiHomeDict)
            user_id=""
            tomcat_count=""
            jKey=""
            jData=""
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            print "output final",output
            output = json.loads(output)
            dictionary =auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)            
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=validate.createErrorResponse(err)
        print auditTrial
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)        


'''First step in login'''
@api_view(["POST"])
def get_login_2fa(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("LOGIN_2FA"))[0].url
            apiName = utilClass.readProperty ("LOGIN_2FA")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            public_key3_pem = requestObj.b64_decode(authorization[1].replace("\n",""))
            tomcat_count= requestObj.b64_decode(authorization[2].replace("\n",""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            logger.debug("userId="+userId)
            jKey = requestObj.get_jkey(public_key3_pem)
            userJSON=bodyContent = request.body
            logger.debug("userJSON="+userJSON)
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            logger.debug("requestId before input availability and format="+str(requestId))
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            logger.debug("result="+str(result))
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
               auditTrial. api_response_audit (requestId, result, apiName,ApiHomeDict)
               #logger.info(utilClass.readProperty("EXITING_METHOD"))
               return Response (result)
            jsonObject = json.loads (bodyContent)
            logger.debug("before validation_and_manipulation")
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            logger.debug("After validation_and_manipulation="+str(result))
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                logger.debug("Inside Status")
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            public_key3=requestObj.import_key(public_key3_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(userJSON,public_key3, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))    
            tomcat_count=requestObj.get_tomcat_count(tomcat_count)
            user_id=userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            logger.debug(dictionary)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)           
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=validate.createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)


'''Provide you with pre-authentication key for encryption'''
@api_view(["POST"])
def get_login(request):

    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("GET_PRE_AUTHENTICATION_KEY"))[0].url
            apiName = utilClass.readProperty ("GET_PRE_AUTHENTICATION_KEY")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key3_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.requestObj.get_jkey(public_key3_pem)
            userJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)

            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key3 = requestObj.import_key(public_key3_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key3, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)
   


'''Provide you with pre-authentication key for encryption'''
@api_view(["POST"])
def get_normal_login(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("GET_PRE_AUTHENTICATION_KEY"))[0].url
            apiName = utilClass.readProperty ("GET_PRE_AUTHENTICATION_KEY")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            private_key2_pem=requestObj.b64_decode(authorization[0].replace("\n",""))
            public_key3_pem = requestObj.b64_decode(authorization[1].replace("\n",""))
            tomcat_count= requestObj.b64_decode(authorization[2].replace("\n",""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key3_pem)
            userJSON=bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId = auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key3=requestObj.import_key(public_key3_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key3, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count=get_tomcat_count(tomcat_count)
            user_id=userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            encrypted_data = output["jEncResp"]
            private_key2 = requestObj.import_key(private_key2_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                decrypted_data = decrypt(encrypted_data,private_key2)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            decrypted_json = json.loads(decrypted_data)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)   
        

'''Gives you information about client enabled data'''
@api_view(["POST"])
def get_default_login(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("DEFAULT_LOGIN"))[0].url
            apiName = utilClass.readProperty ("DEFAULT_LOGIN")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n",""))
            tomcat_count= requestObj.b64_decode(authorization[2].replace("\n",""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON=bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            logger.debug("default login validation_and_manipulation result=")
            logger.debug(result)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId = auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4=requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data,public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count=requestObj.get_tomcat_count(tomcat_count)
            user_id=userId
            logger.debug("Before result")
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            logger.debug(output)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            #
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=validate.createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)
    
'''Authenticates the user with password'''
@api_view(["POST"])
def get_valid_pwd(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("VALID_PASSWORD"))[0].url
            apiName = utilClass.readProperty("VALID_PASSWORD")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            public_key3_pem = requestObj.b64_decode(authorization[1].replace("\n",""))
            tomcat_count= requestObj.b64_decode(authorization[2].replace("\n",""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key3_pem)
            userJSON=bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject,apiName,InputDict)
            logger.debug(result)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit(requestId,result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response(result)
    
            result = utilClass.PasswordHash(result)
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps (result)
            public_key3=requestObj.import_key(public_key3_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data,public_key3, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count=requestObj.get_tomcat_count(tomcat_count)
            user_id=userId
            #output=''
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary=auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            logger.debug("Before success validation")
            output = validate.validation_and_manipulation (output, apiName, dictionary)  #manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
    except Exception as e:
        logger.exception(e)
        err=str(e)
        logger.debug(err)
        output=validate.createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)    


'''Authenticates the answers in 2FA Q&A mode'''
@api_view(["POST"])
def get_valid_ans(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("VALID_ANSWER"))[0].url
            apiName = utilClass.readProperty ("VALID_ANSWER")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            private_key2_pem=requestObj.b64_decode(authorization[0].replace("\n",""))
            public_key3_pem = requestObj.b64_decode(authorization[1].replace("\n",""))
            tomcat_count= requestObj.b64_decode(authorization[2].replace("\n",""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key3_pem)
            userJSON=bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key3=requestObj.import_key(public_key3_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data,public_key3, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count=requestObj.get_tomcat_count(tomcat_count)
            user_id=userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            stat = output.get (utilClass.readProperty ('STATUS'))
            
            encrypted_data=output["jEncResp"]
            private_key2 = requestObj.import_key(private_key2_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                 decrypted_data=requestObj.decrypt(encrypted_data,private_key2)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            logger.debug(decrypted_data)
            decrypted_json = json.loads(decrypted_data)
            logger.debug(decrypted_json)
            dictionary =auditTrial.tso_response_audit (requestId, decrypted_json,apiName,ApiHomeDict,SuccessDict,FailureDict)
            logger.debug(dictionary)
            if decrypted_json[utilClass.readProperty('STATUS')]==utilClass.readProperty('OK'):
                access_token = utilClass.replace_text(requestObj.b64_encode(private_key2_pem), "\n", "") + "-" \
                               + utilClass.replace_text(requestObj.b64_encode(decrypted_json["sUserToken"]), "\n", "") + "-" \
                               + utilClass.replace_text(requestObj.b64_encode(tomcat_count), "\n", "") + "-" \
                               + utilClass.replace_text(requestObj.b64_encode(userId), "\n", "")
                decrypted_json[utilClass.readProperty('ACCESS_TOKEN')] = access_token               
            else:
                emsg = decrypted_json[utilClass.readProperty ('ERROR_MSG')]
                decrypted_json = {utilClass.readProperty('STATUS'): stat,utilClass.readProperty('ERROR_MSG'): emsg}
            logger.debug(str(decrypted_json))
            decrypted_json = validate.validation_and_manipulation (decrypted_json, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial. api_response_audit (requestId, decrypted_json,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(decrypted_json)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)


@api_view(["POST"])
def get_login_by_pass(request):
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    #logger.info(utilClass.readProperty("EXITING_METHOD"))
    return ''

'''Gives retention types for the particular exchange'''
@api_view(["POST"])
def get_load_retention_type(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("LOAD_RETENSION_TYPE"))[0].url
            apiName = utilClass.readProperty ("LOAD_RETENSION_TYPE")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization=authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n",""))
            tomcat_count= requestObj.b64_decode(authorization[2].replace("\n",""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON=bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4=requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data,public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count=requestObj.get_tomcat_count(tomcat_count)
            user_id=userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            print "output",output
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            print "dictionary",dictionary
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            print "output",output
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=validate.createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)


'''Check circuit limt for the order price'''
@api_view(["POST"])
def get_check_crkt_price_range(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:  
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("CHECK_CORRECT_PRICE_RANGE"))[0].url
            apiName = utilClass.readProperty ("CHECK_CORRECT_PRICE_RANGE")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = requestObj.get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)


'''GTD validations are done if retention is selected '''
@api_view(["POST"])
def get_validate_GTD(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("VALIDATE_GTD"))[0].url
            apiName = utilClass.readProperty ("VALIDATE_GTD")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = requestObj.get_tomcat_count(tomcat_count)
            user_id = userId
            print "Before send request"
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            print "After send request",output
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=validate.createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)    

'''Validates Stop loss price'''
@api_view(["POST"])
def get_validate_SLM_price(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("VALIDATE_SLM_PRICE"))[0].url
            apiName = utilClass.readProperty ("VALIDATE_SLM_PRICE")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId = auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)


'''Allows you to place order for selected scrip'''
@api_view(["POST"])
def get_place_order(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("PLACE_ORDER"))[0].url
            apiName = utilClass.readProperty ("PLACE_ORDER")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            print bodyContent
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            print "after result",result 
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId = auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = requestObj.get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=validate.createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)

'''Allows you to view the placed orders and their status'''
@api_view(["POST"])
def get_order_book(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("ORDER_BOOK"))[0].url
            apiName = utilClass.readProperty ("ORDER_BOOK")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId = auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = requestObj.get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            print output
            #dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            #output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            #auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)


'''Allows you to modify open orders'''
@api_view(["POST"])
def get_modify_order(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("MODIFY_ORDER"))[0].url
            apiName = utilClass.readProperty ("MODIFY_ORDER")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)    
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId = auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = requestObj.get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output) 

'''Allows you to cancel an open order'''
@api_view(["POST"])
def get_cancel_order(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("CANCEL_ORDER"))[0].url
            apiName = utilClass.readProperty ("CANCEL_ORDER")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = requestObj.get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)

'''Allows you to view the order history for the Order.'''
@api_view(["POST"])
def get_order_history(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("ORDER_HISTORY"))[0].url
            apiName = utilClass.readProperty ("ORDER_HISTORY")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = requestObj.get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)

'''Allows you to view trade details'''
@api_view(["POST"])
def get_trade_book(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("TRADE_BOOK"))[0].url
            apiName = utilClass.readProperty ("TRADE_BOOK")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = requestObj.get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)

'''This Allows user to view the holdings'''
@api_view(["POST"])
def get_holding(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("HOLDING"))[0].url
            apiName = utilClass.readProperty ("HOLDING")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = requestObj.get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=validate.createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)


'''Allows you to view segment w ise RMS limits'''
@api_view(["POST"])
def get_limits(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("LIMITS"))[0].url
            apiName = utilClass.readProperty ("LIMITS")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = requestObj.get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            print "output=",output
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)


'''Allows you to view segment w ise RMS limits'''
@api_view(["POST"])
def get_check_transaction_password(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("CHECK_TRANSACTION_PASSWORD"))[0].url
            logger.debug("url",url)
            apiName = utilClass.readProperty ("CHECK_TRANSACTION_PASSWORD")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = requestObj.get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            print "output=",output
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)


'''Provides you w ith user details'''
@api_view(["POST"])
def get_user_profile(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            print "Method type"
            url = ApiHomeDict.get(utilClass.readProperty("USER_PROFILE"))[0].url
            apiName = utilClass.readProperty ("USER_PROFILE")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            print "jsonObject-------------------",jsonObject
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = requestObj.get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)


'''Provides you with account details'''
@api_view(["POST"])
def get_account_info(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method ==utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("ACCOUNT_INFO"))[0].url
            apiName = utilClass.readProperty ("ACCOUNT_INFO")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = requestObj.get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=validate.createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)

'''Loads open order to set alerts based on trade.'''
@api_view(["POST"])
def get_open_orders(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("OPEN_ORDERS"))[0].url
            apiName = utilClass.readProperty ("OPEN_ORDERS")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = requestObj.get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)    



'''List of End of the Day holdings for clients'''
@api_view(["POST"])
def get_bo_holdings(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method ==utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("BO_HOLDINGS"))[0].url
            apiName = utilClass.readProperty ("BO_HOLDINGS")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
    
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)


'''List of End of the day underlying Trades for holdings for the clients'''
@api_view(["POST"])
def get_bo_Ul_Trades(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("BO_UI_TRADES"))[0].url
            apiName = utilClass.readProperty ("BO_UI_TRADES")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)


'''Allows you to logout from the application'''
@api_view(["POST"])
def get_logout(request):
    utilClass=UtilClass()
    #logger.info(utilClass.readProperty("ENTERING_METHOD"))
    auditTrial=AuditTrial()
    validate=Validate()
    requestObj=RequestClass()
    output=''
    requestId=''
    apiName=''
    try:
        if request.method == utilClass.readProperty ('METHOD_TYPE'):
            url = ApiHomeDict.get(utilClass.readProperty("LOG_OUT"))[0].url
            apiName=utilClass.readProperty("LOG_OUT")
            authorization = request.META.get(utilClass.readProperty('AUTHORIZATION'))
            authorization = authorization.split("-")
            public_key4_pem = requestObj.b64_decode(authorization[1].replace("\n", ""))
            tomcat_count = requestObj.b64_decode(authorization[2].replace("\n", ""))
            userId= requestObj.b64_decode(authorization[3].replace("\n",""))
            jKey = requestObj.get_jkey(public_key4_pem)
            requestJSON = bodyContent = request.body
            requestId = auditTrial.investak_request_audit (userId, bodyContent, apiName,ApiHomeDict)
            result = validate.chk_input_availability_and_format (bodyContent, apiName, ApiHomeDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result, apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
            jsonObject = json.loads (bodyContent)
            result = validate.validation_and_manipulation (jsonObject, apiName, InputDict)
            if utilClass.readProperty("STATUS") in result and result[utilClass.readProperty("STATUS")]==utilClass.readProperty("NOT_OK"):
                auditTrial.api_response_audit (requestId, result,apiName,ApiHomeDict)
                #logger.info(utilClass.readProperty("EXITING_METHOD"))
                return Response (result)
    
            requestId =auditTrial.api_request_audit (requestId, result, apiName,userId,ApiHomeDict)
            json_data = json.dumps(result)
            public_key4 = requestObj.import_key(public_key4_pem)
            if(utilClass.readProperty('ALGORITHM_TYPE')=='RSA'):
                jData = requestObj.encrypt(json_data, public_key4, 2048)
            else:
                raise Exception(utilClass.readProperty("ALGORITHM"))
            tomcat_count = requestObj.get_tomcat_count(tomcat_count)
            user_id = userId
            output = requestObj.send_request(bodyContent, url, authorization, user_id, tomcat_count, jKey, jData)
            dictionary = auditTrial.tso_response_audit (requestId, output,apiName,ApiHomeDict,SuccessDict,FailureDict)
            output = validate.validation_and_manipulation (output, apiName,dictionary)  # manipulation logic and call auditTrial.api_response_audit
            auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
            return Response(output)
        
    except Exception as e:
        logger.exception(e)
        err=str(e)
        output=createErrorResponse(err)
        auditTrial.api_response_audit (requestId, output,apiName,ApiHomeDict)
        return Response(output)