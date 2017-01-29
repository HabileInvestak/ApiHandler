class Audit():
    
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
