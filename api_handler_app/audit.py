from utils import UtilClass
from datetime import datetime


from api_handler_app.models import Audit


import logging

logger = logging.getLogger('api_handler_app.audit.py')

class AuditTrial():
    
    '''This method will store the request from InvestAK for audit purpose'''
    def investak_request_audit(self,userId,bodyContent,apiName,ApiHomeDict):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        requestId=''
        try:
            dateNow = datetime.now ()
            logging = ApiHomeDict.get(apiName)[0].logging
            logger.debug("Before Investak API audit enable")
            logger.debug("Logging="+logging)
            if (logging == utilClass.readProperty ("YES") and utilClass.readProperty ('INVESTAK_API_AUDIT_ENABLE') == utilClass.readProperty ("YES")):
                logger.debug("Investak API audit enable")
                Auditobj=Audit(user_id=userId, investak_request=bodyContent,investak_request_time_stamp=dateNow)
                Auditobj.save()
                requestId=Auditobj.request_id
                logger.debug("requestId="+str(requestId))
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return requestId
    

    '''This method will store the request of api for audit purpose'''
    def api_request_audit(self,requestId,request,apiName,userId,ApiHomeDict):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            dateNow = datetime.now ()
            logging=ApiHomeDict.get(apiName)[0].logging
            if(logging==utilClass.readProperty("YES") and utilClass.readProperty('API_TSO_AUDIT_ENABLE')==utilClass.readProperty("YES") and utilClass.readProperty('INVESTAK_API_AUDIT_ENABLE')==utilClass.readProperty("YES")):
                obj, created = Audit.objects.update_or_create (
                    request_id=requestId,
                    defaults={utilClass.readProperty('API_REQUEST'): request,utilClass.readProperty('API_REQUEST_TIME_STAMP'):dateNow,utilClass.readProperty('USER_ID'):userId},
                )
            else:
                Auditobj = Audit (user_id=userId, api_request=request, api_request_time_stamp=dateNow)
                Auditobj.save ()
                requestId = Auditobj.request_id   
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return requestId
    
    
    '''This method will store the response of api for audit purpose'''
    def api_response_audit(self,requestId,request,apiName,ApiHomeDict):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            dateNow = datetime.now ()
            stat= request.get (utilClass.readProperty('STATUS'))
            if stat== utilClass.readProperty ('OK'):
                api_status=utilClass.readProperty ('SUCCESS')
            else:
                api_status = utilClass.readProperty ('FAILURE')
            logging = ApiHomeDict.get(apiName)[0].logging
            if (logging == utilClass.readProperty ("YES") and utilClass.readProperty ('INVESTAK_API_AUDIT_ENABLE') == utilClass.readProperty ("YES")):
                obj, created = Audit.objects.update_or_create (
                    request_id=requestId,
                    defaults={utilClass.readProperty('API_RESPONSE'): request,utilClass.readProperty('API_RESPONSE_TIME_STAMP'):dateNow,utilClass.readProperty('API_STATUS'):api_status},
                )
            #logger.info(utilClass.readProperty("EXITING_METHOD"))
        except Exception as e:
            raise e
    
    
    '''This method will store the response of tso for audit purpose'''
    def tso_response_audit(self,requestId,request,apiName,ApiHomeDict,SuccessDict,FailureDict):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
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
                print 'no list it is dict123'
            print "utilClass.readProperty('STATUS')===",utilClass.readProperty('STATUS')
            stat = request.get(utilClass.readProperty('STATUS'))
            print "stat===",stat
            if stat == utilClass.readProperty ('OK'):
                tso_status = utilClass.readProperty('SUCCESS')
                dictionary=SuccessDict
            else:
                tso_status = utilClass.readProperty('FAILURE')
                dictionary=FailureDict
            logging = ApiHomeDict.get(apiName)[0].logging
            if (logging == utilClass.readProperty ("YES") and utilClass.readProperty ('API_TSO_AUDIT_ENABLE') == utilClass.readProperty ("YES")):
                obj, created = Audit.objects.update_or_create (
                    request_id=requestId,
                    defaults={utilClass.readProperty('TSO_RESPONSE'): request,utilClass.readProperty('TSO_RESPONSE_TIME_STAMP'):dateNow,utilClass.readProperty('TSO_STATUS'):tso_status},
                )
        except Exception as e:
            raise Exception(e)
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return dictionary
