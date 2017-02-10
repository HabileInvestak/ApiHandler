from utils import UtilClass
import logging
import requests
import json
import datetime
from api_handler.wsgi import ReturnAllDict
from lib2to3.fixer_util import is_list
from pip.download import is_url

logger = logging.getLogger('api_handler_app.validate.py')


class Validate():
    
    '''This method used to check  mandatory validation'''
    def optional_validation(self,optional, Paramvalue, param):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        errorList = []
        errorMsg = ""
        try:
            print "optional_validation"
            if utilClass.isBlank(optional):
                pass
            elif(optional == utilClass.readProperty('YES')):
                if utilClass.isBlank(Paramvalue) :
                    if Paramvalue is not None:
                        arrayValue = [param]
                        errorMsg = Validate().create_error_message (utilClass.readProperty ("MANDATORY_FIELD"), arrayValue)
            if errorMsg:
                errorList.append (errorMsg)
            print "oprional validation end "
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return errorList
    
    
    def is_string(self,Paramvalue,param, dataType,validValues,error_message_template):
        errorMsg=''
        if Paramvalue:
            pass
        return errorMsg
    
    
    def is_character(self,Paramvalue,param, dataType,validValues,error_message_template):
        errorMsg=''
        utilClass=UtilClass()
        if Paramvalue:
            errorMsg=''
            Valuelen = len(Paramvalue)
            if (Valuelen == 1):
                pass
            else:
                arrayValue = [param, dataType,validValues]
                errorMsg = Validate().create_error_message (utilClass.readProperty (error_message_template), arrayValue)
        return errorMsg
    
    
    def is_number(self,Paramvalue,param, dataType,validValues,error_message_template):
        errorMsg=''
        utilClass=UtilClass()
        if Paramvalue:
            logger.debug(Paramvalue)
            if(Paramvalue.isdigit()):
                pass
            else:
                arrayValue = [param, dataType,validValues]
                errorMsg = Validate().create_error_message (utilClass.readProperty (error_message_template), arrayValue)
        return errorMsg
    
    
    def is_decimal(self,Paramvalue,param, dataType,validValues,error_message_template):
        errorMsg=''
        utilClass=UtilClass()
        if Paramvalue:
            if (isinstance (json.loads (Paramvalue), (float))):
                pass
            else:
                arrayValue = [param, dataType,validValues]
                errorMsg = Validate().create_error_message (utilClass.readProperty (error_message_template), arrayValue)
        return errorMsg
    
    
    def is_list(self,Paramvalue,param, dataType,validValues,error_message_template):
        errorMsg=''
        utilClass=UtilClass()
        e = ReturnAllDict()
        AllList = e.returnDict()
        ApiHomeDict = AllList[0]
        InputDict = AllList[1]
        SuccessDict = AllList[2]
        FailureDict = AllList[3]
        JsonDict = AllList[4]
        ListDict = AllList[5]
        listArray=JsonDict.get(validValues)
        if Paramvalue:
            logger.debug("listArray")
            logger.debug(listArray)
            if Paramvalue in listArray:
                logger.debug("if")
            else:
                logger.debug("else")#pass
                arrayValue = [param, dataType,validValues]
                errorMsg = Validate().create_error_message (utilClass.readProperty (error_message_template), arrayValue)
        return errorMsg
    
    
    def is_date_time(self,Paramvalue,param, dataType,validValues,error_message_template):
        errorMsg=''
        utilClass=UtilClass()
        if Paramvalue:
                    #timestamp = time.strftime ('%m/%d/%Y/%w/%H:%M:%S')
            Date=Validate().validateDate (Paramvalue)
            if Date:
                pass
            else:
                arrayValue = [param,dataType,validValues]
                errorMsg = Validate().create_error_message (utilClass.readProperty ("INVALID_DATATYPE_DATE"), arrayValue)
        return errorMsg
    
    
    def is_url(self,Paramvalue,param, dataType,validValues,error_message_template):
        errorMsg=''
        utilClass=UtilClass()
        if Paramvalue:
            logger.debug("dataType="+str(dataType))
            if Validate().exist_Url(Paramvalue):
                pass
            else:
                arrayValue = [param, dataType,validValues]
                errorMsg = Validate().create_error_message (utilClass.readProperty (error_message_template), arrayValue)
        return errorMsg
    
    
    def is_json(self,Paramvalue,param, dataType,JsonDict,validValues):
        errorMsg=''
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        e = ReturnAllDict()
        AllList = e.returnDict()
        ApiHomeDict = AllList[0]
        InputDict = AllList[1]
        SuccessDict = AllList[2]
        FailureDict = AllList[3]
        JsonDict = AllList[4]
        ListDict = AllList[5]
        utilClass=UtilClass()
        if Paramvalue:
            logger.debug("###############JSON1")
            logger.debug("ValidValues")
            logger.debug(validValues)
            logger.debug("Paramvalue")
            logger.debug(Paramvalue)
            #logger.debug(JsonDict.get(validValues))
            for paramValueTemp in Paramvalue:
                errorMsgTemp=''
                logger.debug(paramValueTemp)
                logger.debug(JsonDict.get(validValues).get(paramValueTemp)[0].dataType)
                dataType=JsonDict.get(validValues).get(paramValueTemp)[0].dataType
                validValuesInner=JsonDict.get(validValues).get(paramValueTemp)[0].validValues
                if (dataType == utilClass.readProperty('STRING')):
                    errorMsgTemp=Validate().is_string(paramValueTemp,paramValueTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgTemp
                        else:
                            errorMsg=errorMsg+errorMsgTemp
                    else:
                        errorMsgTemp=Validate().valid_values_validation_JSON(validValuesInner,paramValueTemp,paramValueTemp,dataType,validValues)
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                elif (dataType == utilClass.readProperty('CHARACTER')):
                    errorMsgTemp=Validate().is_character(paramValueTemp,paramValueTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgTemp
                        else:
                            errorMsg=errorMsg+errorMsgTemp
                    else:
                        errorMsgTemp=Validate().valid_values_validation_JSON(validValuesInner,paramValueTemp,paramValueTemp,dataType,validValues)
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                elif(dataType == utilClass.readProperty('NUMBER')):
                    errorMsgTemp=Validate().is_number(paramValueTemp,paramValueTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgTemp
                        else:
                            errorMsg=errorMsg+errorMsgTemp
                    else:
                        errorMsgTemp=Validate().valid_values_validation_JSON(validValuesInner,paramValueTemp,paramValueTemp,dataType,validValues)
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                elif (dataType == utilClass.readProperty('DECIMAL')):
                    errorMsgTemp=Validate().is_decimal(paramValueTemp,paramValueTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgTemp
                        else:
                            errorMsg=errorMsg+errorMsgTemp
                    else:
                        errorMsgTemp=Validate().valid_values_validation_JSON(validValuesInner,paramValueTemp,paramValueTemp,dataType,validValues)
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                elif (dataType == utilClass.readProperty('LIST')):
                    errorMsgTemp=Validate().is_list(paramValueTemp,paramValueTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgTemp
                        else:
                            errorMsg=errorMsg+errorMsgTemp
                    else:
                        errorMsgTemp=Validate().valid_values_validation_JSON(validValuesInner,paramValueTemp,paramValueTemp,dataType,validValues)
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                elif (dataType == utilClass.readProperty('DATE_TIME')):
                    errorMsgTemp=Validate().is_date_time(paramValueTemp,paramValueTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgTemp
                        else:
                            errorMsg=errorMsg+errorMsgTemp
                    else:
                        errorMsgTemp=Validate().valid_values_validation_JSON(validValuesInner,paramValueTemp,paramValueTemp,dataType,validValues)
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                elif (dataType == utilClass.readProperty ('URL')):
                    errorMsgTemp=Validate().is_url(paramValueTemp,paramValueTemp,dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        if errorMsg:
                            errorMsg=errorMsg+","+errorMsgTemp
                        else:
                            errorMsg=errorMsg+errorMsgTemp
                    else:
                        errorMsgTemp=Validate().valid_values_validation_JSON(validValuesInner,paramValueTemp,paramValueTemp,dataType,validValues)
                        if errorMsgTemp:
                            if errorMsg:
                                errorMsg=errorMsg+","+errorMsgTemp
                            else:
                                errorMsg=errorMsg+errorMsgTemp
                elif (dataType == utilClass.readProperty ('JSON')):
                    logger.debug("JSON2") 
                    logger.debug("ValidValues JSON2")
                    logger.debug(validValues)
                    logger.debug("Paramvalue JSON2")
                    logger.debug(paramValueTemp)
                    validValues1=JsonDict.get(validValues).get(paramValueTemp)[0].validValues
                    logger.debug("validValues JSON2")
                    logger.debug(validValues1)
                    paramValueTemp1=JsonDict.get(validValues1)
                    if paramValueTemp1:
                        #logger.debug(validValues1)
                        #logger.debug(paramValueTemp1)
                        logger.debug(JsonDict.get(validValues1))
                        for paramValueInnerTemp1 in paramValueTemp1:
                            errorMsgTemp=''
                            logger.debug("Inner paramValueTemp1")
                            logger.debug(paramValueInnerTemp1)
                            logger.debug(JsonDict.get(validValues1).get(paramValueInnerTemp1)[0].dataType)
                            logger.debug("Inner datatype")
                            dataType1=JsonDict.get(validValues1).get(paramValueInnerTemp1)[0].dataType
                            validValues1Inner=JsonDict.get(validValues1).get(paramValueInnerTemp1)[0].validValues

                            if (dataType1 == utilClass.readProperty('STRING')):
                                errorMsgTemp=Validate().is_string(paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1,"INVALID_DATATYPE_JSON")
                                if errorMsgTemp:
                                    if errorMsg:
                                        errorMsg=errorMsg+","+errorMsgTemp
                                    else:
                                        errorMsg=errorMsg+errorMsgTemp
                                else:
                                    errorMsgTemp=Validate().valid_values_validation_JSON(validValues1Inner,paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1)
                                    if errorMsgTemp:
                                        if errorMsg:
                                            errorMsg=errorMsg+","+errorMsgTemp
                                        else:
                                            errorMsg=errorMsg+errorMsgTemp
                            elif (dataType1 == utilClass.readProperty('CHARACTER')):
                                errorMsgTemp=Validate().is_character(paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1,"INVALID_DATATYPE_JSON")
                                if errorMsgTemp:
                                    if errorMsg:
                                        errorMsg=errorMsg+","+errorMsgTemp
                                    else:
                                        errorMsg=errorMsg+errorMsgTemp
                                else:
                                    errorMsgTemp=Validate().valid_values_validation_JSON(validValues1Inner,paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1)
                                    if errorMsgTemp:
                                        if errorMsg:
                                            errorMsg=errorMsg+","+errorMsgTemp
                                        else:
                                            errorMsg=errorMsg+errorMsgTemp
                            elif(dataType1 == utilClass.readProperty('NUMBER')):
                                errorMsgTemp=Validate().is_number(paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1,"INVALID_DATATYPE_JSON")
                                if errorMsgTemp:
                                    if errorMsg:
                                        errorMsg=errorMsg+","+errorMsgTemp
                                    else:
                                        errorMsg=errorMsg+errorMsgTemp
                                else:
                                    errorMsgTemp=Validate().valid_values_validation_JSON(validValues1Inner,paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1)
                                    if errorMsgTemp:
                                        if errorMsg:
                                            errorMsg=errorMsg+","+errorMsgTemp
                                        else:
                                            errorMsg=errorMsg+errorMsgTemp
                            elif (dataType1 == utilClass.readProperty('DECIMAL')):
                                errorMsgTemp=Validate().is_decimal(paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1,"INVALID_DATATYPE_JSON")
                                if errorMsgTemp:
                                    if errorMsg:
                                        errorMsg=errorMsg+","+errorMsgTemp
                                    else:
                                        errorMsg=errorMsg+errorMsgTemp
                                else:
                                    errorMsgTemp=Validate().valid_values_validation_JSON(validValues1Inner,paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1)
                                    if errorMsgTemp:
                                        if errorMsg:
                                            errorMsg=errorMsg+","+errorMsgTemp
                                        else:
                                            errorMsg=errorMsg+errorMsgTemp
                            elif (dataType1 == utilClass.readProperty('LIST')):
                                errorMsgTemp=Validate().is_list(paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1,"INVALID_DATATYPE_JSON")
                                if errorMsgTemp:
                                    if errorMsg:
                                        errorMsg=errorMsg+","+errorMsgTemp
                                    else:
                                        errorMsg=errorMsg+errorMsgTemp
                                else:
                                    errorMsgTemp=Validate().valid_values_validation_JSON(validValues1Inner,paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1)
                                    if errorMsgTemp:
                                        if errorMsg:
                                            errorMsg=errorMsg+","+errorMsgTemp
                                        else:
                                            errorMsg=errorMsg+errorMsgTemp
                            elif (dataType1 == utilClass.readProperty('DATE_TIME')):
                                errorMsgTemp=Validate().is_date_time(paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1,"INVALID_DATATYPE_JSON")
                                if errorMsgTemp:
                                    if errorMsg:
                                        errorMsg=errorMsg+","+errorMsgTemp
                                    else:
                                        errorMsg=errorMsg+errorMsgTemp
                                else:
                                    errorMsgTemp=Validate().valid_values_validation_JSON(validValues1Inner,paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1)
                                    if errorMsgTemp:
                                        if errorMsg:
                                            errorMsg=errorMsg+","+errorMsgTemp
                                        else:
                                            errorMsg=errorMsg+errorMsgTemp
                            elif (dataType1 == utilClass.readProperty ('URL')):
                                errorMsgTemp=Validate().is_url(paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1,"INVALID_DATATYPE_JSON")
                                if errorMsgTemp:
                                    if errorMsg:
                                        errorMsg=errorMsg+","+errorMsgTemp
                                    else:
                                        errorMsg=errorMsg+errorMsgTemp
                                else:
                                    errorMsgTemp=Validate().valid_values_validation_JSON(validValues1Inner,paramValueInnerTemp1,paramValueInnerTemp1,dataType1,validValues+"->"+validValues1)
                                    if errorMsgTemp:
                                        if errorMsg:
                                            errorMsg=errorMsg+","+errorMsgTemp
                                        else:
                                            errorMsg=errorMsg+errorMsgTemp
                            elif (dataType1 == utilClass.readProperty ('JSON')):
                                logger.debug("JSON3")
                                logger.debug("ValidValues JSON2")
                                logger.debug(validValues+"->"+validValues1)
                                logger.debug("Paramvalue JSON2")
                                logger.debug(paramValueInnerTemp1)
                                validValues2=JsonDict.get(validValues1).get(paramValueInnerTemp1)[0].validValues
                                logger.debug("validValues JSON2")
                                logger.debug(validValues2)
                                paramValueTemp2=validValues2
                                logger.debug(paramValueTemp2)
                                paramValueTemp2=JsonDict.get(validValues2)
                                logger.debug(validValues2)
                                if paramValueTemp2:
                                    for paramValueInnerTemp2 in paramValueTemp2:
                                        errorMsgTemp=''
                                        logger.debug("Inner paramValueTemp1")
                                        logger.debug(paramValueInnerTemp2)
                                        logger.debug(JsonDict.get(validValues2).get(paramValueInnerTemp2)[0].dataType)
                                        dataType2=JsonDict.get(validValues2).get(paramValueInnerTemp2)[0].dataType
                                        validValues2Inner=JsonDict.get(validValues2).get(paramValueInnerTemp2)[0].validValues
                                        logger.debug("errorMsgTemp@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"+errorMsgTemp)
                                        if (dataType2 == utilClass.readProperty('STRING')):
                                            errorMsgTemp=Validate().is_string(paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2,"INVALID_DATATYPE_JSON")
                                            if errorMsgTemp:
                                                if errorMsg:
                                                    errorMsg=errorMsg+","+errorMsgTemp
                                                else:
                                                    errorMsg=errorMsg+errorMsgTemp
                                            else:
                                                errorMsgTemp=Validate().valid_values_validation_JSON(validValues2Inner,paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2)
                                                if errorMsgTemp:
                                                    if errorMsg:
                                                        errorMsg=errorMsg+","+errorMsgTemp
                                                    else:
                                                        errorMsg=errorMsg+errorMsgTemp
                                        elif (dataType2 == utilClass.readProperty('CHARACTER')):
                                            errorMsgTemp=Validate().is_character(paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2,"INVALID_DATATYPE_JSON")
                                            if errorMsgTemp:
                                                if errorMsg:
                                                    errorMsg=errorMsg+","+errorMsgTemp
                                                else:
                                                    errorMsg=errorMsg+errorMsgTemp
                                            else:
                                                errorMsgTemp=Validate().valid_values_validation_JSON(validValues2Inner,paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2)
                                                if errorMsgTemp:
                                                    if errorMsg:
                                                        errorMsg=errorMsg+","+errorMsgTemp
                                                    else:
                                                        errorMsg=errorMsg+errorMsgTemp
                                        elif(dataType2 == utilClass.readProperty('NUMBER')):
                                            logger.debug("Inside number")
                                            errorMsgTemp=Validate().is_number(paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2,"INVALID_DATATYPE_JSON")
                                            if errorMsgTemp:
                                                if errorMsg:
                                                    logger.debug("Inside error message")
                                                    errorMsg=errorMsg+","+errorMsgTemp
                                                    logger.debug("Inside after error message")
                                                else:
                                                    logger.debug("Outside error message")
                                                    errorMsg=errorMsg+errorMsgTemp
                                                    logger.debug("Outside after error message")
                                            else:
                                                errorMsgTemp=Validate().valid_values_validation_JSON(validValues2Inner,paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2)
                                                if errorMsgTemp:
                                                    if errorMsg:
                                                        errorMsg=errorMsg+","+errorMsgTemp
                                                    else:
                                                        errorMsg=errorMsg+errorMsgTemp
                                        elif (dataType2 == utilClass.readProperty('DECIMAL')):
                                            errorMsgTemp=Validate().is_decimal(paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2,"INVALID_DATATYPE_JSON")
                                            if errorMsgTemp:
                                                if errorMsg:
                                                    errorMsg=errorMsg+","+errorMsgTemp
                                                else:
                                                    errorMsg=errorMsg+errorMsgTemp
                                            else:
                                                errorMsgTemp=Validate().valid_values_validation_JSON(validValues2Inner,paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2)
                                                if errorMsgTemp:
                                                    if errorMsg:
                                                        errorMsg=errorMsg+","+errorMsgTemp
                                                    else:
                                                        errorMsg=errorMsg+errorMsgTemp
                                        elif (dataType2 == utilClass.readProperty('LIST')):
                                            errorMsgTemp=Validate().is_list(paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2,"INVALID_DATATYPE_JSON")
                                            if errorMsgTemp:
                                                if errorMsg:
                                                    errorMsg=errorMsg+","+errorMsgTemp
                                                else:
                                                    errorMsg=errorMsg+errorMsgTemp
                                            else:
                                                errorMsgTemp=Validate().valid_values_validation_JSON(validValues2Inner,paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2)
                                                if errorMsgTemp:
                                                    if errorMsg:
                                                        errorMsg=errorMsg+","+errorMsgTemp
                                                    else:
                                                        errorMsg=errorMsg+errorMsgTemp
                                        elif (dataType2 == utilClass.readProperty('DATE_TIME')):
                                            errorMsgTemp=Validate().is_date_time(paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2,"INVALID_DATATYPE_JSON")
                                            if errorMsgTemp:
                                                if errorMsg:
                                                    errorMsg=errorMsg+","+errorMsgTemp
                                                else:
                                                    errorMsg=errorMsg+errorMsgTemp
                                            else:
                                                errorMsgTemp=Validate().valid_values_validation_JSON(validValues2Inner,paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2)
                                                if errorMsgTemp:
                                                    if errorMsg:
                                                        errorMsg=errorMsg+","+errorMsgTemp
                                                    else:
                                                        errorMsg=errorMsg+errorMsgTemp
                                        elif (dataType2 == utilClass.readProperty ('URL')):
                                            errorMsgTemp=Validate().is_url(paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2,"INVALID_DATATYPE_JSON")
                                            if errorMsgTemp:
                                                if errorMsg:
                                                    errorMsg=errorMsg+","+errorMsgTemp
                                                else:
                                                    errorMsg=errorMsg+errorMsgTemp
                                            else:
                                                errorMsgTemp=Validate().valid_values_validation_JSON(validValues2Inner,paramValueInnerTemp2,paramValueInnerTemp2,dataType2,validValues+"->"+validValues1+"->"+validValues2)
                                                if errorMsgTemp:
                                                    if errorMsg:
                                                        errorMsg=errorMsg+","+errorMsgTemp
                                                    else:
                                                        errorMsg=errorMsg+errorMsgTemp
                elif (dataType == utilClass.readProperty ('SSBOETOD')):
                    errorMsgTemp=Validate().is_ssboetod(paramValueTemp,paramValueTemp, dataType,validValues,"INVALID_DATATYPE_JSON")
                    if errorMsgTemp:
                        errorMsg=errorMsg+errorMsgTemp
                logger.debug("errorMsg=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@"+errorMsg)
        return errorMsg
    
    
    def is_ssboetod(self,Paramvalue,param, dataType,JsonDict,validValues,error_message_template):
        errorMsg=''
        utilClass=UtilClass()
        if Paramvalue:
            pass
        return errorMsg
        
                            
    '''This method used to check all data type validation'''
    def dataType_validation(self,dataType,Paramvalue,param,dict,validValues):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        e = ReturnAllDict()
        AllList = e.returnDict()
        ApiHomeDict = AllList[0]
        InputDict = AllList[1]
        SuccessDict = AllList[2]
        FailureDict = AllList[3]
        JsonDict = AllList[4]
        ListDict = AllList[5]
        errorList = []
        errorMsg=''
        #logger.debug("dataType="+param+"="+Paramvalue+"="+dataType)
        try:
            if (dataType == utilClass.readProperty('STRING')):
                errorMsg=Validate().is_string(Paramvalue,param,dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.readProperty('CHARACTER')):
                errorMsg=Validate().is_character(Paramvalue,param,dataType,validValues,"INVALID_DATATYPE")
            elif(dataType == utilClass.readProperty('NUMBER')):
                errorMsg=Validate().is_number(Paramvalue,param,dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.readProperty('DECIMAL')):
                errorMsg=Validate().is_decimal(Paramvalue,param,dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.readProperty('LIST')):
                logger.debug(validValues)
                logger.debug("JsonDict.get(validValues)")
                
                errorMsg=Validate().is_list(Paramvalue,param,dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.readProperty('DATE_TIME')):
                errorMsg=Validate().is_date_time(Paramvalue,param,dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.readProperty ('URL')):
                errorMsg=Validate().is_url(Paramvalue,param,dataType,validValues,"INVALID_DATATYPE")
            elif (dataType == utilClass.readProperty ('JSON')):
                errorMsg=Validate().is_json(Paramvalue,param, dataType,JsonDict,validValues)
                logger.debug(errorMsg)
            elif (dataType == utilClass.readProperty ('SSBOETOD')):
                errorMsg=Validate().is_ssboetod(Paramvalue,param, dataType,validValues,"INVALID_DATATYPE")
            if errorMsg:
                errorList.append (errorMsg)
            logger.debug("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@="+errorMsg)
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))    
        return errorList
    
    
    '''This method used to check url type validation'''
    def exist_Url(self,path):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            r = requests.head (path)
        except Exception as e:
            raise e   
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return r.status_code == requests.codes.ok
    
    
    '''This method used to validate date time format'''
    def validateDate(self,date_text):
        #logger.info(readProperty("ENTERING_METHOD"))
        try:
            base_date = datetime.datetime.strptime(date_text, "%Y/%m/%d/%w/%H:%M:%S")
            #time.strptime(date_text, '%m/%d/%Y/%w/%H:%M:%S')
            Date = True
        except ValueError:
            Date = False
        #logger.info(readProperty("EXITING_METHOD"))    
        return Date
    
    
    '''This method will check the input field availability and compare length of input field to expected length'''
    def validate_length_and_invalid_field(self,content,ApiName,dict):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        isErrorAvailable=False
        #print dict.get(ApiName).get(ApiName)[0].parameter
        errorList=[]
        expectList=[]
        expectMsg=''
        stat = ''
        e = ReturnAllDict()
        AllList = e.returnDict()
        ApiHomeDict = AllList[0]
        InputDict = AllList[1]
        SuccessDict = AllList[2]
        FailureDict = AllList[3]
        JsonDict = AllList[4]
        ListDict = AllList[5]

        try:
            for k, v in dict.items():
                if k == ApiName:
                    for k1, v1 in v.items():
                        for v2 in v1:
                            b = v2.parameter
                            expectList.append(b)
            logger.debug(expectList)
            expectLen=len (expectList)
            contentLen=len (content)
            logger.debug(content)
            if (expectLen < contentLen) and not dict==JsonDict:
                arrayValue = [expectLen,contentLen]
                expectMsg = Validate().create_error_message (utilClass.readProperty ("EXPECTED_AVAILABLE_PARAMETERS"), arrayValue)
                errorList.append (expectMsg)
            if not errorList:
                print "content==================",content
                for param, v in content.items():
                    if (param in expectList):
                        pass
                    else:
                        arrayValue = [param]
                        errorMsg = Validate().create_error_message (utilClass.readProperty ("INVALID_FIELD"), arrayValue)
                        errorList.append(errorMsg)
            if errorList:
                isErrorAvailable = True
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return isErrorAvailable,errorList
    
    
    '''This method will check the input for availability and format'''
    def check_input_body(self,content,ApiName,dict):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        errorAvailable=False
        errorList=[]
        stat = ''
        try:
            isInputAvailable=dict.get(ApiName)[0].inputApi
            if isInputAvailable==utilClass.readProperty("YES"):
                if content:
                    if(utilClass.readProperty('INPUT_OUTPUT_TYPE')==utilClass.readProperty ("JSON")):
                        result=utilClass.checkJson(content)
                        if result==False:
                            arrayValue = [utilClass.readProperty ("JSON")]
                            errorMsg = Validate().create_error_message (utilClass.readProperty ("BODY_INPUT_INVALID_FORMAT"), arrayValue)
                            errorList.append (errorMsg)
                    else:
                        pass#raise Exception(readProperty('111'))            
                else:
                    arrayValue = []
                    errorMsg = Validate().create_error_message (utilClass.readProperty ("BODY_INPUT_REQUIRED"), arrayValue)
                    errorList.append(errorMsg)
        
            else:
                if content:
                    arrayValue = []
                    errorMsg = Validate().create_error_message (utilClass.readProperty ("BODY_INPUT_NOT_ALLOWED"), arrayValue)
                    errorList.append (errorMsg)
        
            if errorList:
                errorAvailable = True
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return errorAvailable,errorList


    '''This method used to check  mandatory,data type,valid values validation'''
    def check_all_validate(self,content,ApiName,dict):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        isErrorAvailale=False
        errorMsg=''
        errorList=[]
        errorListAll=[]
        e = ReturnAllDict()
        expectList=[]
        AllList = e.returnDict()
        ApiHomeDict = AllList[0]
        InputDict = AllList[1]
        SuccessDict = AllList[2]
        FailureDict = AllList[3]
        JsonDict = AllList[4]
        ListDict = AllList[5]
        try:
            a=0
            logger.debug("check_all_validate=====")
            #logger.debug("ApiName"+ApiName)
            for param, v in content.items():
                expectList.append(param)
            #logger.debug(expectList)
            for k, v in dict.items():
                if k == ApiName:
                    for k1, v1 in v.items():
                        for v2 in v1:
                            b = v2.parameter
                            #logger.debug("Parameter="+b)
                            #logger.debug(dict.get(b))
                            optional= dict.get(ApiName).get(b)[0].optional
                            #logger.debug("optional====="+optional) 
                            if (optional == utilClass.readProperty('YES')):
                                #logger.debug("Yes="+b)
                                if (b in expectList):
                                    #logger.debug("In expect list")
                                    Paramvalue=content[b]
                                    #logger.debug(Paramvalue)
                                    if utilClass.isBlank(Paramvalue) :
                                        if Paramvalue is not None:
                                            arrayValue = [b]
                                            errorMsg = Validate().create_error_message (utilClass.readProperty ("MANDATORY_FIELD"), arrayValue)
                                            if errorMsg:
                                                errorList.append (errorMsg)
                                else:
                                    arrayValue = [b]
                                    errorMsg = Validate().create_error_message (utilClass.readProperty ("MANDATORY_FIELD"), arrayValue)
                                    errorList.append(errorMsg)
                                    #logger.debug(errorList)
            errorListAll.extend (errorList)
            #logger.debug("If not error list all")
            if not errorList:  
                logger.debug("No errorList")              
                for param, value in content.items():
                    a=a+1
                    logger.debug(a)
                    dataType= dict.get(ApiName).get(param)[0].dataType
                    logger.debug("dataType="+dataType)
                    validValues= dict.get(ApiName).get(param)[0].validValues
                    logger.debug("validValues="+validValues)
                    if not dict==FailureDict and not dict==JsonDict:
                        errorList=Validate().dataType_validation(dataType,value,param,dict,validValues)
                        errorListAll.extend (errorList)
                        if not errorList:
                            errorList = Validate().valid_values_validation (validValues, value, param,dataType)
                            errorListAll.extend (errorList)
                        errorList=[]
        
            if errorListAll:
                isErrorAvailale = True
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return isErrorAvailale,errorListAll
    
    
    '''This method used to check valid values validation'''
    def valid_values_validation(self,validValues,paramValue,param,dataType):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        logger.debug("!!!!!!!!!!!Inside Valid values")
        logger.debug(validValues)
        logger.debug(paramValue)
        logger.debug(param)
        logger.debug(dataType)
        errorList = []
        errorMsg=''
        try:
            #logger.debug("valid_values_validation="+validValues+"="+paramValue+"="+param+"="+dataType)
            logger.debug(dataType)
            if not (dataType == utilClass.readProperty('JSON')):
                    if not (dataType == utilClass.readProperty('LIST')):
                        logger.debug("==Inside valid values")
                        if utilClass.isBlank(validValues):
                            pass
                        else:
                            check=1
                            words = validValues.split (',')
                            for word in words:
                                if (paramValue == word):
                                    check = 0
                            if utilClass.isNotBlank(paramValue) and check==0:
                                pass
                            else:
                                arrayValue=[param,validValues,paramValue]
                                logger.debug(arrayValue)
                                errorMsg=Validate().create_error_message(utilClass.readProperty("INVALID_VALUE"),arrayValue)
                                logger.debug("After error message"+errorMsg)
                    if errorMsg:
                        errorList.append (errorMsg)
                    else:
                        logger.debug("No error message")
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))    
        return errorList


    def valid_values_validation_JSON(self,validValues,paramValue,param,dataType,validValuePath):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        logger.debug("!!!!!!!!!!!Inside Valid values")
        logger.debug(validValues)
        logger.debug(paramValue)
        logger.debug(param)
        logger.debug(dataType)
        errorList = []
        errorMsg=''
        try:
            #logger.debug("valid_values_validation="+validValues+"="+paramValue+"="+param+"="+dataType)
            if not (dataType == utilClass.readProperty('JSON')):
                if utilClass.isBlank(validValues):
                    pass
                else:
                    check=1
                    words = validValues.split (',')
                    for word in words:
                        if (paramValue == word):
                            check = 0
                    if utilClass.isNotBlank(paramValue) and check==0:
                        pass
                    else:
                        arrayValue=[param,validValues,paramValue,validValuePath]
                        logger.debug(arrayValue)
                        errorMsg=Validate().create_error_message(utilClass.readProperty("INVALID_VALUE_JSON"),arrayValue)
                        logger.debug("After error message"+errorMsg)
           # if errorMsg:
            #    errorList.append (errorMsg)
            #else:
            #    logger.debug("No error message")
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))    
        return errorMsg
    '''This method used to check validation and manipulation of the data'''
    def validation_and_manipulation(self,jsonObject,apiName,dict):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        result={}
        e = ReturnAllDict()
        AllList = e.returnDict()
        ApiHomeDict = AllList[0]
        InputDict = AllList[1]
        SuccessDict = AllList[2]
        FailureDict = AllList[3]
        JsonDict = AllList[4]
        ListDict = AllList[5]
        try:
            if(dict==InputDict):
                logger.debug("Validation parameter")
                result = Validate().validation_parameter (jsonObject, apiName, dict)
                if not result:
                    logger.debug("After manipulation_default")
                    jsonObject = Validate().manipulation_default (jsonObject, apiName, dict)
                    logger.debug("After validation_all")
                    result = Validate().validation_all (jsonObject, apiName, dict)
                if not result:
                    logger.debug("After manipulation_transformation=================")
                    logger.debug(jsonObject)
                    logger.debug(apiName)
                    logger.debug(dict)
                    jsonObject = Validate().manipulation_transformation(jsonObject, apiName, dict)
                    result=jsonObject
                    #logger.debug("result="+str(result))
            elif(dict==SuccessDict):
                logger.debug("INSIDE SUCCESS")
                result = Validate().validation_parameter (jsonObject, apiName, dict)
                logger.debug(result)
                if not result:
                    logger.debug("After validation_all in success")
                    logger.debug(jsonObject)
                    result = Validate().validation_all (jsonObject, apiName, dict)
                logger.debug(result)
                if not result:
                    logger.debug("After manipulation_transformation in success")
                    jsonObject = Validate().manipulation_transformation(jsonObject, apiName, dict)
                    result=jsonObject
                    logger.debug("result="+str(result))
            else:
                result=jsonObject
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return result
    
    
    '''This method used to manipulate transformation of the data'''
    def manipulation_transformation(self,jsonObject, apiName, dict):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        e = ReturnAllDict()
        AllList = e.returnDict()
        ApiHomeDict = AllList[0]
        InputDict = AllList[1]
        SuccessDict = AllList[2]
        FailureDict = AllList[3]
        JsonDict = AllList[4]
        ListDict = AllList[5]

        try:
            if jsonObject and  not dict==FailureDict and not dict==JsonDict:
                for param, value in jsonObject.items():
                    dataType=dict.get(apiName).get(param)[0].dataType
                    logger.debug(param)
                    logger.debug(dataType)
                    if not dataType=='JSON':
                        transformation= dict.get(apiName).get(param)[0].transformation
                        logger.debug(transformation)
                        value = Validate().transformation_validation (transformation, value)
                        jsonObject[param] = value
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return jsonObject
    
    
    '''This method used to manipulate the data to default value'''
    def manipulation_default(self,jsonObject, apiName, dict):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        e = ReturnAllDict()
        AllList = e.returnDict()
        ApiHomeDict = AllList[0]
        InputDict = AllList[1]
        SuccessDict = AllList[2]
        FailureDict = AllList[3]
        JsonDict = AllList[4]
        ListDict = AllList[5]

        try:
            if jsonObject and dict==InputDict:
                for param, value in jsonObject.items():
                    default= dict.get(apiName).get(param)[0].default
                    value = Validate().default_validation (default, value)
                    jsonObject[param]=value
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return jsonObject
    
    
    '''This method used to transform the data'''
    def transformation_validation(self,transformation,Paramvalue):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        e = ReturnAllDict()
        AllList = e.returnDict()
        ApiHomeDict = AllList[0]
        InputDict = AllList[1]
        SuccessDict = AllList[2]
        FailureDict = AllList[3]
        JsonDict = AllList[4]
        ListDict = AllList[5]
        try:
            if utilClass.isBlank(transformation):
                pass
            else:
                if utilClass.isNotBlank(Paramvalue):
                    logger.debug(transformation)
                    transformation=ListDict.get(transformation).get(Paramvalue)[0].targetValue
                    Paramvalue=transformation
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return Paramvalue
    
    
    '''This method used to check  default validation'''
    def default_validation(self,default,paramvalue):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            if utilClass.isBlank(default):
                pass
            elif(utilClass.isBlank(paramvalue)):
                paramvalue=default
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return paramvalue
    
    
    '''This method will check the input for availability and format'''
    def chk_input_availability_and_format(self,jsonObject,apiName,dict):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        result = {}
        bodyIn=True
        try:
           # if (dict == ApiHomeDict)
           param = Validate().check_input_body(jsonObject, apiName, dict)
           isError = param[0]
           errorList = param[1]
           if (isError == True):
               result = Validate().errorResponse (errorList, utilClass.readProperty("NOT_OK"))
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))        
        return  result
    
    
    '''This method used to check  parameter validation'''
    def validation_parameter(self,jsonObject,apiName,Dict):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        result = {}
        try:
            if jsonObject:
                param = Validate().validate_length_and_invalid_field (jsonObject, apiName, Dict)
                isErrorAvailable = param[0]
                errorList = param[1]
                if (isErrorAvailable == True):
                    result = Validate().errorResponse (errorList, utilClass.readProperty("NOT_OK"))
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))        
        return  result
    
    
    '''This method used to check all validation'''
    def validation_all(self,jsonObject,apiName,Dict):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        result = {}
        try:
            if jsonObject:
                dataType = Validate().check_all_validate(jsonObject, apiName, Dict)
                isErrorAvailable = dataType[0]
                errorList = dataType[1]
                if (isErrorAvailable == True):
                    result = Validate().errorResponse (errorList, utilClass.readProperty("NOT_OK"))
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return  result
    
    
    '''This method is used to create error response'''
    def errorResponse(self,errorList,stat):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        response_data = {}
        try:
            for error in errorList:
                response_data.setdefault(utilClass.readProperty("ERROR_MSG"), [])
                response_data[utilClass.readProperty("ERROR_MSG")].append(error)
                response_data[utilClass.readProperty("STATUS")] = stat
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return response_data
    
    
    '''This method will create error message using property file and place holder'''
    def create_error_message(self,errorMessage,arrayValue):
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))
        try:
            for index, item in enumerate (arrayValue):
                index = str(index)
                if type(item)==int:
                    item = str (item)
                errorMessage = errorMessage.replace ('['+index+']',item)
        except Exception as e:
            raise e
        #logger.info(utilClass.readProperty("EXITING_METHOD"))
        return  errorMessage
    
    
    '''This method is used to create error response'''
    def createErrorResponse(self,e):  
        utilClass=UtilClass()
        #logger.info(utilClass.readProperty("ENTERING_METHOD"))  
        response_data=''
        try:    
            stat = utilClass.readProperty ("NOT_OK")
            errorList = []
            errorMsg = e
            errorList.append(errorMsg)
            response_data=Validate().errorResponse(errorList,stat)
        except Exception as e:
            print "Exception",e
            raise e        
        #logger.info(utilClass.readProperty("EXITING_METHOD"))  
        return response_data