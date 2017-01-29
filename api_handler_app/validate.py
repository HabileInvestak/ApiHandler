class Validate():
    
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

        return Paramvalue
    
    
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
