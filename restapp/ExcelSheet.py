import xlrd
from xlrd import open_workbook
import json, ast

from ExcelReadClass import *

wb = open_workbook ("E:/Investak/Habile_Investak_API_Dictionary_20161130.xlsx")


# API

class ExcelSheetApi():

    def apiHomeDict(self):

        sheet = wb.sheet_by_index(2)
        rows=sheet.nrows
        colmns=sheet.ncols

        ApiHomeDict = {}

        for rownum in range(rows):
            if rownum==0:
                continue
            hashApi = str(sheet.cell(rownum, 0).value)
            source = str(sheet.cell(rownum, 1).value)
            subject = str(sheet.cell(rownum, 2).value)
            ch = str(sheet.cell(rownum, 3).value)
            apiName = str(sheet.cell(rownum, 4).value)
            description = str(sheet.cell(rownum, 5).value)
            url = str(sheet.cell(rownum, 6).value)
            inputApi = str(sheet.cell(rownum, 7).value)
            inputEncryption = str(sheet.cell(rownum, 8).value)
            resonseEncryption = str(sheet.cell(rownum, 9).value)
            notes = (sheet.cell(rownum, 10).value).encode('utf-8').strip()
            inputSample = str(sheet.cell(rownum, 11).value)

            a=ApiClass(hashApi,source,subject,ch,apiName,description,url,inputApi,inputEncryption,resonseEncryption,notes,inputSample)

            ApiHomeDict[apiName] = [a]


        return ApiHomeDict
'''for k,v in ApiHomeDict.items():
    if k=='GetInitialKey':
        for v1 in v:
            b= v1.url
            print b'''


#INPUT

class ExcelSheetInput():

    def inputDict(self):
        sheet = wb.sheet_by_index(4)
        rows=sheet.nrows
        colmns=sheet.ncols

        InputParamDict = {}
        InputDict={}
        TempParamDict={}
        for rownum in range(rows):

            if rownum==0:
                continue
            inputColHash= str(sheet.cell(rownum,0).value)
            apiName= str(sheet.cell(rownum,1).value)
            sno =  str(sheet.cell(rownum, 2).value)
            parameter = str(sheet.cell(rownum, 3).value)
            description =(sheet.cell(rownum, 4).value).encode('utf-8').strip()
            businessTag =  str(sheet.cell(rownum, 5).value)
            dataType = str(sheet.cell(rownum, 6).value)
            validValues = str(sheet.cell(rownum, 7).value)
            optional = str(sheet.cell(rownum, 8).value)
            default = str(sheet.cell(rownum, 9).value)
            transformation = str(sheet.cell(rownum, 10).value)
            if apiName not in InputDict:
                InputDict[apiName] = {}

            i=InputClass(inputColHash,apiName,sno,parameter,description,businessTag,dataType,validValues,optional,default,transformation)
            InputParamDict[parameter] = [i]
            for k, v in InputDict.items():
                if k.__contains__(apiName):
                    TempParamDict[parameter] =  InputParamDict[parameter]
                    InputDict[apiName].update({ parameter : TempParamDict[parameter]})

        return InputDict

'''for k,v in InputDict.items():
    if k=='GetPreAuthenticationKey':
        for k1,v1 in v.items():
            if k1=='jData':
              for v2 in v1:
                  b= v2.description
                  print b'''

#SUCCESS

class ExcelSheetSuccess():

    def successDict(self):
        TempParamDict={}
        sheet = wb.sheet_by_index(5)
        rows=sheet.nrows
        colmns=sheet.ncols
        SuccessParamDict = {}
        SuccessDict = {}
        for rownum in range(rows):
            if rownum==0:
                continue
            successColHash= str(sheet.cell(rownum,0).value)
            apiName= str(sheet.cell(rownum,1).value)
            sno =  str(sheet.cell(rownum, 2).value)
            parameter = str(sheet.cell(rownum, 3).value)
            description = (sheet.cell(rownum, 4).value).encode('utf-8').strip()
            businessTag =  str(sheet.cell(rownum, 5).value)
            dataType = str(sheet.cell(rownum, 6).value)
            validValues =  str(sheet.cell(rownum, 7).value)
            optional =  str(sheet.cell(rownum, 8).value)
            transformation =  str(sheet.cell(rownum, 9).value)
            specialProcess = str(sheet.cell(rownum, 10).value)
            if apiName not in SuccessDict:
                SuccessDict[apiName] = {}
            s=SuccessClass(successColHash,apiName,sno,parameter,description,businessTag,dataType,validValues,optional,transformation,specialProcess)
            SuccessParamDict[parameter] = [s]
            for k, v in SuccessDict.items():
                if k.__contains__(apiName):
                    TempParamDict[parameter] =  SuccessParamDict[parameter]
                    SuccessDict[apiName].update({ parameter : TempParamDict[parameter]})

        return SuccessDict


#FAILURE

class ExcelSheetFailure():

    def failureDict(self):
        TempParamDict={}
        sheet = wb.sheet_by_index(6)
        rows=sheet.nrows
        colmns=sheet.ncols

        FailureParamDict = {}
        FailureDict = {}
        for rownum in range(rows):
            if rownum==0:
             continue
            failureColHash= str(sheet.cell(rownum,0).value)
            apiName= str(sheet.cell(rownum,1).value)
            sno =str(sheet.cell(rownum, 2).value)
            parameter =  str(sheet.cell(rownum, 3).value)
            description = (sheet.cell(rownum, 4).value).encode('utf-8').strip()
            dataType =  str(sheet.cell(rownum, 5).value)
            validValues =  str(sheet.cell(rownum, 6).value)
            if apiName not in FailureDict:
                FailureDict[apiName] = {}
            f = FailureClass(failureColHash, apiName, sno, parameter, description,dataType, validValues)
            FailureParamDict[parameter] = [f]
            for k, v in FailureDict.items():
                if k.__contains__(apiName):
                    TempParamDict[parameter] =  FailureParamDict[parameter]
                    FailureDict[apiName].update({ parameter : TempParamDict[parameter]})

        return FailureDict


#JSON ARRAY

class ExcelSheetJson():

    def jsonDict(self):
        TempParamDict={}
        sheet = wb.sheet_by_index(7)
        rows=sheet.nrows
        colmns=sheet.ncols
        jsonArrayDict = {}
        JsonDict = {}
        for rownum in range(rows):
            if rownum==0:
                continue
            jsonColHash= str(sheet.cell(rownum,0).value)
            arrayName= str(sheet.cell(rownum,1).value)
            sno =  str(sheet.cell(rownum, 2).value)
            parameter =  str(sheet.cell(rownum, 3).value)
            description =  (sheet.cell(rownum, 4).value).encode('utf-8').strip()
            dataType =  str(sheet.cell(rownum, 5).value)
            validValues =  str(sheet.cell(rownum, 6).value)
            if arrayName not in JsonDict:
                JsonDict[arrayName] = {}
            j=JsonArrayClass(jsonColHash,arrayName,sno,parameter,description,dataType,validValues)

            jsonArrayDict[parameter] = [j]
            for k, v in JsonDict.items():
                if k.__contains__(arrayName):
                    TempParamDict[parameter] = jsonArrayDict[parameter]
                    JsonDict[arrayName].update({parameter: TempParamDict[parameter]})

        return JsonDict
#print jsonArrayDict

