class ApiClass(object):

   def __init__(self, hashApi, source,subject,ch,apiName,description,url,inputApi,inputEncryption,resonseEncryption,notes,inputSample):
      self.hashApi = hashApi
      self.source = source
      self.subject = subject
      self.ch = ch
      self.apiName = apiName
      self.description = description
      self.url = url
      self.inputApi = inputApi
      self.inputEncryption = inputEncryption
      self.resonseEncryption = resonseEncryption
      self.notes = notes
      self.inputSample = inputSample


class InputClass(object):

   def __init__(self, inputColHash, apiName,sno,parameter,description,businessTag,dataType,validValues,optional,default,transformation):
      self.inputColHash = inputColHash
      self.apiName = apiName
      self.sno = sno
      self.parameter = parameter
      self.description = description
      self.businessTag = businessTag
      self.dataType = dataType
      self.validValues = validValues
      self.optional = optional
      self.default = default
      self.transformation = transformation


class SuccessClass(object):

   def __init__(self, successColHash, apiName,sno,parameter,description,businessTag,dataType,validValues,optional,transformation,specialProcess):
      self.successColHash = successColHash
      self.apiName = apiName
      self.sno = sno
      self.parameter = parameter
      self.description = description
      self.businessTag = businessTag
      self.dataType = dataType
      self.validValues = validValues
      self.optional = optional
      self.transformation = transformation
      self.specialProcess = specialProcess


class FailureClass(object):

   def __init__(self, failureColHash, apiName,sno,parameter,description,dataType,validValues):
      self.failureColHash = failureColHash
      self.apiName = apiName
      self.sno = sno
      self.parameter = parameter
      self.description = description
      self.dataType = dataType
      self.validValues = validValues




class JsonArrayClass(object):

   def __init__(self,jsonColHash,arrayName,sno,parameter,description,dataType,validValues):
      self.jsonColHash = jsonColHash
      self.arrayName = arrayName
      self.sno = sno
      self.parameter = parameter
      self.description = description
      self.dataType = dataType
      self.validValues = validValues