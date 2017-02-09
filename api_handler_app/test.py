from properties.p import Property
import json
output=[{u'Status': u'rejected', u'stat': u'Ok', u'Nstordno': u'170126000000002', u'Exchange': u'BSE', u'Symbol': u'500477', u'ExchSeg': u'bse_cm', u'Trsym': u'ASHOKLEY'}, {u'Status': u'rejected', u'stat': u'Ok', u'Nstordno': u'170126000000001', u'Exchange': u'BSE', u'Symbol': u'500477', u'ExchSeg': u'bse_cm', u'Trsym': u'ASHOKLEY'}]
#output={'Status': 'rejected'}
 #find json array
if type(output) is list:
    print 'list'
    print len(output)
    for dict in output:
        print dict
else:
    print 'no list it is dict'

# if returns true, then JSON Array
#print 'list',isintance(output, list)

# if returns true, then JSON Object.
#print 'dict',isintance(output, dict)



content={u'stat': u'Not_Ok', u'Emsg': u'Session Expired'}
for param, value in content.items():
    print 'validValues', value

#string = "[0]  Invalid value. expected [1] available [2]"
param='logDevice'
validValues='AND,IOS'
paramValue='A'
ArrayValue=[param,validValues,paramValue]
arrlen=len(ArrayValue)


prop = Property ()
#prop_obj = prop.load_property_files('D:\\InvestAK\\investak.properties')  #hari
prop_obj = prop.load_property_files ('E:\\Investak\\investak\\investak.properties')  # ranjith

def readProperty(name):
    data=prop_obj.get (name)
    return data


arrayValue = ['hi','none']
#expectMsg = errorMsgCreate(readProperty('109'), arrayValue)

string=readProperty('109')
print 'string ',string
try:
    for index, item in enumerate (arrayValue):
        index = index
        if type(item)==int:
            item = str(item)
        newstr = string.replace('['+index+']',item)
        string = newstr
    print string
except Exception as e:
    print "exception is ",e
    #sendResponse(e)

    stat = readProperty ('NOT_OK')
    errorList = []
    errorMsg = e
    print errorMsg
    errorList.append(errorMsg)
    #sendErrorRequesterror(errorList,stat)

i=len(errorList)
print i
response_data = {}
for v in errorList:

    response_data.setdefault(readProperty('ERROR_MSG'),[])
    response_data[readProperty('ERROR_MSG')].append(v)
    response_data[readProperty('STATUS')] = stat

print 'response_data',response_data
print response_data