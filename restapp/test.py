from properties.p import Property

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
for index, item in enumerate (arrayValue):
    index = str(index)
    if type(item)==int:
        item = str(item)
    newstr = string.replace('['+index+']',item)
    string = newstr
print string

