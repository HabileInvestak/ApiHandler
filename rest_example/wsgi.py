"""
WSGI config for rest_example project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/1.10/howto/deployment/wsgi/
"""

import os
from restapp.ExcelSheet import *
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "rest_example.settings")
application = get_wsgi_application()

ApiHomeDict = {}
ListOfDict=[]
a = ExcelSheetApi()
i = ExcelSheetInput()
s = ExcelSheetSuccess()
f = ExcelSheetFailure()
j = ExcelSheetJson()
ApiHomeDict = a.apiHomeDict()
InputDict = i.inputDict()
SuccessDict = s.successDict()
FailureDict = f.failureDict()
JsonDict = j.jsonDict()
ListOfDict=[ApiHomeDict,InputDict,SuccessDict,FailureDict,JsonDict]
#print ListOfDict
print "call Loading dictioanry from excel once deployment"
class ReturnAllDict:
    def returnDict(self):
        #print "Inside function ",ApiHomeDict
        return ListOfDict