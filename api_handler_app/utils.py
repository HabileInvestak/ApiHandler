from properties.p import Property
import logging


logger = logging.getLogger('api_handler_app.utils.py')
prop=Property()
prop_obj = prop.load_property_files('D:\\InvestAK\\26-12-2016\\investak.properties')


__revision__ = "$Id$"
__all__ = [ 'new', 'UtilClass' ]


class UtilClass():   
    
    ''' This method will read the configuration values from property file'''
    def readProperty(name):
        try:
            data=prop_obj.get(name)
            return data
        except Exception as e:
            logger.exception(e)
            raise Exception(e)