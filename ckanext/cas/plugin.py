import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

class CasPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IAuthenticator)
    
    def identify(self):
        pass
    def login(self):
        pass
    def logout(self):
        pass
    def abort(self, status_code, detail, headers, comment):
        pass