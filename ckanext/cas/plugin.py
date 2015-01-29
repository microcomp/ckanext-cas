import logging
import uuid

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.lib.base as base
import ckan.lib.helpers as h
import ckan.logic as logic
import ckan.model as model
import ckan.logic.schema as schema

log = logging.getLogger('ckanext.cas')

def _no_permissions(context, msg):
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}


@logic.auth_sysadmins_check
def user_create(context, data_dict):
    msg = toolkit._('Users cannot be created.')
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
def user_update(context, data_dict):
    msg = toolkit._('Users cannot be edited.')
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
def user_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
def request_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)

def make_password():
        # create a hard to guess password
        out = ''
        for n in xrange(8):
            out += str(uuid.uuid4())
        return out

rememberer_name = None

def delete_cookies():
    global rememberer_name
    log.info("deleting cookies")
    if rememberer_name is None:
        plugins = toolkit.request.environ['repoze.who.plugins']
        cas_plugin = plugins.get('casauth')
        rememberer_name = cas_plugin.rememberer_name
        log.info("rememberer_name: %s", rememberer_name)
    base.response.delete_cookie(rememberer_name)
    # We seem to end up with an extra cookie so kill this too
    domain = toolkit.request.environ['HTTP_HOST']
    base.response.delete_cookie(rememberer_name, domain='.' + domain)

class CasPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IAuthenticator)
    plugins.implements(plugins.IConfigurable)
    plugins.implements(plugins.IAuthFunctions)
    
    cas_identify = None
    
    def get_auth_functions(self):
        # we need to prevent some actions being authorized.
        return {
            'user_create': user_create,
            'user_update': user_update,
            'user_reset': user_reset,
            'request_reset': request_reset,
        }
    
    def configure(self, config):
        self.cas_url = config.get('ckanext.cas.url', None)
        log.info('cas url: %s', self.cas_url)
    
    def identify(self):
        log.info('identify')
        log.debug('identify-debug')
        c = toolkit.c
        environ = toolkit.request.environ
        user = environ.get('REMOTE_USER', '')
        log.info('user %s', user)
        if not user:
            user = environ.get("repoze.who.identity", "")
            log.info("repoze.who.identity: '%s'" % user)
        
        if user:          
            identity = environ.get("repoze.who.identity", {})
            log.info('identity: %s', identity.keys())
            user_data = identity.get("attributes", {})
            log.info('user data: %s', user_data)
            if user_data:
                self.cas_identify = user_data

            if not self.cas_identify:
                log.info("redirect to logged_out")
                delete_cookies()
                h.redirect_to(controller='user', action='logged_out')
                        
            c.user = self.cas_identify['Actor.Username'][1:-1]
            c.userobj = model.User.get(c.user)
            
            if c.userobj is None:
                log.info("creating new user")
                # Create the user
                data_dict = {
                    'password': make_password(),
                    'name' : self.cas_identify['Actor.Username'][1:-1],
                    'email' : self.cas_identify['Actor.Email'][1:-1],
                    'fullname' : self.cas_identify['Actor.FormattedName'][1:-1],
                    'id' : self.cas_identify['Actor.UPVSIdentityID'][1:-1]
                }
                #self.update_data_dict(data_dict, self.user_mapping, saml_info)
                # Update the user schema to allow user creation
                user_schema = schema.default_user_schema()
                user_schema['id'] = [toolkit.get_validator('not_empty')]
                user_schema['name'] = [toolkit.get_validator('not_empty')]
                user_schema['email'] = [toolkit.get_validator('ignore_missing')]

                context = {'schema' : user_schema, 'ignore_auth': True}
                user = toolkit.get_action('user_create')(context, data_dict)
                c.userobj = model.User.get(c.user)
        
    def login(self):
        log.info('login')
        if not toolkit.c.user:
            # A 401 HTTP Status will cause the login to be triggered
            return base.abort(401, toolkit._('Login required!'))
        log.info("redirect to dashboard")
        h.redirect_to(controller='user', action='dashboard')
        
    def logout(self):
        log.info('logout')
        environ = toolkit.request.environ
        #subject_id = environ["repoze.who.identity"]['repoze.who.userid']
        client = environ['repoze.who.plugins']["casauth"]
        identity = environ['repoze.who.identity']
        client.forget(environ, identity)
        delete_cookies()
        h.redirect_to(controller='user', action='logged_out')
        
    def abort(self, status_code, detail, headers, comment):
        log.info('abort')
        if (status_code == 401 and toolkit.request.environ['PATH_INFO'] != '/user/login'):
                c = toolkit.c
                c.code = 401
                c.content = toolkit._('You are not authorized to do this')
                return toolkit.render('error_document_template.html')
        return (status_code, detail, headers, comment)
    
    def create_organization(self, org_name):
        org = model.Group.get(org_name)
        context = {'ignore_auth': True}
        site_user = toolkit.get_action('get_site_user')(context, {})
        c = toolkit.c

        if not org:
            context = {'user': site_user['name']}
            data_dict = {
            }
            org = toolkit.get_action('organization_create')(context, data_dict)
            org = model.Group.get(org_name)

        # check if we are a member of the organization
        data_dict = {
            'id': org.id,
            'type': 'user',
        }
        members = toolkit.get_action('member_list')(context, data_dict)
        members = [member[0] for member in members]
        if c.userobj.id not in members:
            # add membership
            member_dict = {
                'id': org.id,
                'object': c.userobj.id,
                'object_type': 'user',
                'capacity': 'member',
            }
            member_create_context = {
                'user': site_user['name'],
                'ignore_auth': True,
            }

            toolkit.get_action('member_create')(member_create_context, member_dict)



