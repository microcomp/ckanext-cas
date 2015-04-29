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

def upvs_user_update(context, data_dict):
    user = context['user']

    # FIXME: We shouldn't have to do a try ... except here, validation should
    # have ensured that the data_dict contains a valid user id before we get to
    # authorization.
    try:
        user_obj = logic.auth.get_user_object(context, data_dict)
    except logic.NotFound:
        return {'success': False, 'msg': toolkit._('User not found')}

    if user == user_obj.name:
        # Allow users to update their own user accounts.
        return {'success': True}
    return {'success': False,
                'msg': toolkit._('Permission denied!')}



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
    plugins.implements(plugins.IRoutes, inherit = True)
    cas_identify = None
    
    def before_map(self, map):
        map.connect(
            'cas_unauthorized',
            '/cas_unauthorized',
            controller='ckanext.cas.plugin:CasController',
            action='cas_unauthorized'
        )
        return map
    
    
    def get_auth_functions(self):
        # we need to prevent some actions being authorized.
        return {
            'user_create': user_create,
            'user_update': user_update,
            'user_reset': user_reset,
            'request_reset': request_reset,
            'upvs_user_update': upvs_user_update
        }
    
    def configure(self, config):
        self.cas_url = config.get('ckanext.cas.url', None)
        self.ckan_url = config.get('ckan.site_url', None)
        log.info('cas url: %s', self.cas_url)
    
    def identify(self):
        log.info('identify')
        c = toolkit.c
        environ = toolkit.request.environ
        user = environ.get('REMOTE_USER', '')
        log.info('environ user %s', user)
        log.info('c.user: %s', c.user)
        if user:
            who = environ.get("repoze.who", {})
            log.info('repoze.who content: %s', who)
            identity = environ.get("repoze.who.identity", {})
            user_data = identity.get("attributes", {})
            user_id = identity.get("repoze.who.userid")
            actor_id = identity.get("repoze.who.actorid", None)
            log.info('attributes: %s', user_data)
            log.info('repoze.who user id : %s', user_id)
            log.info('repoze.who actor id : %s', actor_id)
            
            if not (user_data or user_id):
                log.info("redirect to logged_out")
                delete_cookies()
                h.redirect_to(controller='user', action='logged_out')
            
            if not user_data:
                c.userobj = model.User.get(user_id)
            else:
                spr_roles = user_data.get('SPR.Roles','')
                delegation_type = user_data.get('DelegationType', -1)
                subject_identity_type = user_data.get('Subject.IdentityType', -1)
                if 'MOD-R-PO' in spr_roles and delegation_type != 0 and subject_identity_type==6:
                    log.info('povinna osoba zastupuje org')
                    identity["repoze.who.actorid"] = user_id
                    identity["repoze.who.userid"] = user_data['Subject.UPVSIdentityID'][0]
                    c.userobj = model.User.get(user_data['Subject.UPVSIdentityID'][0])
                else:
                    log.info('nepovinna osoba zastupuje org')
                    c.userobj = model.User.get(user_id)
                
            if c.userobj is None:
                log.info("creating new user")
                # Create the user
                spr_roles = user_data.get('SPR.Roles', [])
                delegation_type = user_data.get('DelegationType', -1)
                subject_identity_type = user_data.get('Subject.IdentityType', -1)
                if 'MOD-R-PO' in spr_roles and delegation_type != 0 and subject_identity_type==6:
                    log.info('user is org')
                    #this user will be logged in as a subject
                    identity["repoze.who.userid"] = user_data['Subject.UPVSIdentityID'][0]
                    data_dict = {
                    'password': make_password(),
                    'fullname' : user_data['Subject.FormattedName'][0],
                    'id' : user_data['Subject.UPVSIdentityID'][0]
                    }
                    if user_data.get('Subject.Username', []):
                        data_dict['name'] = user_data['Subject.Username'][0]
                    else:
                        data_dict['name'] = user_data['Subject.UPVSIdentityID'][0]
                    if user_data.get('Subject.Email', []):
                        data_dict['email'] = user_data['Subject.Email'][0]

                else:
                    log.info('user is FO')
                    data_dict = {
                        'password': make_password(),
                        'fullname' : user_data['Actor.FormattedName'][0],
                        'id' : user_data['Actor.UPVSIdentityID'][0]
                    }
                    if user_data.get('Actor.Username', []):
                        data_dict['name'] = user_data['Actor.Username'][0]
                    else:
                        data_dict['name'] = user_id
                    if user_data.get('Actor.Email', []):
                        data_dict['email'] = user_data.get['Actor.Email'][0]
                log.info('data for creating user: %s', data_dict)
                # Update the user schema to allow user creation
                user_schema = schema.default_user_schema()
                user_schema['id'] = [toolkit.get_validator('not_empty'), unicode]
                user_schema['name'] = [toolkit.get_validator('not_empty'), unicode]
                user_schema['email'] = [toolkit.get_validator('ignore_missing'), unicode]

                context = {'schema' : user_schema, 'ignore_auth': True}
                user = toolkit.get_action('user_create')(context, data_dict)
                c.userobj = model.User.get(data_dict['id'])
            #set c.user -> CKAN logic
            log.info('c.userobj: %s',c.userobj)
            c.user = c.userobj.name

            if user_data:
                role = toolkit.get_action('enum_roles')()
                spr_roles = user_data.get('SPR.Roles','')
                log.info("SPR roles: %s", spr_roles)
                for spr_role in spr_roles:
                    delegation_type = user_data.get('DelegationType', -1)
                    subject_identity_type = user_data.get('Subject.IdentityType', -1)
                    if 'MOD-R-PO' == spr_role and delegation_type != 0 and delegation_type==6:
                        org_id = user_data['Subject.UPVSIdentityID'][0]
                        org_name = user_data['Subject.UPVSIdentityID'][0]
                        org_title = user_data['Subject.FormattedName'][0]
                        self.create_organization(org_id, org_name, org_title)
                    
                    if 'MOD-R-MODER' == spr_role and delegation_type==0:
                        group = model.Group.get(role.ROLE_MODERATOR.lower())
                        if not group:
                            group = self._create_group_help(role.ROLE_MODERATOR)
                        member = self.is_member(role.ROLE_MODERATOR, c.userobj.id)
                        if not member:
                            self._add_member(group.id, c.userobj.id)
                            
                    if 'MOD-R-DATA' == spr_role and delegation_type==0:
                        self.create_group(role.ROLE_DATA_CURATOR)
                        
                    if 'MOD-R-APP' == spr_role and delegation_type==0:
                        self.create_group(role.ROLE_APP_ADMIN)
                    
                    if 'MOD-R-TRANSA' == spr_role and delegation_type==0:
                        self.create_group(role.ROLE_SPRAVCA_TRANSFORMACII)
        
    def login(self):
        log.info('login')
        if not toolkit.c.user:
            # A 401 HTTP Status will cause the login to be triggered
            log.info('login required')
            return base.abort(401)
            #return base.abort(401, toolkit._('Login is required!'))
        log.info("redirect to dashboard")
        h.redirect_to(controller='user', action='dashboard')
        
    def logout(self):
        log.info('logout')
        if toolkit.c.user:
            log.info('logout abort')
            environ = toolkit.request.environ
            log.info('environ: %s', environ)
            subject_id = environ["repoze.who.identity"]['repoze.who.userid']
            client_auth = environ['repoze.who.plugins']["auth_tkt"]
            log.info('auth tkt methods: %s', dir(client_auth))
            client_cas = environ['repoze.who.plugins']["casauth"]
            log.info('cas methods: %s', dir(client_cas))
            environ['rwpc.logout']= self.ckan_url
            #return base.abort(401)
            #log.info('logout')
            #environ = toolkit.request.environ
            #log.info('environ: %s', environ)
            ##subject_id = environ["repoze.who.identity"]['repoze.who.userid']
            #client = environ['repoze.who.plugins']["casauth"]
            #identity = environ['repoze.who.identity']
            #client.forget(environ, identity)
            
            #delete_cookies()
            #h.redirect_to(controller='user', action='logged_out')
        
    def abort(self, status_code, detail, headers, comment):
        log.info('abort')
        if (status_code == 401 and (toolkit.request.environ['PATH_INFO'] != '/user/login' or toolkit.request.environ['PATH_INFO'] != '/user/_logout')):
                h.redirect_to('cas_unauthorized')
        return (status_code, detail, headers, comment)
    
    def _is_member(self, group_id, user_id):
        context = {'ignore_auth': True}
        data_dict = {
            'id': group_id,
            'object_type': 'user',
        }
        members = toolkit.get_action('member_list')(context, data_dict)
        members = [member[0] for member in members]
        if user_id in members:
            return True
        return False
        
    def _remove_member(self, group_id, member_id):
        c = toolkit.c
        context = {'ignore_auth': True}
        data_dict = {'id' : group_id,
                     'object' : member_id,
                     'object_type' : 'user'}
        toolkit.get_action('member_delete')(context, data_dict)
        
    def _add_member(self, group_id, user_id):
        context = {'ignore_auth': True}
        site_user = toolkit.get_action('get_site_user')(context, {})
        member_dict = {
            'id': group_id,
            'object': user_id,
            'object_type': 'user',
            'capacity': 'member',
        }
        member_create_context = {
            'user': site_user['name'],
            'ignore_auth': True,
        }
        toolkit.get_action('member_create')(member_create_context, member_dict)

    def _create_group_help(self, group_name):
        group = model.Group.get(group_name.lower())
        context = {'ignore_auth': True}
        site_user = toolkit.get_action('get_site_user')(context, {})
        c = toolkit.c
        log.info('site user: %s', site_user)
        if not group:
            log.info('creating group: %s', group_name)      
            context = {'user': site_user['name']}
            data_dict = {'name': group_name.lower(),
                         'title': group_name
            }
            group = toolkit.get_action('group_create')(context, data_dict)
            group = model.Group.get(group_name.lower())
        return group

    def create_group(self, group_name):
        group = model.Group.get(group_name.lower())
        context = {'ignore_auth': True}
        site_user = toolkit.get_action('get_site_user')(context, {})
        c = toolkit.c
        log.info('site user: %s', site_user)
        if not group:
            log.info('creating group: %s', group_name)      
            context = {'user': site_user['name']}
            data_dict = {'name': group_name.lower(),
                         'title': group_name
            }
            group = toolkit.get_action('group_create')(context, data_dict)
            group = model.Group.get(group_name.lower())

        # check if we are a member of the organization
        data_dict = {
            'id': group.id,
            'object_type': 'user',
        }
        members = toolkit.get_action('member_list')(context, data_dict)
        members = [member[0] for member in members]
        if c.userobj.id not in members:
            log.info('adding member to group')
            # add membership
            member_dict = {
                'id': group.id,
                'object': c.userobj.id,
                'object_type': 'user',
                'capacity': 'member',
            }
            member_create_context = {
                'user': site_user['name'],
                'ignore_auth': True,
            }

            toolkit.get_action('member_create')(member_create_context, member_dict)

    
    def create_organization(self, org_id, org_name, org_title):
        org = model.Group.get(org_name.lower())
        context = {'ignore_auth': True}
        site_user = toolkit.get_action('get_site_user')(context, {})
        c = toolkit.c
        #log.info('site user: %s', site_user)
        if not org:
            log.info('creating org: %s', org_name)      
            context = {'user': c.userobj.name, 'ignore_auth': True}
            data_dict = {'id' : org_id,
                         'name': org_name.lower(),
                         'title': org_title
            }
            org = toolkit.get_action('organization_create')(context, data_dict)
            org = model.Group.get(org_name.lower())

        # check if we are a member of the organization
        data_dict = {
            'id': org.id,
            'object_type': 'user',
        }
        members = toolkit.get_action('member_list')(context, data_dict)
        members = [member[0] for member in members]
        if c.userobj.id not in members:
            # add membership
            log.info('adding member to org')            
            member_dict = {
                'id': org.id,
                'object': c.userobj.id,
                'object_type': 'user',
                'capacity': 'admin',
            }
            member_create_context = {
                'user': site_user['name'],
                'ignore_auth': True,
            }
            log.info('data for creating member in org %s: %s', org_title, member_dict)
            res = toolkit.get_action('member_create')(member_create_context, member_dict)
            log.info('result of member_create: %s', res)
            
class CasController(base.BaseController):

    def cas_unauthorized(self):
        # This is our you are not authorized page
        c = toolkit.c
        c.code = 401
        c.content = toolkit._('You are not authorized to do this')
        return toolkit.render('error_document_template.html')

#     def slo(self):
#         environ = toolkit.request.environ
#         # so here I might get either a LogoutResponse or a LogoutRequest
#         client = environ['repoze.who.plugins']['casauth']
#         if 'QUERY_STRING' in environ:
#             saml_resp = toolkit.request.GET.get('SAMLResponse', '')
#             saml_req = toolkit.request.GET.get('SAMLRequest', '')
# 
#             if saml_req:
#                 log.info('SAML REQUEST for logout recieved')
#                 get = toolkit.request.GET
#                 subject_id = environ["repoze.who.identity"]['repoze.who.userid']
#                 headers, success = client.saml_client.do_http_redirect_logout(get, subject_id)
#                 h.redirect_to(headers[0][1])
#             elif saml_resp:
#              ##   # fix the cert so that it is on multiple lines
#              ##   out = []
#              ##   # if on multiple lines make it a single one
#              ##   line = ''.join(saml_resp.split('\n'))
#              ##   while len(line) > 64:
#              ##       out.append(line[:64])
#              ##       line = line[64:]
#              ##   out.append(line)
#              ##   saml_resp = '\n'.join(out)
#              ##   try:
#              ##       res = client.saml_client.logout_request_response(
#              ##           saml_resp,
#              ##           binding=BINDING_HTTP_REDIRECT
#              ##       )
#              ##   except KeyError:
#              ##       # return error reply
#              ##       pass
# 
#                 delete_cookies()
#                 h.redirect_to(controller='user', action='logged_out')




