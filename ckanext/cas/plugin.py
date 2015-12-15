import logging
import uuid
from xml.etree import ElementTree

import pylons
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.lib.base as base
import ckan.lib.helpers as h
import ckan.logic as logic
import ckan.model as model
import ckan.lib.i18n as i18n
import ckan.logic.schema as schema
from ckan.common import request, response
import logic as custom_logic
from model.db import insert_entry, delete_entry, is_ticket_valid

log = logging.getLogger('ckanext.cas')
CAS_NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:protocol'
CAS_NAMESPACE_PREFIX = '{{{}}}'.format(CAS_NAMESPACE)
XML_NAMESPACES = {'samlp': CAS_NAMESPACE}

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
    base.response.delete_cookie(rememberer_name)
    # We seem to end up with an extra cookie so kill this too
    domain = toolkit.request.environ['HTTP_HOST']
    base.response.delete_cookie(rememberer_name, domain='.' + domain)
    
def retrieve_actor_name():
    environ = toolkit.request.environ
    session = environ['beaker.session']
    actor_id = session.get('ckanext-cas-actorid', None)
    if actor_id:
        userobj = model.User.get(actor_id)
        if userobj:
            return userobj.fullname
    return None

def delete_session_items():
    '''Delete any session items created by this plugin.'''
    keys_to_delete = [key for key in pylons.session
                      if key.startswith('ckanext-cas-')]
    if keys_to_delete:
        for key in keys_to_delete:
            del pylons.session[key]
        pylons.session.save()

class CasPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IAuthenticator)
    plugins.implements(plugins.IConfigurable)
    plugins.implements(plugins.IAuthFunctions)
    plugins.implements(plugins.IRoutes, inherit = True)
    plugins.implements(plugins.ITemplateHelpers, inherit=False)
    plugins.implements(plugins.IActions)

    def get_actions(self):
        return {'user_provision' : custom_logic.user_provision}
    
    def get_helpers(self):
        return {'retrieve_actor_name' : retrieve_actor_name}
    
    def before_map(self, map):
        map.connect(
            'cas_unauthorized',
            '/access_unauthorized',
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
            'upvs_user_update': upvs_user_update,
            'user_provision' : custom_logic.auth_user_provision
        }
    
    def configure(self, config):
        self.ckan_url = config.get('ckan.site_url', None)

    def _create_user(self, data_dict, role):
        keys = {}
        keys['id'] = role + '.UPVSIdentityID'
        keys['name'] = role + '.Username'
        keys['email'] =role + '.Email'
        keys['fullname'] = role + '.FormattedName'
        userobj = model.User.get(data_dict[keys['id']][0])
        user_create_dict = {}
        for key, value in keys.iteritems():
            attr_value = data_dict.get(value, ['',])[0]
            if attr_value:
                user_create_dict[key] = attr_value
            elif value.endswith('Username'):
                user_create_dict[key] = data_dict[keys['id']][0]
        user_schema = schema.default_user_schema()
        user_schema['id'] = [toolkit.get_validator('not_empty'), unicode]
        user_schema['name'] = [toolkit.get_validator('not_empty'), unicode]
        user_schema['email'] = [toolkit.get_validator('ignore_missing'), unicode]
        user_schema['password'] = [toolkit.get_validator('ignore_missing'), unicode]
        context = {'schema' : user_schema,
                   'ignore_auth': True,
                   'model' : model,
                   'session' : model.Session}
        log.info('actual user: %s' , userobj)
        log.info('new user: %s', user_create_dict)
        if userobj:
            same_name = userobj.name == user_create_dict.get('name', None)
            same_email = userobj.email == user_create_dict.get('email', None)
            same_fullname = userobj.fullname == user_create_dict.get('fullname', None)
            log.info('compare result: %s, %s, %s', same_name, same_email, same_fullname)
            if unicode(userobj.name) != unicode(user_create_dict.get('name', None)) or \
               userobj.email != user_create_dict.get('email', None) or \
               unicode(userobj.fullname) != unicode(user_create_dict.get('fullname',None)):
                if data_dict.get(keys['name'], ''):
                    del user_create_dict['name']
                user_schema['name'] = [toolkit.get_validator('ignore_missing'), unicode]
                toolkit.get_action('user_update')(context, user_create_dict)
        else:
            user_create_dict['password'] = make_password()
            toolkit.get_action('user_create')(context, user_create_dict)
        userobj = model.User.get(user_create_dict['id'])
        return userobj
      
    def identify(self):
        log.info('identify')
        #set language as default to be able to translate flash messages
        i18n.set_lang('sk')
        c = toolkit.c
        environ = toolkit.request.environ
        user = environ.get('REMOTE_USER', '')
        log.info('environ user %s', user)
        if user:
            identity = environ.get("repoze.who.identity", {})
            user_data = identity.get("attributes", {})
            ticket = identity.get("ticket", '')
            user_id = identity.get("repoze.who.userid")
            if not (user_data or user_id):
                log.info("redirect to logged_out")
                delete_cookies()
                return h.redirect_to(controller='user', action='logged_out')
            
            if not user_data:
                user_ticket = pylons.session.get('ckanext-cas-ticket', '')
                if user_ticket:
                    if is_ticket_valid(user_ticket):
                        c.userobj = model.User.get(user_id)
                    else:
                        log.info("redirect to logged_out")
                        environ['REMOTE_USER'] = None
                        environ['repoze.who.identity'] = None
                        delete_cookies()
                        h.flash_notice(toolkit._('You were logged out in another app'))
                        return #h.redirect_to(controller='home', action='index')
                else:
                    c.userobj = model.User.get(user_id)
            else:
                subject_id = user_data['Subject.UPVSIdentityID'][0]
                actor_id = user_data['Actor.UPVSIdentityID'][0]
                success = insert_entry(ticket, subject_id, actor_id)
                if not success:
                    log.info("same ticket in DB - consistency error")
                pylons.session['ckanext-cas-ticket'] = ticket
                pylons.session.save()
                self._create_user(user_data, 'Actor')
                if actor_id!=subject_id:
                    self._create_user(user_data, 'Subject')
                    log.debug('jedna sa o zastupovanie subjectu %s actorom %s', subject_id, actor_id)
                    spr_roles = user_data.get('SPR.Roles','')
                    if self._subject_is_org(subject_id) and not 'MOD-R-PO' in spr_roles:
                        identity["repoze.who.userid"] = actor_id
                        pylons.session['ckanext-cas-actorid'] = subject_id
                        pylons.session.save()
                        c.userobj = model.User.get(actor_id)
                        h.flash_notice(toolkit._('You are not allowed to act as {0} in data.gov.sk').format(user_data['Subject.FormattedName'][0]))
                    else:
                        identity["repoze.who.userid"] = subject_id
                        pylons.session['ckanext-cas-actorid'] = actor_id
                        pylons.session.save()
                        c.userobj = model.User.get(subject_id)
                else:
                    c.userobj = model.User.get(subject_id)
                                    
            #set c.user -> CKAN logic
            log.debug('c.userobj: %s',c.userobj)
            c.user = c.userobj.name


            if user_data:
                spr_roles = user_data.get('SPR.Roles','')
                subject_id = user_data['Subject.UPVSIdentityID'][0]
                actor_id = user_data['Actor.UPVSIdentityID'][0]
                log.debug("SPR roles: %s", spr_roles)
                pylons.session['ckanext-cas-roles'] = spr_roles
                pylons.session.save()
                if 'MOD-R-PO' in spr_roles:
                    org_id = user_data['Subject.UPVSIdentityID'][0]
                    org_name = user_data.get('Subject.Username',user_data['Subject.UPVSIdentityID'])[0]
                    org_title = user_data['Subject.FormattedName'][0]
                    self.create_organization(org_id, org_name, org_title)
                if c.user:
                    toolkit.get_action('auditlog_send')(data_dict={'event_name' : 'user_login',
                                                                   'subject' : user_data['Subject.UPVSIdentityID'][0],
                                                                   'authorized_user' : user_data['Actor.UPVSIdentityID'][0],
                                                                   'description' : 'User login to CKAN from IP {0}'.format(environ.get('REMOTE_ADDR', '')),
                                                                   'object_reference' : 'UserID://' + user_data['Subject.UPVSIdentityID'][0],
                                                                   'debug_level' : 2,
                                                                   'error_code' : 0})
                else:
                    toolkit.get_action('auditlog_send')(data_dict={'event_name' : 'user_login',
                                                                   'subject' : user_data['Subject.UPVSIdentityID'][0],
                                                                   'authorized_user' : user_data['Actor.UPVSIdentityID'][0],
                                                                   'description' : 'User login to CKAN from IP {0}'.format(environ.get('REMOTE_ADDR', '')),
                                                                   'object_reference' : 'UserID://' + user_data['Subject.UPVSIdentityID'][0],
                                                                   'debug_level' : 1,
                                                                   'error_code' : 1})
        else:
            delete_session_items()
        
    def login(self):
        log.info('login')
        environ = toolkit.request.environ
        if environ.get('REQUEST_METHOD', '') == 'POST':
            data = toolkit.request.POST
            message = data.get('logoutRequest', None)
            parsed = ElementTree.fromstring(message)
            sessionIndex = parsed.find('samlp:SessionIndex', XML_NAMESPACES)
            if sessionIndex is not None:
                delete_entry(sessionIndex.text)
        else:
            if not toolkit.c.user:
                # A 401 HTTP Status will cause the login to be triggered
                log.info('login required')
                return base.abort(401)
                #return base.abort(401, toolkit._('Login is required!'))
            log.info("redirect to dashboard")
            h.redirect_to(controller='user', action='dashboard')
        
    def logout(self):
        log.info('logout')
        environ = toolkit.request.environ
        if toolkit.c.user:
            #invalidate ticket to keepdb table up to date
            user_ticket = pylons.session.get('ckanext-cas-ticket', '')
            if user_ticket:
                delete_entry(user_ticket)
                log.info('ticket invalidated')
            environ = toolkit.request.environ
            subject_id = environ["repoze.who.identity"]['repoze.who.userid']
            plugins = environ['repoze.who.plugins']
            client_auth = environ['repoze.who.plugins']["auth_tkt"]
            headers_logout = client_auth.forget(environ, subject_id)
            client_cas = environ['repoze.who.plugins']["casauth"]
            client_cas.forget(environ, subject_id)
            environ['rwpc.logout'] = self.ckan_url
            delete_cookies()
            toolkit.get_action('auditlog_send')(data_dict={'event_name' : 'user_logout',
                                               'subject' : subject_id,
                                               'authorized_user' : pylons.session.get('ckanext-cas-actorid') if pylons.session.get('ckanext-cas-actorid', '') else subject_id,
                                               'description' : 'User loged out from CKAN using IP {0}'.format(environ.get('REMOTE_ADDR', '')),
                                               'object_reference' : 'UserID://' + subject_id,
                                               'debug_level' : 2,
                                               'error_code' : 0})
        
    def abort(self, status_code, detail, headers, comment):
        log.info('abort')
        #if (status_code == 401 and (toolkit.request.environ['PATH_INFO'] != '/user/login' or toolkit.request.environ['PATH_INFO'] != '/user/_logout')):
        #        h.redirect_to('cas_unauthorized', message = detail)
        return (status_code, detail, headers, comment)
    
    def _subject_is_org(self, subject):
        org = model.Group.get(subject) or model.Group.get(subject.lower())
        if org:
            return True
        return False
        
        
    def create_organization(self, org_id, org_name, org_title):
        org = model.Group.get(org_name.lower())
        context = {'ignore_auth': True}
        site_user = toolkit.get_action('get_site_user')(context, {})
        c = toolkit.c
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
            res = toolkit.get_action('member_create')(member_create_context, member_dict)
          
class CasController(base.BaseController):

    def cas_unauthorized(self):
        # This is our you are not authorized page
        data = request.GET
        detail = data.get('message', '')
        c = toolkit.c
        c.code = [403]
        response.status_int = 403
        if detail:
            c.content = detail
        else:
            c.content = toolkit._('You are not authorized to do this')
        return toolkit.render('error_document_template.html')