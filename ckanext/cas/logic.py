import logging
import uuid

import schema
import ckan.logic as logic
import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.logic.schema as default_schema
from ckan.lib.navl.dictization_functions import DataError
from pylons import config

log = logging.getLogger(__name__)
_check_access = logic.check_access

@logic.auth_allow_anonymous_access
def auth_user_provision(context, data_dict):
    environ = toolkit.request.environ
    secret_token_provided = environ.get('HTTP_AUTHORIZATION', None)
    if secret_token_provided:
        secret_token = config.get('ckan.user_provision.secret', '')
        if not secret_token:
            return {'success': False,
            'msg': toolkit._('Missing configuration!')}
        if secret_token == secret_token_provided:
            return {'success': True}
    else:
        return {'success': False,
                'msg': toolkit._('Missing authorization header!')}
    return {'success': False,
            'msg': toolkit._('Authorization failed! Provided secret token is invalid.')}

def user_provision(context, data_dict):
    log.info('received data on user provisiong endpoint')
    log.info(toolkit.request.environ)
    _check_access('user_provision', context, data_dict)
    actor = _create_user(data_dict, 'Actor')
    log.info('actor processed')
    subject = _create_user(data_dict, 'Subject')
    log.info('subject processed')
    #TODO vytvaranie organizacie a zaclenenie
    spr_roles = data_dict.get('SPR.Roles','')
    subject_id = data_dict['Subject.UPVSIdentityID']
    actor_id = data_dict['Actor.UPVSIdentityID']
    if 'MOD-R-PO' in spr_roles:
        org_id = data_dict['Subject.UPVSIdentityID']
        org_name = data_dict.get('Subject.Username',data_dict['Subject.UPVSIdentityID'])
        org_title = data_dict['Subject.FormattedName']
        create_organization(org_id, org_name, org_title)
    if actor and subject:
        return True
    raise DataError('Unable to provision user')

def make_password():
        # create a hard to guess password
        out = ''
        for n in xrange(8):
            out += str(uuid.uuid4())
        return out

def _create_user(data_dict, role):
    keys = {}
    keys['id'] = role + '.UPVSIdentityID'
    keys['name'] = role + '.Username'
    keys['email'] =role + '.Email'
    keys['fullname'] = role + '.FormattedName'
    userobj = model.User.get(data_dict[keys['id']])
    user_create_dict = {}
    for key, value in keys.iteritems():
        attr_value = data_dict.get(value, ['',])
        if attr_value:
            user_create_dict[key] = attr_value
        elif value.endswith('Username'):
            user_create_dict[key] = data_dict[keys['id']]
    user_schema = default_schema.default_user_schema()
    user_schema['id'] = [toolkit.get_validator('not_empty'), unicode]
    user_schema['name'] = [toolkit.get_validator('not_empty'), unicode]
    user_schema['email'] = [toolkit.get_validator('ignore_missing'), unicode]
    user_schema['password'] = [toolkit.get_validator('ignore_missing'), unicode]
    context = {'schema' : user_schema,
               'ignore_auth': True,
               'model' : model,
               'session' : model.Session}
    if userobj:
        if userobj.name != user_create_dict.get('name', '') or \
           userobj.email != user_create_dict.get('email', '') or \
           userobj.fullname != user_create_dict.get('fullname',''):
            toolkit.get_action('user_update')(context, user_create_dict)
    else:
        user_create_dict['password'] = make_password()
        toolkit.get_action('user_create')(context, user_create_dict)
    userobj = model.User.get(user_create_dict['id'])
    return userobj

def create_organization(org_id, org_name, org_title):
    org = model.Group.get(org_id)
    context = {'ignore_auth': True}
    site_user = toolkit.get_action('get_site_user')(context, {})
    c = toolkit.c
    if not org:
        log.info('creating org: %s', org_name)      
        context = {'user': site_user['name'], 'ignore_auth': True}
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
    if org_id not in members:
        # add membership
        log.info('adding member to org')            
        member_dict = {
            'id': org.id,
            'object': org_id,
            'object_type': 'user',
            'capacity': 'admin',
        }
        member_create_context = {
            'user': site_user['name'],
            'ignore_auth': True,
        }
        res = toolkit.get_action('member_create')(member_create_context, member_dict)

def user_create(context, data_dict):
    '''Create a new user.
    You must be authorized to create users.
    Wrapper around core user_create action ensures that the ECODP custom user
    schema are used.
    :param name: the name of the new user, a string between 2 and 100
        characters in length, containing only alphanumeric characters, ``-``
        and ``_``
    :type name: string
    :param email: the email address for the new user (optional)
    :type email: string
    :param password: the password of the new user, a string of at least 4
        characters
    :type password: string
    :param id: the id of the new user (optional)
    :type id: string
    :param fullname: the full name of the new user (optional)
    :type fullname: string
    :param about: a description of the new user (optional)
    :type about: string
    :param openid: (optional)
    :type openid: string
    :returns: the newly created user
    :rtype: dictionary
    '''
    new_context = context.copy()  # Don't modify caller's context
    user_schema = context.get('schema', logic.schema.default_user_schema())
    new_context['schema'] = schema.default_user_schema(user_schema)
    return logic.action.create.user_create(new_context, data_dict)


def user_update(context, data_dict):
    '''Update a user account.
    Normal users can only update their own user accounts. Sysadmins can update
    any user account.
    For further parameters see ``user_create()``.
    :param id: the name or id of the user to update
    :type id: string
    :returns: the updated user account
    :rtype: dictionary
    '''
    new_context = context.copy()  # Don't modify caller's context
    user_schema = context.get('schema',
                              logic.schema.default_update_user_schema())
    new_context['schema'] = schema.default_update_user_schema(user_schema)
    return logic.action.update.user_update(new_context, data_dict)