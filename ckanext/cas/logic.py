import schema
import ckan.logic as logic


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