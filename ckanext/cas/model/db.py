import datetime
import logging

from ckan.model import domain_object
from ckan.model.meta import metadata, Session, mapper
from sqlalchemy import types, Column, Table, ForeignKey, func, CheckConstraint, UniqueConstraint
import sqlalchemy.exc

log = logging.getLogger(__name__)

class LogedInUser(domain_object.DomainObject):
    def __init__(self, ticket_id, subject_id, actor_id):
        assert ticket_id
        assert subject_id
        assert actor_id
        self.ticket_id = ticket_id
        self.subject_id = subject_id
        self.actor_id = actor_id
        
    @classmethod
    def get(cls, **kw):
        '''Finds a single entity in the register.'''
        query = Session.query(cls).autoflush(False)
        return query.filter_by(**kw).all()

    @classmethod
    def dataset_lock(cls, **kw):
        '''Finds a single entity in the register.'''
        order = kw.pop('order', False)
        query = Session.query(cls).autoflush(False)
        query = query.filter_by(**kw)
        if order:
            query = query.order_by(cls.order).filter(cls.order != '')
        return query.all()
    
    @classmethod
    def delete(cls, **kw):
        query = Session.query(cls).autoflush(False).filter_by(**kw).all()
        for i in query:
            Session.delete(i)
        return

user_login_table = Table('ckanext_cas_login', metadata,
        Column('ticket_id', types.UnicodeText, primary_key=True, nullable=False),
        Column('subject_id', types.UnicodeText, default=u'', nullable=False),
        Column('actor_id', types.UnicodeText, default=u'', nullable=False),
        Column('timestamp', types.DateTime, default=datetime.datetime.utcnow, nullable=False),
        #UniqueConstraint('subject_id', 'actor_id', name='idx_subject_actor')
    )

mapper(LogedInUser, user_login_table)

def create_user_login_table():
    if not user_login_table.exists():
        user_login_table.create()

def insert_entry(ticket_id, subject_id, actor_id=None):
    create_user_login_table()
    actor_id = actor_id or subject_id
    search = {'ticket_id' : ticket_id}
    result = LogedInUser.get(**search)
    if result:
        result[0].subject_id = subject_id
        result[0].actor_id = actor_id
        result[0].save()
        return True
    try:
        new_login = LogedInUser(ticket_id, subject_id, actor_id)
        new_login.save()
        return True
    except sqlalchemy.exc.IntegrityError, exc:
        reason = exc.message
        log.error(reason)
        if reason.endswith('is not unique'):
                log.error("%s already exists",exc.params[0])
        Session.rollback()
        return False
    except Exception:
        Session.rollback()
        return False
    
def delete_entry(ticket_id):
    create_user_login_table()
    result = user_login_table.delete(LogedInUser.ticket_id==ticket_id).execute()
    log.info(result)
    
def is_ticket_valid(ticket_id):
    create_user_login_table()
    search = {'ticket_id' : ticket_id}
    results = LogedInUser.get(**search)
    if len(results) == 1:
        return True
    return False
        
    