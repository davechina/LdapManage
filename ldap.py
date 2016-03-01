# -*-coding:utf8 -*-

from ldap3 import (
    Server,
    Connection,
    AUTO_BIND_NO_TLS,
    AUTH_SIMPLE,
    ALL,
    SUBTREE,
    ALL_ATTRIBUTES,
    STRATEGY_SYNC,
    MODIFY_REPLACE
)

__author__ = 'lqs'


class LdapQuery:
    # In default configuration of access control, only rootdn can modify a
    # user's entries.
    # Refers to: http://www.openldap.org/doc/admin24/access-control.html
    def __init__(self, host, user, password, port=389):
        self.server = Server(host=host,
                             port=port,
                             get_info=ALL,
                             connect_timeout=5,
                             allowed_referral_hosts=[('*', True)])

        try:
            self.conn = Connection(self.server,
                                   user=user,
                                   password=str(password),
                                   authentication=AUTH_SIMPLE,
                                   auto_bind=AUTO_BIND_NO_TLS,
                                   client_strategy=STRATEGY_SYNC)
            # self.login = self.conn.extend.standard.who_am_i()
        except Exception:
            raise

    def query(self,
              base='',
              filters='',
              attributes=ALL_ATTRIBUTES,
              scope=SUBTREE):
        with self.conn as c:
            c.search(
                search_base=base,
                search_filter=filters,
                attributes=attributes,
                search_scope=scope,
            )

            return c.response

    def add(self, dn, objects=None, attributes=None, controls=None):
        with self.conn as c:
            c.add(dn, objects, attributes, controls)
            return c.result

    def delete(self, dn):
        with self.conn as c:
            c.delete(dn)
            return c.result

    # new_attrs is a dict, need not provide an old_value
    # if old_value does not exist, will create attributes; if old_value exists and new_value is None, will delete attributes.

    # changes is a dictionary in the form
    # {‘attribute1’: [(operation, [val1, val2, ...]), (operation2, [val1, val2, ...]), ...], ‘attribute2’: [(operation, [val1, val2, ...])], ...}

    # Use method MODIFY_REPLACE for all operations: add, delete, replace.
    def modify(self, dn, attrs, controls=None):
        changes = {}
        for k, v in attrs.items():
            assert isinstance(v, list)
            changes.update({k: (MODIFY_REPLACE, v)})

        with self.conn as c:
            c.modify(dn, changes, controls)
            return c.result

    # Encounter a bug when change user's password using
    # `c.extend.standard.modify_password`, fall back to using `modify` method
    # again.
    def modify_password(self, dn, new_password):
        self.modify(dn, {'userPassword': [new_password]})


if __name__ == '__main__':
    pass
