# -*- coding:utf-8 -*-

import crypt
import re
from ldap3.utils.hashed import hashed
from ldap3 import (HASHED_SALTED_SHA, LDAPBindError,
                   LDAPPasswordIsMandatoryError)

from passport.utils.util import to_str, b64_decode, compare_hmac
from passport.utils.ldap.ldap import LdapQuery
from .ldap_errs import LdapAccessError, LdapParamsError, LdapModifyError

__author__ = "lqs"

LDAP_BASE = 'dc=example,dc=com'


class User:
    def __init__(self, host, port, name, password, admin=False):
        if admin:
            self.dn = 'cn=%s,%s' % (name, self.base)
        else:
            self.dn = 'uid=%s,%s' % (name, self.account)
        self.password = password

        try:
            self.dpc = LdapQuery(host=host,
                                 port=port,
                                 user=self.dn,
                                 password=self.password)
        except LDAPPasswordIsMandatoryError:
            raise LdapAccessError('argument password could not be None')
        except LDAPBindError:
            raise LdapAccessError('invalid username or password')
        except Exception:
            raise

    @property
    def base(self):
        return LDAP_BASE

    @property
    def account(self):
        return ''.join(['ou=Account,', self.base])

    @property
    def group(self):
        return ''.join(['ou=Group,', self.base])

    @property
    def sudoer(self):
        return ''.join(['ou=SUDOers,', self.base])

    @property
    def sudo_attributes(self):
        return {'sudoOption': '!authenticate',
                'sudoCommand': 'ALL',
                'sudoHost': 'ALL'}

    @property
    def sudo_objects(self):
        return ['sudoRole', 'top']

    @staticmethod
    def generate_secret(hash_method='CRYPT', phrase="", salt=None):
        if hash_method == 'CRYPT':
            cr = crypt.crypt(phrase, salt=salt)
            return '{}{}'.format('{crypt}', cr)
        elif hash_method == 'SSHA':
            return hashed(HASHED_SALTED_SHA, phrase, salt=salt)

    @staticmethod
    def split_password(password):
        pass_tuple = re.match(r'({.*})(.*)', password).groups()
        return pass_tuple[0].strip('{}'), pass_tuple[1]

    def _query(self, base=None, **filter_params):
        if not base:
            base = self.account

        if not filter_params:
            filters = '(uid=*)'
        else:
            params = ['(%s=%s)' % (k, v) for k, v in filter_params.items()]
            filters = '(&{})'.format(''.join(params))

        entries = self.dpc.query(base=base, filters=filters)
        return entries

    def _get_attrs_of_entry(self, base=None, **filters):
        # with ** ahead of dict name, we pass the dict as keyword arguments.
        entries = self._query(base=base, **filters)
        if entries:
            return entries[0].get('attributes')

    def _get_max_uid(self):
        entries = self.dpc.query(base=self.account,
                                 filters='(uid=*)',
                                 attributes=['uidNumber'])
        uids = [i.get('attributes').get('uidNumber') for i in entries]
        uids.sort(reverse=True)
        return uids[0]

    def _get_pass(self, uid=None):
        if uid is None:
            uid = self.dn.split(',')[0].split('=')[1]
        attrs = self._get_attrs_of_entry(uid=uid)
        if not attrs:
            raise AttributeError('user %s does not exist' % uid)

        return attrs.get('userPassword')[0]

    def get_group_attrs(self, **kwargs):
        attr = self._get_attrs_of_entry(base=self.group, **kwargs)
        return attr

    def get_user_profile(self, uid=None):
        if uid is None:
            uid = self.dn.split(',')[0].split('=')[1]
        profile = {}
        attrs = self._get_attrs_of_entry(uid=uid)
        if attrs:
            profile['uid'] = attrs.get('uid')[0]
            profile['name'] = attrs.get('cn')[0]
            profile['mail'] = attrs.get('mail')[0]
            profile['mobile'] = attrs.get('mobile')[0]
            profile['groups'] = attrs.get('o')
            profile['apps'] = attrs.get('l')
            profile['sudo'] = False

            gid = attrs.get('gidNumber')
            g_attrs = self.get_group_attrs(gidnumber=gid)
            if g_attrs:
                profile['group'] = g_attrs.get('description')[0]
                profile['group_code'] = g_attrs.get('cn')[0]

            sudo = self._get_attrs_of_entry(base=self.sudoer, cn=uid)
            if sudo:
                profile['sudo'] = True
        return profile

    # Reported by xueming, if the password is complicated, this method may
    # encounter error. It is Unused for now.
    def check_password(self, password=None, username=None):
        exist_pass = self._get_pass(uid=username)
        alg, content = self.split_password(to_str(exist_pass))

        # It is recommended to use the full encrypted password as salt when
        # checking for a password. Refers to the manual of crypt.
        if alg == 'crypt':
            comparable = self.generate_secret(phrase=password, salt=content)
            n_digest = self.split_password(comparable)[1]
            o_digest = content
        elif alg == 'ssha':
            salt = b64_decode(content)[20:]
            comparable = self.generate_secret(hash_method='SSHA',
                                              phrase=password,
                                              salt=salt)
            n_digest = self.split_password(comparable)[1]
            o_digest = content
        else:
            raise AttributeError(
                """
                Invalid hash algorithm {0}.
                Only "CRYPT" and sha1 secure hash algorithm "SSHA" are
                supported
                """.format(alg)
            )

        return compare_hmac(o_digest, n_digest)

    def change_password(self, username, new_password):
        if username is not None:
            dn = 'uid=%s,%s' % (username, self.account)
        else:
            dn = self.dn

        secret = self.generate_secret(phrase=new_password)
        self.dpc.modify_password(dn, secret)

    def show_all_users(self, page=1, page_size=100, **filters):
        def filter_attrs(obj, *attrs):
            attributes = obj.get('attributes')
            return {i: attributes.get(i)[0] for i in attrs}

        attrs = ['uid', 'cn', 'mail', 'mobile']
        entries = self._query(**filters)

        if not entries:
            return

        # if page:
        #     import math
        #     page = 1 if int(page) < 1 else int(page)
        #     page_size = int(page_size)
        #     total_page = int(math.ceil(len(entries) / page_size))
        #
        #     if page > total_page:
        #         page = total_page
        #
        #     pagination = entries[(page-1)*page_size: page*page_size]
        #     return {'total_page': total_page,
        #             'page_size': page_size,
        #             'users': [filter_attrs(i, *attrs) for i in pagination]}
        # else:
        #     return [filter_attrs(i, *attrs) for i in entries]
        # return [filter_attrs(i, *attrs) for i in entries]

        data = [filter_attrs(i, *attrs) for i in entries]
        for i in data:
            i.update(name=i.pop('cn'))
        return data


class Privileged(User):
    def __init__(self, host, port, ldap_root, root_password):
        super().__init__(host, port, ldap_root, root_password, admin=True)

    def show_sudoers(self):
        entries = self.dpc.query(base=self.sudoer, filters='(cn=*)')
        sudoers = []
        for entry in entries:
            attrs = entry.get('attributes')
            sudoers.append(attrs.get('cn')[0])

        if 'defaults' in sudoers:
            sudoers.remove('defaults')
        return sudoers

    def add_sudoers(self, users):
        objects = self.sudo_objects
        attrs = self.sudo_attributes
        exist_sudoers = self.show_sudoers()
        fail = {}

        assert isinstance(users, (str, list))
        if isinstance(users, str):
            users = [users]

        for name in users:
            if name not in exist_sudoers:
                attrs.update({'cn': name, 'sudoUser': name})
                dn = 'cn=%s,%s' % (name, self.sudoer)

                ok = self.dpc.add(dn, objects=objects, attributes=attrs)
                if ok.get('result') != 0:
                    fail.update({'name': name, 'des': ok['description']})
        return fail

    def add_user(self, username, zh_name, gid, phone):
        g_attr = self.get_group_attrs(gidnumber=gid)
        if not g_attr:
            raise AttributeError('invalid gid')

        gidnumber = g_attr.get('gidNumber')
        uidnumber = self._get_max_uid() + 1
        mail = ''.join([username, '@ele.me'])
        home = ''.join(['/home', username])

        dn = ''.join(['uid=%s,' % username, 'ou=Account,', self.base])
        objects = ['inetOrgPerson',
                   'organizationalPerson',
                   'person',
                   'posixAccount',
                   'shadowAccount',
                   'top']
        attributes = {'cn': zh_name,
                      'sn': username,
                      'uid': username,
                      'uidNumber': uidnumber,
                      'gidNumber': gidnumber,
                      'homeDirectory': home,
                      'mail': mail,
                      'mobile': phone,
                      'loginshell': '/bin/bash'}
        ok = self.dpc.add(dn, objects, attributes)
        if ok.get('result') == 0:
            return True
        return False

    def update_attrs(self, uid, appid=None, groups=None, operation='replace'):
        """
        :param uid:
        :param appid:
        :param groups:
        :param operation: should be 'delete' or 'replace'
        :return:
        """
        attrs = self._get_attrs_of_entry(uid=uid)
        dn = 'uid=%s,%s' % (uid, self.account)
        new_attrs = {}

        def deal_action(params=None, params_action=None, attr=None):
            p_list = params.split(',')
            a_list = attrs.get(attr)

            if params_action == 'delete':
                return list(set(a_list) - set(p_list)) if a_list else None
            elif params_action == 'replace':
                return list(set(a_list) | set(p_list)) if a_list else p_list

        if not attrs:
            raise LdapParamsError('The uid %s does not exist.' % uid)

        if appid:
            ids = deal_action(appid, params_action=operation, attr='l')
            new_attrs['l'] = ids

        if groups:
            gs = deal_action(groups, params_action=operation, attr='o')
            new_attrs['o'] = gs

        results = self.dpc.modify(dn, new_attrs)
        code = results.get('result')
        if (code != 0) and (code != 20):
            raise LdapModifyError(results.get('description'))

    def cancel_sudo(self, users):
        exist_sudoers = self.show_sudoers()
        fail = {}

        assert isinstance(users, (str, list))
        if isinstance(users, str):
            users = [users]

        for name in users:
            if name in exist_sudoers:
                dn = 'cn=%s,%s' % (name, self.sudoer)
                ok = self.dpc.delete(dn)

                if ok.get('result') != 0:
                    fail.update({'name': name, 'des': ok['description']})
        return fail
