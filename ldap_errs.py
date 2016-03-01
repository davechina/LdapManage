# -*- coding:utf-8 -*-

from passport.errors import CustomerException
from ldap3.core.exceptions import LDAPOperationResult

__author__ = "lqs"


class LdapAccessError(CustomerException):
    """Invalid username or password error.

    The error is usually caused by invalid username or password, and the error
    code is defined as 401.
    """
    def __init__(self, message):
        self.message = message
        self.code = 401


class LdapParamsError(CustomerException):
    """Invalid parameter error.

    The operation to query some specified information of ldap entry may contain
    some invalid parameter, such as invalid uid or group name.
    """
    def __init__(self, message):
        self.message = message
        self.code = 401


class LdapSudoError(LDAPOperationResult):
    def __init__(self, message):
        self.message = message
        self.code = 400


class  LdapModifyError(LDAPOperationResult):
    def __init__(self, message):
        self.message = message
        self.code = 400
