# -*- coding: utf-8 -*-

"""nethz.

Provide a Connector to easily query the ETH ldap.
"""

import os.path
import ssl

import ldap3


BIND_DN = "cn=%(user)s,ou=%(group)s,ou=nethz,ou=id,ou=auth,o=ethz,c=ch"


class _BaseLdap(object):
    """Base class for ETH LDAP connectors.

    Uses a server pool to distribute LDAP queries among multiple servers.
    """

    server_pool = None

    def __init__(self, hosts=None):
        """Set up the LDAP connector.

        Args:
            hosts (list of str): Host URIs to connect to.
        """
        if not hosts:
            hosts = self.DEFAULT_HOSTS

        servers = []
        for host in hosts:
            servers.append(ldap3.Server(
                host,
                connect_timeout=10,  # Wait up to 10 seconds
            ))

        # Only try to reach each server once before reporting error
        # (To avoid getting stuck in a loop waiting forever)
        self.server_pool = ldap3.ServerPool(servers, active=1, exhaust=True)


class _SearchableLdap(object):
    """Provides facilities to search the ETH LDAP."""

    SEARCH_DN = None

    bind_dn = None
    bind_pw = None

    def search(self, query_string, attributes=ldap3.ALL_ATTRIBUTES):
        """Query the ETH LDAP server for the given search string.

        Args:
            query_string (str): LDAP-encoded query string for the search.

        Returns:
            generator: search results (dict of LDAP attributes).
        """
        search_opts = dict(auto_bind=True,
                           read_only=True,
                           raise_exceptions=True)

        if None not in (self.bind_dn, self.bind_pw):
            search_opts.update(user=self.bind_dn,
                               password=self.bind_pw)

        conn = ldap3.Connection(self.server_pool, **search_opts)

        res = conn.extend.standard.paged_search(
            self.SEARCH_DN, query_string,
            attributes=attributes,
            paged_size=300,
            generator=True)

        return (item['attributes'] for item in res)


class AnonymousLdap(_BaseLdap, _SearchableLdap):
    """Perform LDAP queries against an anonymous connection.

    This is in general only useful to do simple name searches, similar to what
    the `ETH people search <https://people.ethz.ch>`_ offers all ETH students.
    """

    DEFAULT_HOSTS = ["ldap://ldap.ethz.ch"]
    SEARCH_DN = "o=ethz,c=ch"


class AuthenticatedLdap(_BaseLdap, _SearchableLdap):
    """Performs LDAP queries against an authenticated connection.

    This allows to search for an extended attribute set and requires special
    credentials (to be obtained from `ETH IT services <www.id.ethz.ch/>`_).
    """

    DEFAULT_HOSTS = ["ldaps://ldaps01.ethz.ch",
                     "ldaps://ldaps02.ethz.ch",
                     "ldaps://ldaps03.ethz.ch"]

    SEARCH_DN = "ou=users,ou=nethz,ou=id,ou=auth,o=ethz,c=ch"

    def __init__(self, username, password, hosts=None):
        """Set up the LDAP connector.

        Args:
            username (str): LDAP username to use for the bind when searching.
            password (str): LDAP password to use for the bind when searching.
            hosts (list of str): Host URIs to connect to.

        Raises:
            ValueError: when not both username and password were provided.
        """
        if None in (username, password):
            raise ValueError("username and password must be provided")

        self.bind_dn = BIND_DN % dict(user=username, group="admins")
        self.bind_pw = password

        super(AuthenticatedLdap, self).__init__(hosts=hosts)

    def authenticate(self, username, password):
        """Authenticate the given N.ETHZ credentials against the LDAP.

        Returns:
            True if the credentials are valid, False otherwise.
        """
        user_dn = BIND_DN % dict(user=username, group="users")

        try:
            # Try to authentivate, i.e. bind to server
            # On success, immediately unbind to avoid dangling connections
            ldap3.Connection(self.server_pool,
                             read_only=True,
                             user=user_dn,
                             password=password,
                             auto_bind=True
                             raise_exceptions=True,
                             authentication=ldap3.SIMPLE).unbind()
        except ldap3.core.exceptions.LDAPException:
            return False

        return True
