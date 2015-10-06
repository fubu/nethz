import os.path
import ssl

import ldap3


_CERT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__),
                             "ldap-root.pem"))
ENFORCE_TLS = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=_CERT_PATH)

BIND_DN = "cn=%(user)s,ou=%(group)s,ou=nethz,ou=id,ou=auth,o=ethz,c=ch"


class _BaseLdap(object):
    """Base class for ETH LDAP connectors.

    Uses a server pool to distribute LDAP queries among multiple servers.
    """

    server_pool = None

    def __init__(self, hosts=None):
        """Sets up the LDAP connector.

        Args:
            hosts (list of str): Host URIs to connect to.
        """
        if not hosts:
            hosts = self.DEFAULT_HOSTS

        servers = []
        for host in hosts:
            servers.append(ldap3.Server(
                host, tls=ENFORCE_TLS if "ldaps://" in host else None))

        self.server_pool = ldap3.ServerPool(servers, active=True, exhaust=True)


class _SearchableLdap(object):
    """Provides facilities to search the ETH LDAP."""

    SEARCH_DN = None

    bind_dn = None
    bind_pw = None

    def search(self, query_string, limit=None):
        """Queries the ETH LDAP server for the given search string.

        Args:
            query_string (str): LDAP-encoded query string for the search.

        Returns:
            A list of search results (dict of LDAP attributes).
        """
        search_opts = dict(read_only=True,
                           auto_bind=ldap3.AUTO_BIND_NO_TLS,
                           raise_exceptions=True,
                           lazy=True)

        if None not in (self.bind_dn, self.bind_pw):
            search_opts.update(user=self.bind_dn,
                               password=self.bind_pw,
                               auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND)

        conn = ldap3.Connection(self.server_pool, **search_opts)

        if not conn.search(self.SEARCH_DN, query_string,
                           attributes=ldap3.ALL_ATTRIBUTES,
                           paged_size=limit):
            # The search returned no results
            return []

        return [res['attributes'] for res in conn.response]


class AnonymousLdap(_BaseLdap, _SearchableLdap):
    """Performs LDAP queries against an anonymous connection.

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
        """Sets up the LDAP connector.

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
        """Authenticates the given N.ETHZ credentials against the LDAP.

        Returns:
            True if the credentials are valid, False otherwise.
        """
        user_dn = BIND_DN % dict(user=username, group="users")

        try:
            ldap3.Connection(self.server_pool,
                             read_only=True,
                             user=user_dn,
                             password=password,
                             auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND,
                             raise_exceptions=True,
                             authentication=ldap3.AUTH_SIMPLE)
        except ldap3.LDAPException:
            return False

        return True
