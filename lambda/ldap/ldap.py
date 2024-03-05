from ldap3 import Server, Connection, NTLM, SUBTREE
from util.logger import get_logger
from util.common import decode
import sys


logger = get_logger()


class Ldap:
    def __init__(self, ldap_url, ad_admin_username, ad_admin_password):
        logger.info("Initializing LDAP connection")
        self.ldap_url = ldap_url
        self.ad_admin_username = ad_admin_username
        self.ad_admin_password = ad_admin_password
        self.connection = self.ldap_connection()

    def ldap_connection(self):
        logger.info("getting LDAP server...")
        server = Server(self.ldap_url)
        logger.info("Server Found...")

        try:
            logger.info("Connecting to server")
            con = Connection(
                server,
                user=self.ad_admin_username,
                password=self.ad_admin_password,
                authentication=NTLM,
            )
            con.bind()
        except:
            logger.error("Connection Failed")
            raise
        return con

    def ldap_unbind(self):
        """
        Un-binds an LDAP connection
        :param connection:
        :return: None
        """
        self.connection.unbind()
        return

    def ldap_search_computers(self, domain_base_dn, search_attribute):
        """
        Query LDAP based on given parametes
        :param connection: LDAP connection
        :param domain_base_dn: Base LDAP search path
        :param search_filter: Query filter
        :param search_attribute: Attributes to return from the query
        :return computer_filter: List of computer objects
        """
        search_filter = "(objectClass=computer)"
        logger.debug("domain_base_dn : {}".format(domain_base_dn))
        logger.debug("search_filter : {}".format(search_filter))
        logger.debug("search_attribute : {}".format(search_attribute))
        self.connection.search(
            domain_base_dn, search_filter, attributes=search_attribute)

        ldap_computers = self.connection.entries

        return ldap_computers

    def ldap_search_users(self, domain_base_dn, user_group_cns):
        search_attribute = [
            "sAMAccountName",
            "name",
            "givenName",
            "sn",
            "mail",
            "department",
            "departmentNumber",
        ]
        ldap_users = self.connection.entries
        ldap_users_filter = []
        ldap_user_info = {}
        member_search_filter = ""

        for user_group_cn in user_group_cns:
            member_search_filter += "(MemberOf={})".format(user_group_cn)

        search_filter = "(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|{}))".format(
            member_search_filter
        )
        
        logger.info("search_filter: {}".format(search_filter))
        users_query_result = self.connection.search(
            domain_base_dn, search_filter, attributes=search_attribute
        )

        logger.info("users_query_result: {}".format(users_query_result))
        for user in ldap_users:
            
            if user is None:
                continue
            
            user_cn = decode(user)
            account_name = decode(user["sAMAccountName"][0])
            account_email = decode(user["mail"][0]) if user["mail"] else "None"
            account_department = (
                decode(user["department"][0]) if user["department"] else "None"
            )
            account_department_number = (
                decode(user["departmentNumber"][0]
                       ) if user["departmentNumber"] else "None"
            )
            user_full_name = decode(
                user["name"][0]) if user["name"] else "None"
            user_given_name = decode(
                user["givenName"][0]) if user["givenName"] else "None"
            user_surname = decode(user["sn"][0]) if user["sn"] else "None"
            ldap_users_filter.append(account_name)

            ldap_user_info[account_name] = {
                "user_id": account_name,
                "full_name": user_full_name.replace(",", " "),
                "given_name": user_given_name.replace(",", " "),
                "surname": user_surname.replace(",", " "),
                "cn": user_cn,
                "mail": account_email,
                "department": account_department.replace(",", " "),
                "department_number": account_department_number.replace(",", " "),
            }

        return ldap_users_filter, ldap_user_info
    
    
    def ldap_search(self, domain_base_dn, search_filter, search_attribute):
        """
        Query LDAP based on given parametes
        :param connection: LDAP connection
        :param domain_base_dn: Base LDAP search path
        :param search_filter: Query filter
        :param search_attribute: Attributes to return from the query
        :return computer_filter: List of computer objects
        """
        logger.debug("domain_base_dn : {}".format(domain_base_dn))
        logger.debug("search_filter : {}".format(search_filter))
        logger.debug("search_attribute : {}".format(search_attribute))
        scope = SUBTREE
        self.connection.search(domain_base_dn, search_filter, attributes=search_attribute, search_scope=scope)

        ldap_users = self.connection.entries

        return ldap_users

    def ldap_delete(self, distinguished_name):
        """
        Deletes given LDAP object
        :param connection: LDAP connection
        :param distinguished_name: Object absolute path
        :return: None
        """
        try:
            logger.info(distinguished_name)
            self.connection.delete(distinguished_name)
        except Exception as err:
            logger.error(err)
            sys.exit()
        return
