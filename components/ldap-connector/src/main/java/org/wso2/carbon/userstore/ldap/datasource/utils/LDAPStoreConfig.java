package org.wso2.carbon.userstore.ldap.datasource.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.mgt.exception.CredentialStoreConnectorException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;

import java.util.Properties;

/**
 * Created by wso2 on 10/31/16.
 */
public class LDAPStoreConfig {

    private static Logger log = LoggerFactory.getLogger(LDAPStoreConfig.class);
    Properties properties;

    public void checkRequiredUserStoreConfigurations() throws IdentityStoreException, CredentialStoreConnectorException {

        log.debug("Checking LDAP configurations ");
        String connectionURL = properties.getProperty(LDAPConstants.CONNECTION_URL);

        if (connectionURL == null || connectionURL.trim().length() == 0) {
            throw new IdentityStoreException(
                    "Required ConnectionURL property is not set at the LDAP configurations");
        }
        String connectionName = properties.getProperty(LDAPConstants.CONNECTION_NAME);
        if (connectionName == null || connectionName.trim().length() == 0) {
            throw new IdentityStoreException(
                    "Required ConnectionNme property is not set at the LDAP configurations");
        }
        String connectionPassword =
                properties.getProperty(LDAPConstants.CONNECTION_PASSWORD);
        if (connectionPassword == null || connectionPassword.trim().length() == 0) {
            throw new IdentityStoreException(
                    "Required ConnectionPassword property is not set at the LDAP configurations");
        }
        String userSearchBase = properties.getProperty(LDAPConstants.USER_SEARCH_BASE);
        if (userSearchBase == null || userSearchBase.trim().length() == 0) {
            throw new IdentityStoreException(
                    "Required UserSearchBase property is not set at the LDAP configurations");
        }
        String usernameListFilter =
                properties.getProperty(LDAPConstants.USER_NAME_LIST_FILTER);
        if (usernameListFilter == null || usernameListFilter.trim().length() == 0) {
            throw new IdentityStoreException(
                    "Required UserNameListFilter property is not set at the LDAP configurations");
        }

        String usernameSearchFilter =
                properties.getProperty(LDAPConstants.USER_NAME_SEARCH_FILTER);
        if (usernameSearchFilter == null || usernameSearchFilter.trim().length() == 0) {
            throw new IdentityStoreException(
                    "Required UserNameSearchFilter property is not set at the LDAP configurations");
        }

        String usernameAttribute =
                properties.getProperty(LDAPConstants.USER_NAME_ATTRIBUTE);
        if (usernameAttribute == null || usernameAttribute.trim().length() == 0) {
            throw new IdentityStoreException(
                    "Required UserNameAttribute property is not set at the LDAP configurations");
        }
        String groupSearchBase = properties.getProperty(LDAPConstants.GROUP_SEARCH_BASE);
        if (groupSearchBase == null || groupSearchBase.trim().length() == 0) {
            throw new IdentityStoreException(
                    "Required GroupSearchBase property is not set at the LDAP configurations");
        }
        String groupNameListFilter =
                properties.getProperty(LDAPConstants.GROUP_NAME_LIST_FILTER);
        if (groupNameListFilter == null || groupNameListFilter.trim().length() == 0) {
            throw new IdentityStoreException(
                    "Required GroupNameListFilter property is not set at the LDAP configurations");
        }

        String groupNameAttribute =
                properties.getProperty(LDAPConstants.GROUP_NAME_ATTRIBUTE);
        if (groupNameAttribute == null || groupNameAttribute.trim().length() == 0) {
            throw new IdentityStoreException(
                    "Required GroupNameAttribute property is not set at the LDAP configurations");
        }
        String memebershipAttribute =
                properties.getProperty(LDAPConstants.MEMBERSHIP_ATTRIBUTE);
        if (memebershipAttribute == null || memebershipAttribute.trim().length() == 0) {
            throw new IdentityStoreException(
                    "Required MembershipAttribute property is not set at the LDAP configurations");
        }

    }

}