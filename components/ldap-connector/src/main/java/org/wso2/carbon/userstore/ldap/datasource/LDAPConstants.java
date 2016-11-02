/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.wso2.carbon.userstore.ldap.datasource;

/**
 * Class holding the default values for LDAP configuration.
 */
public class LDAPConstants {

    public static final String LDAP_DATASOURCE_TYPE = "LDAP";
    public static final String LDAP_CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
    public static final String LDAP_POOLING_ENABLED = "com.sun.jndi.ldap.connect.pool";
    public static final String LDAP_REFERRAL = "java.naming.referral";
    public static final String LDAP_ATTRIBUTES_BINARY = "java.naming.ldap.attributes.binary";
    public static final String LDAP_READ_TIMEOUT = "com.sun.jndi.ldap.read.timeout";
    public static final String LDAP_CONNECTION_TIMEOUT = "com.sun.jndi.ldap.connect.timeout";

    //pooling constants
    public static final String LDAP_POOL_AUTHENTICATION = "com.sun.jndi.ldap.connect.pool.authentication";
    public static final String LDAP_POOL_DEBUG = "com.sun.jndi.ldap.connect.pool.debug";
    public static final String LDAP_POOL_INITSIZE = "com.sun.jndi.ldap.connect.pool.initsize";
    public static final String LDAP_POOL_MAXSIZE = "com.sun.jndi.ldap.connect.pool.maxsize";
    public static final String LDAP_POOL_PREFSIZE = "com.sun.jndi.ldap.connect.pool.prefsize";
    public static final String LDAP_POOL_PROTOCOL = "com.sun.jndi.ldap.connect.pool.protocol";
    public static final String LDAP_POOL_TIMEOUT = "com.sun.jndi.ldap.connect.pool.timeout";

    //dns constants
    public static final String DNS_URL = "urlOfDns";
    public static final String DNS_DOMAIN_NAME = "dnsDomainName";
    public static final String CONNECTION_POOLING_ENABLED = "ConnectionPoolingEnabled";
    public static final String GROUP_SEARCH_BASE = "GroupSearchBase";
    public static final String GROUP_NAME_LIST_FILTER = "GroupNameListFilter";
    public static final String GROUP_NAME_ATTRIBUTE = "GroupNameAttribute";
    public static final String MEMBERSHIP_ATTRIBUTE = "MembershipAttribute";


    //AuthenticationConstants
    public static final String CONNECTION_URL = "connection_url";
    public static final String CONNECTION_NAME = "connection_name";
    public static final String CONNECTION_PASSWORD = "connection_password";
    public static final String LDAP_SEARCH_BASE = "ldap_search_base";
    public static final String DOMAIN_SEPARATOR = "domain_seperator";
    public static final String USER_LOGIN_STRING = "user_login_string";
    public static final String MAX_ROW_LIMIT = "max_row_limit";
    public static final String USER_SEARCH_BASE = "user_search_base";
    public static final String PROVIDER_PATH = "provider_path";
    public static final String USER_NAME_LIST_FILTER = "UserNameListFilter";
    public static final String USER_NAME_ATTRIBUTE = "UserNameAttribute";
    public static final String DISPLAY_NAME_ATTRIBUTE = "DisplayNameAttribute";
    public static final String USER_DN_PATTERN = "UserDNPattern";
    public static final String PROPERTY_REFERRAL = "Referral";

    //filter attribute in user-mgt.xml that filters users by user name
    public static final String USER_NAME_SEARCH_FILTER = "UserNameSearchFilter";

    //KDC specific constant
    public static final String SERVER_PRINCIPAL_ATTRIBUTE_VALUE = "Service";

    //Common Constants
    public static final String PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN = "ReplaceEscapeCharactersAtUserLogin";
    public static final String PROPERTY_MAX_USER_LIST = "MaxUserNameListLength";
    public static final String PROPERTY_MAX_SEARCH_TIME = "MaxSearchQueryTime";
    public static final String PROPERTY_MAX_ROLE_LIST = "MaxRoleNameListLength";
    public static final String XML_PATTERN_SEPERATOR = "#";
    public static final String ATTRIBUTE_LIST_SEPERATOR = ",";
    public static final String WILD_CARD_FILTER = "*";
    public static final String CARBON_HOME = "carbon.home";
    public static final int MAX_USER_LIST = 100;
    public static final int MAX_SEARCH_TIME = 10000;   // ms


    private LDAPConstants() {

    }
}

    class DatabaseColumnNames {

        /**
         * Names of the Group table columns.
         */
        public static final class Group {
            public static final String ID = "ID";
            public static final String GROUP_UNIQUE_ID = "GROUP_UNIQUE_ID";
            public static final String GROUP_NAME = "GROUP_NAME";
        }

        /**
         * Names of the User table columns.
         */
        public static final class User {
            public static final String ID = "ID";
            public static final String USERNAME = "USERNAME";
            public static final String PASSWORD = "PASSWORD";
            public static final String USER_UNIQUE_ID = "USER_UNIQUE_ID";
            public static final String IDENTITY_STORE_ID = "IDENTITY_STORE_ID";
            public static final String CREDENTIAL_STORE_ID = "CREDENTIAL_STORE_ID";
            public static final String TENANT_ID = "TENANT_ID";
        }

        /**
         * Names of the Group table columns.
         */
        public static final class Role {

            public static final String ROLE_UNIQUE_ID = "ROLE_UNIQUE_ID";
            public static final String ROLE_NAME = "ROLE_NAME";
        }

        /**
         * Names of the UserAttributes table columns.
         */
        public static final class UserAttributes {
            public static final String ATTR_NAME = "ATTR_NAME";
            public static final String ATTR_VALUE = "ATTR_VALUE";
            public static final String USER_ID = "USER_ID";
        }

        /**
         * Names of the GroupAttributes table columns.
         */
        public static final class GroupAttributes {
            public static final String ATTR_NAME = "ATTR_NAME";
            public static final String ATTR_VALUE = "ATTR_VALUE";
        }

        /**
         * Names of the UserGroup table columns.
         */
        public static final class UserGroup {
            public static final String USER_ID = "USER_ID";
            public static final String GROUP_ID = "GROUP_ID";
        }

        /**
         * Names of the PasswordInfo table columns.
         */
        public static final class PasswordInfo {
            public static final String HASH_ALGO = "HASH_ALGO";
            public static final String PASSWORD_SALT = "PASSWORD_SALT";
            public static final String ITERATION_COUNT = "ITERATION_COUNT";
            public static final String KEY_LENGTH = "KEY_LENGTH";
        }

        /**
         * Names of the Permission table columns.
         */
        public static final class Permission {
            public static final String ID = "ID";
            public static final String RESOURCE_ID = "DOMAIN";
            public static final String ACTION = "ACTION_NAMESPACE";
            public static final String PERMISSION_ID = "PERMISSION_UNIQUE_ID";
        }

        /**
         * Names of the Resource Namespace table columns.
         */
        public static final class ResourceNamespace {
            public static final String ID = "ID";
            public static final String NAMESPACE = "NAMESPACE";
        }

        /**
         * Names of the Resource table columns.
         */
        public static final class Resource {
            public static final String ID = "ID";
            public static final String NAMESPACE_ID = "NAMESPACE_ID";
            public static final String RESOURCE_NAME = "RESOURCE_NAME";
            public static final String USER_UNIQUE_ID = "USER_UNIQUE_ID";
            public static final String IDENTITY_STORE_ID = "IDENTITY_STORE_ID";
        }

        /**
         * Names of the Action table columns.
         */
        public static final class Action {
            public static final String ID = "ID";
            public static final String NAMESPACE_ID = "NAMESPACE_ID";
            public static final String ACTION_NAME = "ACTION_NAME";
        }

        /**
         * Names of the Tenant table columns.
         */
        public static final class Tenant {
            public static final String DOMAIN_NAME = "DOMAIN_NAME";
        }

        /**
         * Names of the UserRole table columns.
         */
        public static final class UserRole {

            public static final String ROLE_ID = "ROLE_ID";
            public static final String USER_UNIQUE_ID = "USER_UNIQUE_ID";
            public static final String IDENTITY_STORE_ID = "IDENTITY_STORE_ID";
        }

        /**
         * Names of the GroupRole table columns.
         */
        public static final class GroupRole {

            public static final String ROLE_ID = "ROLE_ID";
            public static final String GROUP_UNIQUE_ID = "GROUP_UNIQUE_ID";
            public static final String IDENTITY_STORE_ID = "IDENTITY_STORE_ID";
        }

    }

