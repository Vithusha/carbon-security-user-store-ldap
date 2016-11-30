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
    public static final String ATTRIBUTE_NAMES = "AttributeNames";


    //AuthenticationConstants
    public static final String CONNECTION_URL = "connection_url";
    public static final String CONNECTION_NAME = "connection_name";
    public static final String CONNECTION_PASSWORD = "connection_password";
    public static final String DOMAIN_SEPARATOR = "domain_seperator";
    public static final String USER_LOGIN_STRING = "user_login_string";
    public static final String MAX_ROW_LIMIT = "max_row_limit";
    public static final String USER_SEARCH_BASE = "user_search_base";
    public static final String USER_NAME_LIST_FILTER = "UserNameListFilter";
    public static final String USER_NAME_ATTRIBUTE = "UserNameAttribute";
    public static final String DISPLAY_NAME_ATTRIBUTE = "DisplayNameAttribute";
    public static final String AUTHENTICATION_TYPE = "Authentication_type";


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

