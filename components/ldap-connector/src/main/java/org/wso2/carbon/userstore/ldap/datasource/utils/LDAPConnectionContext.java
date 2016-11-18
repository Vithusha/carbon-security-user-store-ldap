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

/**
 * Created by wso2 on 9/29/16.
 */

package org.wso2.carbon.userstore.ldap.datasource.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.datasource.core.exception.DataSourceException;
import org.wso2.carbon.identity.mgt.exception.CredentialStoreException;
import org.wso2.carbon.userstore.ldap.datasource.LDAPConstants;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;

/**
 * Bean class to create LDAP connections.
 */

 public class LDAPConnectionContext {

        private static Logger log = LoggerFactory.getLogger(LDAPConnectionContext.class);
        @SuppressWarnings("rawtypes")
        private Hashtable<String, String> environment;
        private static final String CONNECTION_TIME_OUT = "LDAPConnectionTimeout";
        private static final String READ_TIME_OUT = "ReadTimeout";




        @SuppressWarnings({"rawtypes", "unchecked"})
        public LDAPConnectionContext(Properties properties) throws DataSourceException {

            String connectionURL = properties.getProperty(LDAPConstants.CONNECTION_URL);
            String connectionName = properties.getProperty(LDAPConstants.CONNECTION_NAME);
            String connectionPassword = properties.getProperty(LDAPConstants.CONNECTION_PASSWORD);

            if (log.isDebugEnabled()) {
                log.debug("Connection Name :: " + connectionName + ", Connection URL :: " + connectionURL);
            }

            environment = new Hashtable<>();
            environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            environment.put(Context.SECURITY_AUTHENTICATION, "simple");

            if (connectionName != null) {
                environment.put(Context.SECURITY_PRINCIPAL, connectionName);
            }

            if (connectionPassword != null) {
                environment.put(Context.SECURITY_CREDENTIALS, connectionPassword);
            }

            if (connectionURL != null) {
                environment.put(Context.PROVIDER_URL, connectionURL);
            }

            // Enable connection pooling if property is set in user-mgt.xml
            boolean isLDAPConnectionPoolingEnabled = false;
            String value = properties.getProperty(LDAPConstants.LDAP_POOLING_ENABLED);

            if (value != null && !value.trim().isEmpty()) {
                isLDAPConnectionPoolingEnabled = Boolean.parseBoolean(value);
            }

            environment.put("com.sun.jndi.ldap.connect.pool", isLDAPConnectionPoolingEnabled ? "true" : "false");

            // set referral status if provided in configuration.
            if (properties.getProperty(LDAPConstants.LDAP_REFERRAL) != null) {
                environment.put("java.naming.referral",
                        properties.getProperty(LDAPConstants.LDAP_REFERRAL));
            }
            //Set connect timeout if provided in configuration. Otherwise set default value

            String connectTimeout = properties.getProperty(CONNECTION_TIME_OUT);
            String readTimeout = properties.getProperty(READ_TIME_OUT);
            if (connectTimeout != null && !connectTimeout.trim().isEmpty()) {
                environment.put("com.sun.jndi.ldap.connect.timeout", connectTimeout);
            } else {
                environment.put("com.sun.jndi.ldap.connect.timeout", "5000");
                environment.put("com.sun.jndi.ldap.connect.isLDAPConnectionPoolingEnabled", "true");

            }


        }

        public DirContext getContext() throws CredentialStoreException {
            DirContext context;
            try {
                context = new InitialDirContext(environment);

            } catch (NamingException e) {
                log.error("Error obtaining connection. " + e.getMessage(), e);
                log.error("Trying again to get connection.");

                try {
                    context = new InitialDirContext(environment);
                } catch (Exception e1) {
                    log.error("Error obtaining connection for the second time" + e.getMessage(), e);
                    throw new CredentialStoreException("Error obtaining connection. " + e.getMessage(), e);
                }

            }
            return (context);
        }
        //TODO: Naming Exception to be caught, Access Modifier

        public LdapContext getContextWithCredentials(String userDN, String password)
                throws CredentialStoreException, NamingException {
            LdapContext context;

            //create a temp env for this particular authentication session by copying the original env
            Hashtable<String, String> tempEnv = new Hashtable<>();
            for (Map.Entry entry : environment.entrySet()) {
                tempEnv.put((String) entry.getKey(), (String) entry.getValue());
            }
            //replace connection name and password with the passed credentials to this method
            tempEnv.put(Context.SECURITY_PRINCIPAL, userDN);
            tempEnv.put(Context.SECURITY_CREDENTIALS, password);

            //replace environment properties with these credentials
            context = new InitialLdapContext(tempEnv, null);
            return (context);

        }



    /**
     * Method description
     *
     *
     * @param token
     * @param result
     *
     * @return
     */


/**
 * Perform authentication based on the supplied token.
 *
 */





}

