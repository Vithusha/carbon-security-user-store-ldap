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
import org.wso2.carbon.identity.mgt.exception.CredentialStoreConnectorException;


import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;
import java.util.Map;

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
        public LDAPConnectionContext(Map<String, String> properties) throws DataSourceException {

            String contextFactory = properties.get(LDAPConstants.LDAP_CONTEXT_FACTORY);
            String connectionURL = properties.get(LDAPConstants.CONNECTION_URL);
            String connectionName = properties.get(LDAPConstants.CONNECTION_NAME);
            String connectionPassword = properties.get(LDAPConstants.CONNECTION_PASSWORD);


            if (log.isDebugEnabled()) {
                log.debug("Connection Name :: " + connectionName + ", Connection URL :: " + connectionURL);
            }

            environment = new Hashtable<>();

            environment.put(Context.INITIAL_CONTEXT_FACTORY, contextFactory);

            if (connectionURL != null) {
                environment.put(Context.PROVIDER_URL, connectionURL);
            }
            environment.put(Context.SECURITY_AUTHENTICATION, LDAPConstants.AUTHENTICATION_TYPE);

            if (connectionName != null) {
                environment.put(Context.SECURITY_PRINCIPAL, connectionName);
            }
            if (connectionPassword != null) {
                environment.put(Context.SECURITY_CREDENTIALS,connectionPassword);
            }


            // Enable connection pooling if property is set in user-mgt.xml
            boolean isLDAPConnectionPoolingEnabled = false;
            String value = properties.get(LDAPConstants.LDAP_POOLING_ENABLED);

            if (value != null && !value.trim().isEmpty()) {
                isLDAPConnectionPoolingEnabled = Boolean.parseBoolean(value);
            }

            environment.put("com.sun.jndi.ldap.connect.pool", isLDAPConnectionPoolingEnabled ? "true" : "false");

            // set referral status if provided in configuration.
            if (properties.get(LDAPConstants.LDAP_REFERRAL) != null) {
                environment.put("java.naming.referral",
                        properties.get(LDAPConstants.LDAP_REFERRAL));
            }
            //Set connect timeout if provided in configuration. Otherwise set default value

            String connectTimeout = properties.get(CONNECTION_TIME_OUT);
            String readTimeout = properties.get(READ_TIME_OUT);
            if (connectTimeout != null && !connectTimeout.trim().isEmpty()) {
                environment.put("com.sun.jndi.ldap.connect.timeout", connectTimeout);
            } else {
                environment.put("com.sun.jndi.ldap.connect.timeout", "5000");
                environment.put("com.sun.jndi.ldap.connect.isLDAPConnectionPoolingEnabled", "true");

            }

        }

        public DirContext getContext() throws CredentialStoreConnectorException {
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
                    throw new CredentialStoreConnectorException("Error obtaining connection. " + e.getMessage(), e);
                }

            }
            return (context);
        }


        public DirContext getContextWithCredentials(String userDN, String password)
                throws CredentialStoreConnectorException {
            DirContext context;

            //create a temp env for this particular authentication session by copying the original env
            Hashtable<String, String> tempEnv = new Hashtable<>();
            for (Map.Entry entry : environment.entrySet()) {
                tempEnv.put((String) entry.getKey(), (String) entry.getValue());
            }
            //replace connection name and password with the passed credentials to this method
            tempEnv.put(Context.SECURITY_PRINCIPAL, userDN);
            tempEnv.put(Context.SECURITY_AUTHENTICATION,"DIGEST-MD5");
            tempEnv.put(Context.SECURITY_CREDENTIALS, password);

            //replace environment properties with these credentials
            try {
                context = new InitialDirContext(tempEnv);
            } catch (NamingException e) {
                throw new CredentialStoreConnectorException("Error occured while obtaining connection with Credentials" , e);
            }
            return (context);

        }

}

