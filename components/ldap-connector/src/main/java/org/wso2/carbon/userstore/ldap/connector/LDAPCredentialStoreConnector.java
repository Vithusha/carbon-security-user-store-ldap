/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.userstore.ldap.connector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.caas.api.CarbonCallback;
import org.wso2.carbon.security.caas.user.core.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnector;
import org.wso2.carbon.userstore.ldap.datasource.utils.LDAPConnectionContext;
import org.wso2.carbon.userstore.ldap.datasource.utils.LDAPStoreConfig;

import javax.naming.directory.DirContext;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import java.util.Map;
import java.util.Properties;

/**
 * LDAP based implementation for credential store connector.
 */
public class LDAPCredentialStoreConnector implements CredentialStoreConnector {

    /*
    @Override
    public void init(String s, CredentialStoreConfig credentialStoreConfig) throws CredentialStoreException {
    }
    */


    private static Logger log = LoggerFactory.getLogger(LDAPCredentialStoreConnector.class);
    private Properties properties;
    private String credentialStoreId;
    private DirContext context;
    private CredentialStoreConnectorConfig credentialConnectorConfig;
    LDAPConnectionContext connectionSource;


    @Override
    public void init(CredentialStoreConnectorConfig credentialStoreConnectorConfig) throws CredentialStoreException {

        this.credentialConnectorConfig=credentialStoreConnectorConfig;
        this.properties=credentialConnectorConfig.getProperties();
        // check if required configurations are in the user-mgt.xml

        try {
            new LDAPStoreConfig().checkRequiredUserStoreConfigurations();
        } catch (IdentityStoreException e) {

        }


        if (log.isDebugEnabled()) {
            log.debug("Initialization Started " + System.currentTimeMillis());
        }

    }

    @Override
    public String getCredentialStoreConnectorId() {
        this.credentialStoreId=properties.getProperty(credentialStoreId);
        return credentialStoreId;
    }

    @Override
    public void authenticate(Callback[] callbacks) throws CredentialStoreException, AuthenticationFailure {
        Map<String, String> userData = null;
        char[] password = null;

        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            } else if (callback instanceof CarbonCallback) {
                userData = (Map<String, String>) ((CarbonCallback) callback).getContent();
            }
        }

        if (userData == null || password == null || userData.isEmpty()) {
            throw new AuthenticationFailure("Data required for authentication is missing.");
        }



    }

    @Override
    public boolean canHandle(Callback[] callbacks) {
        boolean carbonCallbackPresent = false;
        boolean passwordCallbackPresent = false;

        for (Callback callback : callbacks) {

            if(callback instanceof CarbonCallback){
                carbonCallbackPresent=true;
            }
            if(callback instanceof  PasswordCallback){
                passwordCallbackPresent=true;
            }

        }

        return carbonCallbackPresent && passwordCallbackPresent;

    }

    @Override
    public CredentialStoreConnectorConfig getCredentialStoreConfig() {
        return credentialConnectorConfig;
    }



}

