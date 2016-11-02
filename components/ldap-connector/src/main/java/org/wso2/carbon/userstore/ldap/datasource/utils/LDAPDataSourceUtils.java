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
package org.wso2.carbon.userstore.ldap.datasource.utils;

import org.wso2.carbon.datasource.core.exception.DataSourceException;
import org.wso2.carbon.datasource.utils.DataSourceUtils;
import org.wso2.carbon.userstore.ldap.datasource.LDAPConfiguration;
import org.wso2.carbon.userstore.ldap.datasource.LDAPConstants;
import org.wso2.carbon.userstore.ldap.datasource.beans.LDAPDataSource;

import javax.naming.Context;

/**
 * utility methods for LDAPDataSource.
 */
public class LDAPDataSourceUtils {

    /**
     * Generate the configuration bean by reading the xml configuration.
     *
     * @param xmlConfiguration String
     * @return {@code }
     * @throws DataSourceException
     */
    public static LDAPDataSource buildConfiguration(String xmlConfiguration) throws DataSourceException {
        try {
            LDAPConfiguration config = DataSourceUtils.loadJAXBConfiguration(xmlConfiguration, LDAPConfiguration.class);
            LDAPDataSource ldapDataSource = new LDAPDataSource();

            //set LDAP Initial context factory
            ldapDataSource.addEnvironmentProperty(Context.INITIAL_CONTEXT_FACTORY, LDAPConstants.LDAP_CONTEXT_FACTORY);

            //set DNS related properties
            ldapDataSource.addDnsProperty(LDAPConstants.DNS_URL, config.getUrlOfDns());
            ldapDataSource.addDnsProperty(LDAPConstants.DNS_DOMAIN_NAME, config.getDnsDomainName());

            //set LDAP environment properties
            ldapDataSource.addEnvironmentProperty(Context.SECURITY_PRINCIPAL, config.getUsername());
            ldapDataSource.addEnvironmentProperty(Context.PROVIDER_URL, config.getUrl());
            ldapDataSource.addEnvironmentProperty(Context.SECURITY_CREDENTIALS, config.getPassword());
            ldapDataSource.addEnvironmentProperty(Context.SECURITY_AUTHENTICATION, config.getAuthentication());
            ldapDataSource.addEnvironmentProperty(LDAPConstants.LDAP_CONNECTION_TIMEOUT, config.getConnectionTimeout());
            ldapDataSource.addEnvironmentProperty(LDAPConstants.LDAP_READ_TIMEOUT, config.getReadTimeout());
            ldapDataSource.addEnvironmentProperty(LDAPConstants.LDAP_ATTRIBUTES_BINARY, config.getBinaryAttribute());
            ldapDataSource
                    .addEnvironmentProperty(LDAPConstants.LDAP_POOLING_ENABLED, config.getConnectionPoolingEnabled());
            ldapDataSource.addEnvironmentProperty(LDAPConstants.LDAP_REFERRAL, config.getReferral());

            //set LDAP pooling properties
            ldapDataSource.addPoolingProperty(LDAPConstants.LDAP_POOL_AUTHENTICATION, config.getPoolAuthentication());
            ldapDataSource.addPoolingProperty(LDAPConstants.LDAP_POOL_DEBUG, config.getPoolDebug());
            ldapDataSource.addPoolingProperty(LDAPConstants.LDAP_POOL_INITSIZE, config.getPoolInitsize());
            ldapDataSource.addPoolingProperty(LDAPConstants.LDAP_POOL_MAXSIZE, config.getPoolMaxsize());
            ldapDataSource.addPoolingProperty(LDAPConstants.LDAP_POOL_PREFSIZE, config.getPoolPrefsize());
            ldapDataSource.addPoolingProperty(LDAPConstants.LDAP_POOL_PROTOCOL, config.getPoolProtocol());
            ldapDataSource.addPoolingProperty(LDAPConstants.LDAP_POOL_TIMEOUT, config.getPoolTimeout());

            return ldapDataSource;
        } catch (DataSourceException e) {
            throw new DataSourceException("Error in loading LDAP configuration: ", e);
        }
    }

}


