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
package org.wso2.carbon.userstore.ldap.datasource.beans;

import java.util.Hashtable;

/**
 * Bean class to hold LDAP connection details.
 */
public class LDAPDataSource {

    private Hashtable dnsProperties;
    private Hashtable environment;
    private Hashtable poolingProperties;

    public LDAPDataSource() {
        environment = new Hashtable<String, String>();
        poolingProperties = new Hashtable<String, String>();
        dnsProperties = new Hashtable<String, String>();
    }

    public void addDnsProperty(String property, String value) {
        if (value != null) {
            dnsProperties.put(property, value);
        }
    }

    public void addEnvironmentProperty(String property, String value) {
        if (value != null) {
            environment.put(property, value);
        }
    }

    public void addPoolingProperty(String property, String value) {
        if (value != null) {
            poolingProperties.put(property, value);
        }
    }

    public Hashtable getEnvironment() {
        return (Hashtable) environment.clone();
    }

    public Hashtable getPoolingProperties() {
        return (Hashtable) poolingProperties.clone();
    }

    public Hashtable getDnsProperties() {
        return (Hashtable) dnsProperties.clone();
    }
}
