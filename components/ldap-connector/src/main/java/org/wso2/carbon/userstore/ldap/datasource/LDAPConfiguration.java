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

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.XmlValue;

/**
 * LDAP configuration class.
 */
@XmlRootElement(name = "configuration")
public class LDAPConfiguration {

    private String urlOfDns;
    private String dnsDomainName;
    private String url;
    private String username;
    private Password passwordPersist;
    private String authentication;
    private String connectionTimeout;
    private String readTimeout;
    private String connectionPoolingEnabled;
    private String referral;
    private String binaryAttribute;
    private String poolAuthentication;
    private String poolDebug;
    private String poolInitsize;
    private String poolPrefsize;
    private String poolProtocol;
    private String poolTimeout;
    private String poolMaxsize;

    @XmlElement(name = "urlOfDns")
    public String getUrlOfDns() {
        return urlOfDns;
    }

    public void setUrlOfDns(String urlOfDns) {
        this.urlOfDns = urlOfDns;
    }

    @XmlElement(name = "dnsDomainName")
    public String getDnsDomainName() {
        return dnsDomainName;
    }

    public void setDnsDomainName(String dnsDomainName) {
        this.dnsDomainName = dnsDomainName;
    }

    @XmlElement(name = "url")
    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    @XmlElement(name = "username")
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @XmlTransient
    public String getPassword() {
        if (this.getPasswordPersist() != null) {
            return this.getPasswordPersist().getValue();
        } else {
            return null;
        }
    }

    public void setPassword(String password) {
        if (this.getPasswordPersist() == null) {
            this.passwordPersist = new Password();
        }
        this.passwordPersist.setValue(password);
    }

    @XmlElement(name = "password")
    public Password getPasswordPersist() {
        return passwordPersist;
    }

    public void setPasswordPersist(Password passwordPersist) {
        this.passwordPersist = passwordPersist;
    }

    @XmlElement(name = "authentication")
    public String getAuthentication() {
        return authentication;
    }

    public void setAuthentication(String authentication) {
        this.authentication = authentication;
    }

    @XmlElement(name = "connectionTimeout")
    public String getConnectionTimeout() {
        return connectionTimeout;
    }

    public void setConnectionTimeout(String connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }

    @XmlElement(name = "readTimeout")
    public String getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(String readTimeout) {
        this.readTimeout = readTimeout;
    }

    @XmlElement(name = "connectionPoolingEnabled")
    public String getConnectionPoolingEnabled() {
        return connectionPoolingEnabled;
    }

    public void setConnectionPoolingEnabled(String connectionPoolingEnabled) {
        this.connectionPoolingEnabled = connectionPoolingEnabled;
    }

    @XmlElement(name = "referral")
    public String getReferral() {
        return referral;
    }

    public void setReferral(String referral) {
        this.referral = referral;
    }

    @XmlElement(name = "binaryAttribute")
    public String getBinaryAttribute() {
        return binaryAttribute;
    }

    public void setBinaryAttribute(String binaryAttribute) {
        this.binaryAttribute = binaryAttribute;
    }

    @XmlElement(name = "poolAuthentication")
    public String getPoolAuthentication() {
        return poolAuthentication;
    }

    public void setPoolAuthentication(String poolAuthentication) {
        this.poolAuthentication = poolAuthentication;
    }

    @XmlElement(name = "poolDebug")
    public String getPoolDebug() {
        return poolDebug;
    }

    public void setPoolDebug(String poolDebug) {
        this.poolDebug = poolDebug;
    }

    @XmlElement(name = "poolInitsize")
    public String getPoolInitsize() {
        return poolInitsize;
    }

    public void setPoolInitsize(String poolInitsize) {
        this.poolInitsize = poolInitsize;
    }

    @XmlElement(name = "poolPrefsize")
    public String getPoolPrefsize() {
        return poolPrefsize;
    }

    public void setPoolPrefsize(String poolPrefsize) {
        this.poolPrefsize = poolPrefsize;
    }

    @XmlElement(name = "poolProtocol")
    public String getPoolProtocol() {
        return poolProtocol;
    }

    public void setPoolProtocol(String poolProtocol) {
        this.poolProtocol = poolProtocol;
    }

    @XmlElement(name = "poolTimeout")
    public String getPoolTimeout() {
        return poolTimeout;
    }

    public void setPoolTimeout(String poolTimeout) {
        this.poolTimeout = poolTimeout;
    }

    @XmlElement(name = "poolMaxsize")
    public String getPoolMaxsize() {
        return poolMaxsize;
    }

    public void setPoolMaxsize(String poolMaxsize) {
        this.poolMaxsize = poolMaxsize;
    }

    /**
     * Bean class holding password.
     */
    @XmlRootElement(name = "password")
    public static class Password {

        private boolean encrypted = true;

        private String value;

        @XmlAttribute(name = "encrypted")
        public boolean isEncrypted() {
            return encrypted;
        }

        public void setEncrypted(boolean encrypted) {
            this.encrypted = encrypted;
        }

        @XmlValue
        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

    }
}
