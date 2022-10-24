/*
 * *
 *  * Copyright 2022 eBay Inc.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *  http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *  *
 */
package com.ebay.developer;

/**
 * Signature Component include request details
 */
public class SignatureComponent {
    private String method;
    private String authority;
    private String targetUri;
    private String path;
    private String scheme;
    private String requestTarget;

    /**
     * Get Method type
     * @return method type
     */
    public String getMethod() {
        return method;
    }

    /**
     * Set Method type
     * @param method method type
     */
    public void setMethod(String method) {
        this.method = method;
    }

    /**
     * Get Authority
     * @return authority
     */
    public String getAuthority() {
        return authority;
    }

    /**
     * Set Authority
     * @param authority authority
     */
    public void setAuthority(String authority) {
        this.authority = authority;
    }

    /**
     * Get Target URI
     * @return target uri
     */
    public String getTargetUri() {
        return targetUri;
    }

    /**
     * Set Target URI
     * @param targetUri target uri
     */
    public void setTargetUri(String targetUri) {
        this.targetUri = targetUri;
    }

    /**
     * Get the path
     * @return path
     */
    public String getPath() {
        return path;
    }

    /**
     * Set Path
     * @param path path
     */
    public void setPath(String path) {
        this.path = path;
    }

    /**
     * Get Scheme
     * @return schema
     */
    public String getScheme() {
        return scheme;
    }

    /**
     * Set Scheme
     * @param scheme schema
     */
    public void setScheme(String scheme) {
        this.scheme = scheme;
    }

    /**
     * Get Request Type
     * @return request type
     */
    public String getRequestTarget() {
        return requestTarget;
    }

    /**
     * Set Request Type
     * @param requestTarget request type
     */
    public void setRequestTarget(String requestTarget) {
        this.requestTarget = requestTarget;
    }

    @Override
    public String toString() {
        return "SignatureComponent{" + "method='" + method + '\''
            + ", authority='" + authority + '\'' + ", targetUri='" + targetUri
            + '\'' + ", path='" + path + '\'' + ", scheme='" + scheme + '\''
            + ", requestTarget='" + requestTarget + '\'' + '}';
    }
}
