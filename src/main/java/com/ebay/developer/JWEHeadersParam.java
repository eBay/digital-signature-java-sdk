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
 * JWEHeadersParam used for JWE header params
 */
public class JWEHeadersParam {
    private String alg;
    private String enc;
    private String zip;

    /**
     * Get Algorithm
     * @return algo
     */
    public String getAlg() {
        return alg;
    }

    /**
     * Set Algorithm
     * @param alg
     */
    public void setAlg(String alg) {
        this.alg = alg;
    }

    /**
     * Get Encryption
     * @return encryption
     */
    public String getEnc() {
        return enc;
    }

    /**
     * Set Encryption
     * @param enc
     */
    public void setEnc(String enc) {
        this.enc = enc;
    }

    /**
     * Get Compression method
     * @return compression
     */
    public String getZip() {
        return zip;
    }

    /**
     * Set Compression method
     * @param zip
     */
    public void setZip(String zip) {
        this.zip = zip;
    }

    @Override
    public String toString() {
        return "JWEHeadersParam{" + "alg='" + alg + '\'' + ", enc='" + enc
            + '\'' + ", zip='" + zip + '\'' + '}';
    }
}
