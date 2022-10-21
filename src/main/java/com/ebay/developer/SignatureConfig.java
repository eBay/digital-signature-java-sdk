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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.List;

/**
 * Signature Config used for load config details
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SignatureConfig {

    @JsonProperty("digestAlgorithm")
    private String digestAlgorithm;

    @JsonProperty("algorithm")
    private String algorithm;

    @JsonProperty("masterKey")
    private String masterKey;

    @JsonProperty("privateKey")
    private String privateKeyStr;

    @JsonProperty("publicKey")
    private String publicKeyStr;

    @JsonProperty("jwe")
    private String jwe;

    @JsonProperty("jwtExpiration")
    private String jwtExpiration;

    @JsonProperty("jwtPayload")
    private JWTPayload jwtPayload;

    @JsonProperty("signatureParams")
    private List<String> signatureParams;

    @JsonProperty("signatureComponents")
    private SignatureComponent signatureComponents;

    @JsonProperty("jweHeaderParams")
    private JWEHeadersParam jweHeadersParam;

    @JsonIgnore
    private PublicKey publicKey;

    @JsonIgnore
    private PrivateKey privateKey;

    public SignatureConfig() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Get digest algorithm
     * @return digest algo
     */
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Get signing algorithm
     * @return signing algorithm
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Get Signature params
     * @return signature params
     */
    public List<String> getSignatureParams() {
        return signatureParams;
    }

    /**
     * Get JWT expiration value
     * @return JWT expiration value
     */
    public String getJwtExpiration() {
        return jwtExpiration;
    }

    /**
     * Get JWT payload value
     * @return JWT payload value
     */
    public JWTPayload getJwtPayload() {
        return jwtPayload;
    }

    /**
     * Get Master Key
     * @return Master Key
     */
    public String getMasterKey() {
        return masterKey;
    }

    /**
     * Get JWE string
     * @return JWE string
     */
    public String getJwe() {
        return jwe;
    }

    /**
     * Get Signature Components
     * @return signature Components
     */
    public SignatureComponent getSignatureComponents() {
        return signatureComponents;
    }

    /**
     * Get JWE header params
     * @return JWE header params
     */
    public JWEHeadersParam getJweHeadersParam() {
        return jweHeadersParam;
    }

    /**
     * Extract JWT expiration year value from Config
     *
     * @return JWT expiration year value
     */
    @JsonIgnore
    public int getJwtExpirationYear() {
        if (jwtExpiration != null) {
            return Integer.parseInt(jwtExpiration);
        }
        //default to 3 Years
        return 3;
    }

    @Override
    public String toString() {
        return "SignatureConfig{" + "digestAlgorithm='" + digestAlgorithm + '\''
            + ", algorithm='" + algorithm + '\'' + ", masterKey='" + masterKey
            + '\'' + ", privateKeyStr='" + privateKeyStr + '\''
            + ", publicKeyStr='" + publicKeyStr + '\'' + ", jwe='" + jwe + '\''
            + ", jwtExpiration='" + jwtExpiration + '\'' + ", jwtPayload="
            + jwtPayload + ", signatureParams=" + signatureParams
            + ", signatureComponents=" + signatureComponents
            + ", jweHeadersParam=" + jweHeadersParam + ", publicKey="
            + publicKey + ", privateKey=" + privateKey + '}';
    }

    /**
     * Get public key value as a file or as a string value
     *
     * @return publicKey
     * @throws SignatureException
     */
    public PublicKey getPublicKey() throws SignatureException {
        if (publicKey != null) {
            return publicKey;
        }

        Reader reader = null;
        if (publicKeyStr.contains("-----BEGIN PUBLIC KEY-----")) {
            reader = new StringReader(publicKeyStr);
        } else {
            try {
                reader = new FileReader(publicKeyStr);
            } catch (FileNotFoundException e) {
                throw new SignatureException(
                    "Error loading public file: " + e.getMessage(), e);
            }
        }
        publicKey = getPublic(reader);
        return publicKey;
    }

    /**
     * Get private key value as a file or as a string value
     *
     * @return privateKey
     * @throws SignatureException
     */
    public PrivateKey getPrivateKey() throws SignatureException {
        if (privateKey != null) {
            return privateKey;
        }

        Reader reader = null;
        if (privateKeyStr.contains("-----BEGIN PRIVATE KEY-----")) {
            reader = new StringReader(privateKeyStr);
        } else {
            try {
                reader = new FileReader(privateKeyStr);
            } catch (FileNotFoundException e) {
                throw new SignatureException(
                    "Error loading private file: " + e.getMessage(), e);
            }
        }
        privateKey = getPrivate(reader);
        return privateKey;
    }

    /**
     * Extract Private key from reader(string or file)
     *
     * @param reader
     * @return privateKey
     * @throws SignatureException
     */
    private PrivateKey getPrivate(Reader reader) throws SignatureException {
        try {
            PEMParser pemParser = new PEMParser(reader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo
                .getInstance(pemParser.readObject());
            return converter.getPrivateKey(privateKeyInfo);
        } catch (PEMException ex) {
            throw new SignatureException(
                "Error parsing private key: " + ex.getMessage(), ex);
        } catch (IOException e) {
            throw new SignatureException(
                "Error loading private file: " + e.getMessage(), e);
        }
    }

    /**
     * Extract Public key from reader(string or file)
     *
     * @param reader
     * @return publicKey
     * @throws SignatureException
     */
    private PublicKey getPublic(Reader reader) throws SignatureException {
        try {
            PEMParser pemParser = new PEMParser(reader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo
                .getInstance(pemParser.readObject());
            return converter.getPublicKey(publicKeyInfo);
        } catch (PEMException ex) {
            throw new SignatureException(
                "Error parsing public key: " + ex.getMessage(), ex);
        } catch (IOException e) {
            throw new SignatureException(
                "Error loading public file: " + e.getMessage(), e);
        }
    }
}
