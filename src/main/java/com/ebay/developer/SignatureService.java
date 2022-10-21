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

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class SignatureService {

    /**
     * Generate Content Digest
     *
     * @param body
     * @param signatureConfig
     * @return contentDigest
     * @throws SignatureException
     */
    public String generateContentDigest(String body,
        SignatureConfig signatureConfig) throws SignatureException {

        if(StringUtils.isBlank(body)){
            return null;
        }

        String contentDigest = "";
        String cipher = signatureConfig.getDigestAlgorithm();
        try {
            MessageDigest messageDigest = MessageDigest
                .getInstance(cipher.toUpperCase());
            String digest = new String(Base64.encode(
                messageDigest.digest(body.getBytes(StandardCharsets.UTF_8))));
            if (StringUtils.isNotBlank(digest)) {
                contentDigest = new StringBuilder().append(cipher).append("=:")
                    .append(digest).append(":").toString();
            }

        } catch (Exception ex) {
            throw new SignatureException(
                "Error generating Content-Digest header: " + ex.getMessage(),
                ex);
        }
        return contentDigest;

    }

    /**
     * Generate Signature Key Header
     *
     * @param signatureConfig
     * @return signature key header
     */
    public String generateSignatureKeyHeader(SignatureConfig signatureConfig)
        throws SignatureException {
        return getJWE(signatureConfig);
    }

    /**
     * Generate Signature Input header
     *
     * @param contentDigest
     * @param signatureParams
     * @return signatureInputHeader
     */
    public String getSignatureInput(String contentDigest, List<String> signatureParams) {
        StringBuilder signatureInputBuf = new StringBuilder();
        signatureInputBuf.append("(");

        for (int i = 0; i < signatureParams.size(); i++) {
            String param = signatureParams.get(i);
            if(param.equalsIgnoreCase(Constants.CONTENT_DIGEST) && contentDigest==null){
                continue;
            }
            signatureInputBuf.append("\"");
            signatureInputBuf.append(param);
            signatureInputBuf.append("\"");
            if (i < signatureParams.size() - 1) {
                signatureInputBuf.append(" ");
            }
        }

        signatureInputBuf.append(");created=");
        signatureInputBuf.append(Instant.now().getEpochSecond());
        return signatureInputBuf.toString();
    }

    /**
     * Get 'Signature' header value
     *
     * @param headers
     * @param signatureConfig
     * @return signature
     * @throws SignatureException
     */
    public String getSignature(Map<String, String> headers,
        SignatureConfig signatureConfig) throws SignatureException {
        try {
            String baseString = calculateBase(headers, signatureConfig);
            byte[] base = baseString.getBytes(StandardCharsets.UTF_8);

            Signer signer;
            if (signatureConfig.getAlgorithm().equals(Constants.ALGORITHM_RSA)) {
                signer = new RSADigestSigner(new SHA256Digest());
            } else {
                signer = new Ed25519Signer();
            }
            AsymmetricKeyParameter privateKeyParameters = PrivateKeyFactory
                .createKey(signatureConfig.getPrivateKey().getEncoded());
            signer.init(true, privateKeyParameters);
            signer.update(base, 0, base.length);
            byte[] signature = signer.generateSignature();

            String signatureStr = new String(Base64.encode(signature));
            return new StringBuilder().append(Constants.SIGNATURE_PREFIX).append(signatureStr)
                .append(":").toString();
        } catch (CryptoException | IOException ex) {
            throw new SignatureException(
                "Error creating value for signature: " + ex.getMessage(), ex);
        }
    }

    /**
     * Get JWE value
     * @param signatureConfig
     * @return JWE
     * @throws SignatureException
     */
    String getJWE(SignatureConfig signatureConfig) throws SignatureException {
        try {

            if(StringUtils.isNotBlank(signatureConfig.getJwe())){
                return signatureConfig.getJwe();
            }
            // Compose the JWT claims set
            Date now = new Date();

            JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .expirationTime(new Date(now.getTime() + 1000L * 60 * 60 * 24 * 365 * signatureConfig.getJwtExpirationYear())) // expires in 3 years
                .notBeforeTime(now)
                .issueTime(now)
                .jwtID(UUID.randomUUID().toString())
                .claim("pkey", signatureConfig.getJwtPayload().getPkey()) // public ed25519 key
                .build();


            // Request JWT encrypted with DIR and 256-bit AES/GCM
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.parse(signatureConfig.getJweHeadersParam().getAlg()), EncryptionMethod
                .parse(signatureConfig.getJweHeadersParam().getEnc()))
                .compressionAlgorithm(new CompressionAlgorithm(signatureConfig.getJweHeadersParam().getZip()))
                .build();

            String secretKeyBase64 = Files.readAllLines(Paths.get(signatureConfig.getMasterKey())).get(0);
            final byte[] secretKey = Base64.decode(secretKeyBase64);
            JWEEncrypter jweEncrypter = new AESEncrypter(secretKey);

            // Create the encrypted JWT object
            EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);

            // Do the actual encryption
            jwt.encrypt(jweEncrypter);

            // Serialise to JWT compact form
            String jwtString = jwt.serialize();

            return jwtString;
        } catch (JOSEException | IOException ex) {
            throw new SignatureException("Error creating JWE: " + ex.getMessage(), ex);
        }

    }

    /**
     * Method to calculate base string value
     *
     * @param headers
     * @param signatureConfig
     * @return calculatedBase
     * @throws SignatureException
     */
     String calculateBase(Map<String, String> headers,
        SignatureConfig signatureConfig) throws SignatureException {
        try {
            StringBuilder buf = new StringBuilder();
            SignatureComponent signatureComponent = signatureConfig
                .getSignatureComponents();
            List<String> signatureParams = signatureConfig.getSignatureParams();
            for (String header : signatureParams) {
                if (header.equalsIgnoreCase(Constants.CONTENT_DIGEST)
                    && headers.get(Constants.CONTENT_DIGEST) == null) {
                    continue;
                }
                buf.append("\"");
                buf.append(header.toLowerCase());
                buf.append("\": ");

                if (header.startsWith("@")) {
                    switch (header.toLowerCase()) {
                    case "@method":
                        buf.append(signatureComponent.getMethod());
                        break;
                    case "@authority":
                        buf.append(signatureComponent.getAuthority());
                        break;
                    case "@target-uri":
                        buf.append(signatureComponent.getTargetUri());
                        break;
                    case "@path":
                        buf.append(signatureComponent.getPath());
                        break;
                    case "@scheme":
                        buf.append(signatureComponent.getScheme());
                        break;
                    case "@request-target":
                        buf.append(signatureComponent.getRequestTarget());
                        break;
                    default:
                        throw new SignatureException(
                            "Unknown pseudo header " + header);
                    }
                } else {
                    if (!headers.containsKey(header)) {
                        throw new SignatureException(
                            "Header " + header + " not included in message");
                    }

                    buf.append(headers.get(header));
                }

                buf.append("\n");
            }

            buf.append("\"@signature-params\": ");
            buf.append(getSignatureInput(headers.get(Constants.CONTENT_DIGEST), signatureParams));
            return buf.toString();
        } catch (Exception ex) {
            throw new SignatureException(
                "Error calculating signature base: " + ex.getMessage(), ex);
        }
    }

}
