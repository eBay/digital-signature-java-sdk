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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class VerificationService {

    private final Pattern signatureInputPattern = Pattern
        .compile(".+=(\\((.+)\\);created=(\\d+)(;keyid=.+)?)");
    private final Pattern signaturePattern = Pattern.compile(".+=:(.+):");
    private final Pattern contentDigestPattern = Pattern.compile("(.+)=:(.+):");

    /**
     * Verify all signature headers
     *
     * @param body request body
     * @param headers request headers
     * @param signatureConfig signature config
     * @return boolean verification success
     * @throws SignatureException signature exception
     */
    public boolean verification(String body, Map<String, String> headers,
        SignatureConfig signatureConfig) throws SignatureException {
        String base = null;
        try {
            base = calculateBase(body, headers, signatureConfig);
            PublicKey publicKey = verifyJWT(headers, signatureConfig);
            verifyDigestHeader(body, headers);
            verifySignature(publicKey, base, headers);
        } catch (SignatureException ex) {
            throw new SignatureException(
                "Error in verification base: " + ex.getMessage(), ex);
        }
        return true;
    }

    /**
     * Validate Content Digest
     *
     * @param body request body
     * @param headers request headers
     * @return isValid Content digest validity
     */
    public boolean validateDigestHeader(String body,
        Map<String, String> headers) {
        boolean isValid = false;
        try {
            verifyDigestHeader(body, headers);
            isValid = true;
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return isValid;
    }

    /**
     * Validate Signature Header
     *
     * @param body request body
     * @param headers request headers
     * @param signatureConfig signature config
     * @return isValid signature header validity
     */
    public boolean validateSignatureHeader(String body, Map<String, String> headers,
        SignatureConfig signatureConfig) {
        boolean isValid = false;

        String base = null;
        PublicKey publickey = null;
        try {
            base = calculateBase(body, headers, signatureConfig);
            publickey = verifyJWT(headers, signatureConfig);
            verifySignature(publickey, base, headers);
            isValid = true;
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return isValid;
    }

    /**
     * Verify 'signature' header
     *
     * @param publicKey public key
     * @param base base string
     * @param headers request headers
     * @throws SignatureException signature exception
     */
    public void verifySignature(PublicKey publicKey, String base,
        Map<String, String> headers) throws SignatureException {
        if (!headers.containsKey(Constants.SIGNATURE_HEADER.toLowerCase())) {
            throw new SignatureException("Signature header missing");
        }

        String signatureHeader = headers.get(Constants.SIGNATURE_HEADER.toLowerCase());
        Matcher signatureMatcher = signaturePattern.matcher(signatureHeader);
        if (!signatureMatcher.find()) {
            throw new SignatureException("Signature header invalid");
        }
        String signature = signatureMatcher.group(1);

        byte[] signatureBytes;
        try {
            signatureBytes = Base64.decode(signature);
        } catch (Exception ex) {
            throw new SignatureException(
                "Signature not a valid Base64: " + ex.getMessage(), ex);
        }

        String algorithm = publicKey.getAlgorithm();
        Signer signer;
        if (algorithm.equals(Constants.ALGORITHM_RSA)) {
            signer = new RSADigestSigner(new SHA256Digest());
        } else {
            signer = new Ed25519Signer();
        }

        try {
            AsymmetricKeyParameter publicKeyParameters = PublicKeyFactory
                .createKey(publicKey.getEncoded());
            signer.init(false, publicKeyParameters);
            byte[] baseBytes = base.getBytes(StandardCharsets.UTF_8);
            signer.update(baseBytes, 0, baseBytes.length);
            boolean verified = signer.verifySignature(signatureBytes);

            if (!verified) {
                throw new SignatureException("Signature invalid");
            }
        } catch (IOException ex) {
            throw new SignatureException(
                "Error validating signature: " + ex.getMessage(), ex);
        }
    }

    /**
     * Verify Content Digest
     *
     * @param body request body
     * @param headers request headers
     * @throws SignatureException signature exception
     */
    public void verifyDigestHeader(String body, Map<String, String> headers)
        throws SignatureException {
        try {
            if (!headers.containsKey(Constants.CONTENT_DIGEST)) {
                //Content Digest is missing. Assuming it is GET method
                return;
            }

            String contentDigestHeader = headers.get(Constants.CONTENT_DIGEST);
            Matcher contentDigestMatcher = contentDigestPattern
                .matcher(contentDigestHeader);
            if (!contentDigestMatcher.find()) {
                throw new SignatureException("Content-digest header invalid");
            }
            String cipher = contentDigestMatcher.group(1);
            String digest = contentDigestMatcher.group(2);

            if (!cipher.equals(Constants.SHA256) && !cipher.equals(Constants.SHA512)) {
                throw new SignatureException("Invalid cipher " + cipher);
            }

            MessageDigest messageDigest = MessageDigest
                .getInstance(cipher.toUpperCase());
            String newDigest = new String(Base64.encode(
                messageDigest.digest(body.getBytes(StandardCharsets.UTF_8))));

            if (!newDigest.equals(digest)) {
                throw new SignatureException(
                    "Content-Digest value is invalid. Expected body digest is: "
                        + newDigest);
            }
        } catch (NoSuchAlgorithmException | SignatureException ex) {
            throw new SignatureException(
                "Error creating message digest: " + ex.getMessage(), ex);
        }
    }

    /**
     * Verify JWT and return public key
     *
     * @param headers request headers
     * @param signatureConfig signature config
     * @return publicKey public key
     * @throws SignatureException signature exception
     */
    PublicKey verifyJWT(Map<String, String> headers,
        SignatureConfig signatureConfig) throws SignatureException {
        if (!headers.containsKey(Constants.X_EBAY_SIGNATURE_HEADER)) {
            throw new SignatureException("x-ebay-signature-key header missing");
        }

        String jwtString = headers.get(Constants.X_EBAY_SIGNATURE_HEADER);
        EncryptedJWT jwe = decryptJWE(jwtString, signatureConfig);

        try {
            JWTClaimsSet jwtClaimsSet = jwe.getJWTClaimsSet();
            // TODO: additional validation of expiration, appID etc
            byte[] keyBytes = Base64
                .decode((String) jwtClaimsSet.getClaim("pkey"));

            KeyFactory keyFactory = KeyFactory.getInstance(signatureConfig.getAlgorithm());
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return keyFactory.generatePublic(keySpec);
        } catch (ParseException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new SignatureException(
                "Error parsing JWE from x-ebay-signature-key header: " + ex
                    .getMessage(), ex);
        }
    }

    /**
     * Get Encrypted JWT value from JWE
     * @param jweString JWE string
     * @return encryptedJWT encrypted JWT
     * @throws SignatureException signature exception
     */
    EncryptedJWT decryptJWE(String jweString, SignatureConfig signatureConfig) throws SignatureException {
        try {
            EncryptedJWT jwe = EncryptedJWT.parse(jweString);
            String secretKeyBase64 = Files.readAllLines(Paths.get(signatureConfig.getMasterKey())).get(0);;
            final byte[] secretKey = Base64.decode(secretKeyBase64);
            JWEDecrypter jweDecrypter = new AESDecrypter(secretKey);
            jwe.decrypt(jweDecrypter);
            return jwe;
        } catch (ParseException | JOSEException | IOException ex) {
            throw new SignatureException("Error decrypting the JWE from x-ebay-signature-key header", ex);
        }
    }

    /**
     * Method to calculate base string value
     *
     * @param body request body
     * @param headers request headers
     * @param signatureConfig signature config
     * @return calculatedBase base string
     * @throws SignatureException signature exception
     */
    String calculateBase(String body, Map<String, String> headers,
        SignatureConfig signatureConfig) throws SignatureException {
        try {
            String signatureInputHeader = headers.get(Constants.SIGNATURE_INPUT_HEADER.toLowerCase());
            if (!headers.containsKey(Constants.SIGNATURE_INPUT_HEADER.toLowerCase())) {
                throw new SignatureException("Signature-Input header missing");
            }

            Matcher signatureInputMatcher = signatureInputPattern
                .matcher(signatureInputHeader);
            if (!signatureInputMatcher.find()) {
                throw new SignatureException(
                    "Invalid signature-input. Make sure it's of format: .+=\\(.+\\;created=\\d+)");
            }
            String signatureInput = signatureInputMatcher.group(2)
                .replaceAll("\"", "");
            List<String> signatureParams = Stream.of(signatureInput.split(" "))
                .collect(Collectors.toList());

            if (signatureParams.contains(Constants.CONTENT_DIGEST)) {
                if((StringUtils.isBlank(body) || headers.get(Constants.CONTENT_DIGEST) == null)){
                    throw new SignatureException(
                        "Invalid Signature-Input for request body or content-digest");
                }
            } else {
                if((StringUtils.isNotBlank(body) || headers.get(Constants.CONTENT_DIGEST) != null)){
                    throw new SignatureException(
                        "Invalid Signature-Input for request body or content-digest");
                }
            }

            SignatureComponent signatureComponent = signatureConfig
                .getSignatureComponents();
            StringBuilder buf = new StringBuilder();

            for (String header : signatureParams) {
                if (header.equalsIgnoreCase(Constants.CONTENT_DIGEST)
                    && StringUtils.isBlank(body)) {
                    throw new SignatureException(
                        "Header " + header + " require body to be present in request");
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
            buf.append(signatureInputMatcher.group(1));
            return buf.toString();
        } catch (Exception ex) {
            throw new SignatureException(
                "Error calculating base: " + ex.getMessage(), ex);
        }
    }
}
