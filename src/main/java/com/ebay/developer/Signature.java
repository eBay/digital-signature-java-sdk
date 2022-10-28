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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import static com.ebay.developer.Constants.*;

public class Signature {
    private final SignatureConfig signatureConfig;
    private final SignatureService signatureService;
    private final VerificationService verificationService;

    public Signature(String configPath) throws SignatureConfigException {
        signatureConfig = loadSignatureConfig(configPath);
        signatureService = new SignatureService();
        verificationService = new VerificationService();
    }

    public Signature(SignatureConfig signatureConfig) {
        this.signatureConfig = signatureConfig;
        signatureService = new SignatureService();
        verificationService = new VerificationService();
    }

    /**
     * Get Request signed
     *
     * @param request  HTTP request
     * @param response HTTP response
     * @return response HTTP response
     * @throws IOException        Input/Output exception
     * @throws SignatureException signature exception
     */
    public HttpServletResponse getSignedRequest(HttpServletRequest request, HttpServletResponse response)
            throws IOException, SignatureException {
        String body = IOUtils.toString(request.getReader());
        String contentDigest = generateDigestHeader(body);
        String signatureKeyHeader = generateSignatureKey();
        Map<String, String> headers = new HashMap<>();
        if (StringUtils.isNotBlank(contentDigest)) {
            headers.put(CONTENT_DIGEST, contentDigest);
            response.setHeader(CONTENT_DIGEST_HEADER, contentDigest);
        }
        headers.put(X_EBAY_SIGNATURE_HEADER, signatureKeyHeader);
        response.setHeader(X_EBAY_SIGNATURE_HEADER, signatureKeyHeader);
        response.setHeader(SIGNATURE_HEADER, getSignature(headers));
        response.setHeader(SIGNATURE_INPUT_HEADER, generateSignatureInput(contentDigest));
        return response;
    }

    /**
     * Get Signature Object in response
     *
     * @param body request body
     * @return signature headers
     * @throws SignatureException      signature exception
     * @throws JsonProcessingException Json processing exception
     */
    public String getSignatureJson(String body)
            throws SignatureException, JsonProcessingException {

        Map<String, String> headers = new HashMap<>();
        String contentDigest = signatureService
                .generateContentDigest(body, signatureConfig);
        if (StringUtils.isNotBlank(contentDigest)) {
            headers.put(CONTENT_DIGEST, contentDigest);
        }


        String xEbaySignatureKey = signatureService
                .generateSignatureKeyHeader(signatureConfig);
        headers.put(X_EBAY_SIGNATURE_HEADER, xEbaySignatureKey);

        String signature = signatureService
                .getSignature(headers, signatureConfig);

        String signatureInput = SIGNATURE_INPUT_PREFIX + signatureService
                .getSignatureInput(contentDigest, signatureConfig.getSignatureParams());

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode sign = mapper.createObjectNode();
        if (StringUtils.isNotBlank(contentDigest)) {
            sign.put(CONTENT_DIGEST_PARAM, contentDigest);
        }
        sign.put(X_EBAY_SIGNATURE_PARAM, xEbaySignatureKey);
        sign.put(SIGNATURE_INPUT_PARAM, signatureInput);
        sign.put(SIGNATURE_PARAM, signature);

        return mapper
                .writerWithDefaultPrettyPrinter()
                .writeValueAsString(sign);
    }

    /**
     * Get Signature Header as Map
     *
     * @param body request body
     * @return signature headers
     * @throws SignatureException signature exception
     */
    public Map<String, String> getSignatureHeaderAsMap(String body)
            throws SignatureException {

        final Map<String, String> headers = new HashMap<>();
        final String contentDigest = generateDigestHeader(body);
        final String xEbaySignatureKey = generateSignatureKey();
        headers.put(X_EBAY_SIGNATURE_HEADER.toLowerCase(), xEbaySignatureKey);

        final ObjectMapper mapper = new ObjectMapper();
        final ObjectNode sign = mapper.createObjectNode();
        if (StringUtils.isNotBlank(contentDigest)) {
            headers.put(CONTENT_DIGEST.toLowerCase(), contentDigest);
            sign.put(CONTENT_DIGEST_HEADER.toLowerCase(), contentDigest);
        }
        sign.put(X_EBAY_SIGNATURE_HEADER.toLowerCase(), xEbaySignatureKey);
        sign.put(SIGNATURE_HEADER.toLowerCase(), getSignature(headers));
        sign.put(SIGNATURE_INPUT_HEADER.toLowerCase(), generateSignatureInput(contentDigest));

        return mapper.convertValue(sign, new TypeReference<HashMap<String,String>>(){});
    }

    /**
     * Get the SignatureConfig
     *
     * @return signatureConfig
     */
    public SignatureConfig getSignatureConfig() {
        return signatureConfig;
    }

    /**
     * Generate Content digest
     *
     * @param body request body
     * @return contentDigest content digest
     * @throws SignatureException signature exception
     */
    public String generateDigestHeader(String body) throws SignatureException {
        return signatureService.generateContentDigest(body, signatureConfig);
    }

    /**
     * Get 'Signature' header value
     *
     * @param headers request headers
     * @return signature signature string
     * @throws SignatureException signature exception
     */
    public String getSignature(Map<String, String> headers) throws SignatureException {
        return signatureService.getSignature(headers, signatureConfig);
    }

    /**
     * Generate Signature Key header
     *
     * @return signatureKeyHeader signature key header
     * @throws SignatureException signature exception
     */
    public String generateSignatureKey()
            throws SignatureException {
        return signatureService.generateSignatureKeyHeader(signatureConfig);
    }

    /**
     * Generate Signature Input header
     *
     * @param contentDigest content digest
     * @return signatureInputHeader signature key header
     */
    public String generateSignatureInput(String contentDigest) {
        return "sig1=" + signatureService.getSignatureInput(contentDigest, signatureConfig.getSignatureParams());
    }

    /**
     * Verify all signature headers
     *
     * @param body    request body
     * @param headers request headers
     * @return boolean Signature validity
     * @throws SignatureException signature exception
     */
    public boolean validateSignature(String body, Map<String, String> headers) throws SignatureException {

        return verificationService.verification(body, headers, signatureConfig);
    }

    /**
     * Validate Content Digest
     *
     * @param body    response body
     * @param headers response headers
     * @return boolean content digest validity
     */
    public boolean validateDigestHeader(String body,
                                        Map<String, String> headers) {
        return verificationService.validateDigestHeader(body, headers);
    }

    /**
     * Validate Signature Header
     *
     * @param body    request body
     * @param headers request headers
     * @return boolean Signature header validity
     */
    public boolean validateSignatureHeader(String body, Map<String, String> headers) {
        return verificationService
                .validateSignatureHeader(body, headers, signatureConfig);
    }

    /**
     * Load config value into SignatureConfig Object
     *
     * @param configPath config path
     * @return SignatureConfig signature config
     * @throws SignatureConfigException
     */
    private SignatureConfig loadSignatureConfig(String configPath)
            throws SignatureConfigException {
        SignatureConfig signatureConfig;
        ObjectMapper mapper = new ObjectMapper();

        // convert JSON file to map
        try {
            signatureConfig = mapper.readValue(Paths.get(configPath).toFile(),
                    SignatureConfig.class);
            if (signatureConfig == null) {
                throw new SignatureConfigException("Failed to map config fields");
            }
        } catch (IOException e) {
            e.printStackTrace();
            throw new SignatureConfigException("Failed to load config file");
        }
        return signatureConfig;
    }
}
