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
package com.ebay.example;

import com.ebay.developer.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
public class SignatureController {

    public Signature signatureFull;
    public Signature signature;

    /**
     * Get config details
     *
     * @return config
     */
    @GetMapping("/config")
    public SignatureConfig getSignatureConfig() {
        return signature.getSignatureConfig();
    }

    /**
     * Get full config details
     *
     * @return fullConfig
     */
    @GetMapping("/fullconfig")
    public SignatureConfig getFullSignatureConfig() {
        return signatureFull.getSignatureConfig();
    }

    /**
     * This endpoint uses `example-config.json`.
     * Generate signature headers and add it as headers to response.
     */
    @PostMapping("/sign-request")
    public ResponseEntity signRequest(
        HttpServletRequest request, HttpServletResponse response) {

        HttpServletResponse signatureObjectResponse = null;
        try {
            signatureObjectResponse = signature
                .getSignedRequest(request, response);
        } catch (SignatureException e) {
            e.printStackTrace();
            return ResponseEntity.badRequest()
                .body("Failure in generating Signature");
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return ResponseEntity.badRequest()
                .body("Failure in processing Signature Config");
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.badRequest()
                .body("Failure in processing Request Body");
        }
        return ResponseEntity.ok().build();
    }

    /**
     * This endpoint uses `example-config-full.json`.
     * Generate signature headers and return it as response.
     */
    @PostMapping("/sign")
    public ResponseEntity signRequest(HttpServletRequest request) {
        String response = "";
        try {
            String body = IOUtils.toString(request.getReader());
            String contentDigest = signatureFull
                .generateDigestHeader(body);
            String xEbaySignatureKey = signatureFull
                .generateSignatureKey();
            Map<String, String> headers = new HashMap<>();
            if(StringUtils.isNotBlank(contentDigest)){
                headers.put("content-digest", contentDigest);
            }
            headers.put("x-ebay-signature-key", xEbaySignatureKey);
            String signatureStr =  signatureFull
                .getSignature(headers);
            String signatureInput =  signatureFull
                .generateSignatureInput(headers.get("content-digest"));
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode sign = mapper.createObjectNode();
            if(StringUtils.isNotBlank(contentDigest)){
                sign.put(Constants.CONTENT_DIGEST_PARAM, contentDigest);
            }
            sign.put(Constants.X_EBAY_SIGNATURE_PARAM, xEbaySignatureKey);
            sign.put(Constants.SIGNATURE_INPUT_PARAM, signatureInput);
            sign.put(Constants.SIGNATURE_PARAM, signatureStr);

            response = mapper.writerWithDefaultPrettyPrinter()
                .writeValueAsString(sign);
        } catch (SignatureException | JsonProcessingException se) {
            return ResponseEntity.badRequest()
                .body("Failure in generating Signature");
        } catch (IOException e) {
            return ResponseEntity.badRequest()
                .body("Failure in reading the body");
        }
        return ResponseEntity.ok(response);
    }

    /**
     * This endpoint uses `example-config-full.json`.
     * Validate signature headers in the request
     */
    @PostMapping("/validate-request")
    public ResponseEntity validateRequest(
        HttpServletRequest request, @RequestHeader
        Map<String, String> headers) {

        boolean isSuccess = false;
        try {
            String body = IOUtils.toString(request.getReader());
            isSuccess = signatureFull.validateSignature(body, headers);
            if (isSuccess) {
                return ResponseEntity.accepted().build();
            } else {
                return ResponseEntity.badRequest().body("Invalid Signature");
            }
        } catch (SignatureException e) {
            e.printStackTrace();
            return ResponseEntity.badRequest()
                .body("Failure in validating Signature");
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.badRequest()
                .body("Failure in reading request body");
        }
    }

    /**
     * This endpoint uses `example-config-full.json`.
     * Validate signature headers in the request using individual methods
     */
    @PostMapping("/validate")
    public ResponseEntity validate(HttpServletRequest request,
        @RequestHeader
            Map<String, String> headers) {
        String body = null;
        try {
            body = IOUtils.toString(request.getReader());
        } catch (IOException e) {
            return ResponseEntity.badRequest()
                .body("Failure in reading request body");
        }
        boolean isContentDigestValid = signatureFull
            .validateDigestHeader(body, headers);
        boolean isSignaturHeaderValid = signatureFull.validateSignatureHeader(body, headers);
        if (isContentDigestValid && isSignaturHeaderValid) {
            return ResponseEntity.accepted().build();
        } else {
            return ResponseEntity.badRequest()
                .body("Invalid Content Digest or Signature header");
        }
    }

    /**
     * Load both config file values
     * `example-config-full.json` as signatureFull
     * `example-config.json` as signature
     */
    @PostConstruct
    public void loadConfig() {
        String fullConfigPath = "./example-config-full.json";
        String configPath = "./example-config.json";
        try {
            signatureFull = new Signature(fullConfigPath);
            signature = new Signature(configPath);
        } catch (SignatureConfigException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to read/load configs");
        }
    }
}
