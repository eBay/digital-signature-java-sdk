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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class SignatureServiceTest {
    SignatureService signatureService;
    SignatureConfig signatureConfigFull;
    SignatureConfig signatureConfig;

    @Before
    public void setUp() throws Exception {
        signatureService = new SignatureService();
        signatureConfigFull = loadSignatureConfig("./src/test/java/com/ebay/developer/example-config-full.json");
        signatureConfig = loadSignatureConfig("./src/test/java/com/ebay/developer/example-config.json");
    }

    private SignatureConfig loadSignatureConfig(String configPath)
        throws SignatureConfigException {
        SignatureConfig signatureConfig = null;
        ObjectMapper mapper = new ObjectMapper();

        // convert JSON file to map
        try {
            signatureConfig = mapper.readValue(Paths.get(configPath).toFile(),
                SignatureConfig.class);
        } catch (IOException e) {
            e.printStackTrace();
            throw new SignatureConfigException("Failed to load config file");
        }

        if (signatureConfig == null) {
            throw new SignatureConfigException("Failed to map config fields");
        }

        return signatureConfig;
    }

    @Test
    public void generateContentDigest_valid() {
        try {
            String contentDigest = signatureService
                .generateContentDigest("{\"hello\": \"world1\"}",
                    signatureConfig);
            Assert.assertEquals(
                "sha-256=:R5Y7wFpTlnya0Tlfejy6BoU8XpHQv3VZyt/IQyVr+J4=:",
                contentDigest);
        } catch (SignatureException e) {
            Assert.fail("Should not throw exception");
        }
    }

    @Test
    public void generateContentDigest_EmptyBodyValid() {
        try {
            String contentDigest = signatureService
                .generateContentDigest("",
                    signatureConfig);
            Assert.assertNull(contentDigest);
        } catch (SignatureException e) {
            Assert.fail("Should not throw exception");
        }
    }

    @Test
    public void generateSignatureKeyHeader_valid() {
        try {
            String signatureKeyHeader = signatureService
                .generateSignatureKeyHeader(signatureConfig);
            Assert.assertEquals(
                "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIiwiaXYiOiIzaE4yVElWOGNpcnFlbkFFIiwidGFnIjoiRU5pNnh3VTRpQlNFdFlKSWxXLTFzZyJ9.iCr0uh3U5-9HhbN9ieeOY8aMbTEemQw8-LWkaWNZ0KM.8VD3RAlDFrroF_vz.CPLqXgKdWIUZflkqFx00odfHbkR48AwvVvk5s8aZPYp1cKlWS2fstfhFgQDKHgvZN3onc5Bn4hbk_frexCUrLcOxOd8ga2zU_3PB1VWLV_CHizoqwLkMzdDkymzSGKKGt3kCFknfqbQkQFjY0iUc.RomdXeeOtVhzb9gUMlWnsg",
                signatureKeyHeader);
        } catch (SignatureException e) {
            Assert.fail("Should not throw exception");
        }
    }

    @Test
    public void getSignatureInput_valid() {
        String signatureInput = signatureService
            .getSignatureInput("xyz", signatureConfig.getSignatureParams());
        Assert.assertNotNull(signatureInput);
        Assert.assertTrue(signatureInput.startsWith(
            "(\"content-digest\" \"x-ebay-signature-key\" \"@method\" \"@path\" \"@authority\");created="));
    }

    @Test
    public void getSignatureInput_MissingContentDigest() {
        String signatureInput = signatureService
            .getSignatureInput(null, signatureConfig.getSignatureParams());
        Assert.assertNotNull(signatureInput);
        Assert.assertTrue(signatureInput.startsWith(
            "(\"x-ebay-signature-key\" \"@method\" \"@path\" \"@authority\");created="));
    }

    @Test
    public void getSignature_valid() {
        Map<String, String> headers = new HashMap<>();
        headers.put("signature-input",
            "sig1=(\"content-digest\" \"x-ebay-signature-key\" \"@method\" \"@path\" \"@authority\");created=1658440308");
        headers.put("content-digest",
            "sha-256=:R5Y7wFpTlnya0Tlfejy6BoU8XpHQv3VZyt/IQyVr+J4=:");
        headers.put("signature",
            "sig1=:kng+eN2o1Odm/8xZbEHW5s/0ZxpAlbH+oHnhyQilz9adHZCvFgxzabtib4t5TVFcq2qIIX6cYaV0ia3M/L3kBg==:");
        headers.put("x-ebay-signature-key",
            "eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoiWXIwT1hJNEhERENTWTlVMG1wNTNGdyIsImFsZyI6IkEyNTZHQ01LVyIsIml2IjoiSDlpNkI3Z1lGNEZ6UE9TQyJ9.Kwy5uL3t8pOyDoYCVGtNvizmsvP38jsvXeG3lDyKQeI.1x9D8RxO0by-C5Gp.kC4Y9LfnsYCJ0LBELSoeyBX3x4uQm0pHDxXMyetUha_dZFX5bCLZFuPpofaz4w1T4Sbwzk7aveqhchyGohUoGGgBvOKcMucVxUvglAxb9zTxtgRz43P9vwn-ha62pdp2-BnuH7Xz5V8lgi9gFw11fzbfe6vt7JW8eNlNguaJJgBvkRbz5mJjIrQezgke49am4a-bhOqbxTOvLEPRG6GdLxzVYiE.1IHkTyRcvrHlA0xBMSSYlg");

        try {
            String signature = signatureService
                .getSignature(headers, signatureConfigFull);
            Assert.assertNotNull(signature);
            Assert.assertTrue(signature.startsWith("sig1=:"));
            Assert.assertTrue(signature.endsWith("==:"));
        } catch (SignatureException e) {
            Assert.fail("Should not throw exception");
        }
    }

    @Test
    public void calculateBase_valid() {
        Map<String, String> headers = new HashMap<>();
        headers.put("signature-input",
            "sig1=(\"content-digest\" \"x-ebay-signature-key\" \"@method\" \"@path\" \"@authority\");created=1658440308");
        headers.put("content-digest",
            "sha-256=:R5Y7wFpTlnya0Tlfejy6BoU8XpHQv3VZyt/IQyVr+J4=:");
        headers.put("signature",
            "sig1=:kng+eN2o1Odm/8xZbEHW5s/0ZxpAlbH+oHnhyQilz9adHZCvFgxzabtib4t5TVFcq2qIIX6cYaV0ia3M/L3kBg==:");
        headers.put("x-ebay-signature-key",
            "eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoiWXIwT1hJNEhERENTWTlVMG1wNTNGdyIsImFsZyI6IkEyNTZHQ01LVyIsIml2IjoiSDlpNkI3Z1lGNEZ6UE9TQyJ9.Kwy5uL3t8pOyDoYCVGtNvizmsvP38jsvXeG3lDyKQeI.1x9D8RxO0by-C5Gp.kC4Y9LfnsYCJ0LBELSoeyBX3x4uQm0pHDxXMyetUha_dZFX5bCLZFuPpofaz4w1T4Sbwzk7aveqhchyGohUoGGgBvOKcMucVxUvglAxb9zTxtgRz43P9vwn-ha62pdp2-BnuH7Xz5V8lgi9gFw11fzbfe6vt7JW8eNlNguaJJgBvkRbz5mJjIrQezgke49am4a-bhOqbxTOvLEPRG6GdLxzVYiE.1IHkTyRcvrHlA0xBMSSYlg");

        try {
            String base = signatureService
                .calculateBase(headers, signatureConfig);
            Assert.assertTrue(base.contains(
                "sha-256=:R5Y7wFpTlnya0Tlfejy6BoU8XpHQv3VZyt/IQyVr+J4=:"));
            Assert.assertTrue(base.contains(
                "(\"content-digest\" \"x-ebay-signature-key\" \"@method\" \"@path\" \"@authority\")"));
            Assert.assertTrue(
                base.contains("/sell/fulfillment/v1/order/1234/issue_refund"));
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }
}
