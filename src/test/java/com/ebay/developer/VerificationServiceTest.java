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
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class VerificationServiceTest {
    VerificationService verificationService;
    SignatureConfig signatureConfig;

    @Before
    public void setUp() throws Exception {
        verificationService = new VerificationService();
        signatureConfig = loadSignatureConfig("./src/test/java/com/ebay/developer/example-config-full.json");
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
    public void verifyDigestHeader_valid() {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("content-digest",
                "sha-256=:R5Y7wFpTlnya0Tlfejy6BoU8XpHQv3VZyt/IQyVr+J4=:");
            verificationService
                .verifyDigestHeader("{\"hello\": \"world1\"}", headers);
            Assert.assertTrue(true);
        } catch (SignatureException e) {
            Assert.fail("Should not throw exception");
        }
    }

    @Test
    public void verifyDigestHeader_invalidDigest() {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("content-digest",
                "sha-256=:R5Y7wFpTlnya0Tlfejy6BoU8XpHQv3VZyt/IQyVr+J4=:");
            verificationService.verifyDigestHeader("", headers);
            Assert.fail("Should exception");
        } catch (SignatureException e) {
            Assert.assertNotNull(e);
            Assert.assertEquals(
                "Content-Digest value is invalid. Expected body digest is: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
                e.getCause().getMessage());
        }
    }

    @Test
    public void verifyDigestHeader_invalidCipherAlgo() {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("content-digest",
                "sha256=:R5Y7wFpTlnya0Tlfejy6BoU8XpHQv3VZyt/IQyVr+J4=:");
            verificationService.verifyDigestHeader("", headers);
            Assert.fail("Should exception");
        } catch (SignatureException e) {
            Assert.assertNotNull(e);
            Assert.assertEquals("Invalid cipher sha256",
                e.getCause().getMessage());
        }
    }

    @Test
    public void verifyDigestHeader_incorrectContentDigest() {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("content-digest","sha-256=:R5Y7wFpTlnya0Tlfejy6BoU8XpHQv3VZyt/IQyVr+J4=:");
            verificationService.verifyDigestHeader("", headers);
            Assert.fail("Should throw exception");
        } catch (SignatureException e) {
            Assert.assertNotNull(e);
            Assert.assertTrue(e.getCause().getMessage().startsWith("Content-Digest value is invalid. Expected body digest is:"));
        }
    }

    @Test
    public void verifyDigestHeader_emptyBody() {
        try {
            verificationService.verifyDigestHeader("", new HashMap<>());
            Assert.assertTrue(true);
        } catch (SignatureException e) {
            Assert.fail("Should not throw exception");
        }
    }

    @Test
    public void verifyDigestHeader_invalidContentPattern() {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("content-digest",
                ":R5Y7wFpTlnya0Tlfejy6BoU8XpHQv3VZyt/IQyVr+J4=:");
            verificationService.verifyDigestHeader("", headers);
            Assert.fail("Should exception");
        } catch (SignatureException e) {
            Assert.assertNotNull(e);
            Assert.assertEquals("Content-digest header invalid",
                e.getCause().getMessage());
        }
    }

    @Test
    public void verifySignature_valid() {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("signature-input",
                "sig1=(\"content-digest\" \"x-ebay-signature-key\" \"@method\" \"@path\" \"@authority\");created=1658440308");
            headers.put("content-digest",
                "sha-256=:R5Y7wFpTlnya0Tlfejy6BoU8XpHQv3VZyt/IQyVr+J4=:");
            headers.put("signature",
                "sig1=:kng+eN2o1Odm/8xZbEHW5s/0ZxpAlbH+oHnhyQilz9adHZCvFgxzabtib4t5TVFcq2qIIX6cYaV0ia3M/L3kBg==:");
            headers.put("x-ebay-signature-key",
                "eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoiWXIwT1hJNEhERENTWTlVMG1wNTNGdyIsImFsZyI6IkEyNTZHQ01LVyIsIml2IjoiSDlpNkI3Z1lGNEZ6UE9TQyJ9.Kwy5uL3t8pOyDoYCVGtNvizmsvP38jsvXeG3lDyKQeI.1x9D8RxO0by-C5Gp.kC4Y9LfnsYCJ0LBELSoeyBX3x4uQm0pHDxXMyetUha_dZFX5bCLZFuPpofaz4w1T4Sbwzk7aveqhchyGohUoGGgBvOKcMucVxUvglAxb9zTxtgRz43P9vwn-ha62pdp2-BnuH7Xz5V8lgi9gFw11fzbfe6vt7JW8eNlNguaJJgBvkRbz5mJjIrQezgke49am4a-bhOqbxTOvLEPRG6GdLxzVYiE.1IHkTyRcvrHlA0xBMSSYlg");
            PublicKey publicKey = verificationService
                .verifyJWT(headers, signatureConfig);
            String base = verificationService
                .calculateBase("{\"hello\": \"world1\"}", headers, signatureConfig);
            verificationService.verifySignature(publicKey, base, headers);
            Assert.assertTrue(true);
        } catch (SignatureException e) {
            Assert.fail("Should not throw exception");
        }
    }

    @Test
    public void verifySignature_invalidSignature() {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("x-ebay-signature-key",
                "eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoickVxTEpLS1pILUVoRlJjeWE2R0tCdyIsImFsZyI6IkEyNTZHQ01LVyIsIml2IjoiajJIaHRVaUl0ZVowODR1USJ9.D1JLtTpu2X5dqrR3DW5hJAP9XfkhenFBp6_fscnaqGg.MUJSNoNUCpWcq6tk.Pe-8rpk3kv1iE2fWF0hNNWf4FX-Zc7IkD7Uh6Nd0xuoRNDFJy7UUH_ZcdJ1ydlcTxveUU1ekOheEZvm_TPT0N5DFgol7xwEEiUp_Ms2QMeDenIfxJogsgde27ynMDfecEfHrjkVsn3YrUx6SI3b7G-l9c88eZvvd4Q0sJN1jBwrHd-hfjiURBhzIdHe-LAiQ7Qi_oDqXrOg05MD-44VRdYOCjw.5oSc9iXPo7ni1e72dO58uQ");
            headers.put("signature",
                "sig1=:uAPeaUEqWvTB8MUqzAqVJjeRMzNaMlBMDyBpVifh0kdG/t52NVp3hZF+mdZnUPI/y8oW67QAVVhaYkaXoeuBDA==:");
            PublicKey publicKey = verificationService
                .verifyJWT(headers, signatureConfig);
            verificationService
                .verifySignature(publicKey, "{\"hello\": \"world1\"}", headers);
            Assert.fail("Should exception");
        } catch (SignatureException e) {
            Assert.assertNotNull(e);
            Assert.assertEquals("Signature invalid", e.getMessage());
        }
    }

    @Test
    public void verifySignature_invalidBase64() {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("signature",
                "sig1=:tCSTMUe6YVBNco3Y7UZxyyJ5Z7HUwv5sv5avYo0dVu6hqu1wG01JUOkK//14PWwwb5y1wf6RAM28ICZVCECA==:");
            verificationService.verifySignature(null, "", headers);
            Assert.fail("Should exception");
        } catch (SignatureException e) {
            Assert.assertNotNull(e);
        }
    }

    @Test
    public void verifySignature_missingSignature() {
        try {
            verificationService.verifySignature(null, "", new HashMap<>());
            Assert.fail("Should exception");
        } catch (SignatureException e) {
            Assert.assertNotNull(e);
            Assert.assertEquals("Signature header missing", e.getMessage());
        }
    }

    @Test
    public void verifySignature_invalidContentPattern() {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("signature",
                ":tCSTMUeOL6YVBNco3Y7UZxyyJ5Z7HUwv5sv5avYo0dVu6hqu1wG01JUOkK//14PWwwb5y1wf6RAM28ICZVCECA==:");
            verificationService.verifySignature(null, "", headers);
            Assert.fail("Should exception");
        } catch (SignatureException e) {
            Assert.assertNotNull(e);
            Assert.assertEquals("Signature header invalid", e.getMessage());
        }
    }

    @Test
    public void verifyJWT_valid() {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("signature-input",
                "sig1=(\"content-digest\" \"x-ebay-signature-key\" \"@method\" \"@path\" \"@authority\");created=1658440308");
            headers.put("content-digest",
                "sha-256=:R5Y7wFpTlnya0Tlfejy6BoU8XpHQv3VZyt/IQyVr+J4=:");
            headers.put("signature",
                "sig1=:tCSTMUeOL6YVBNco3Y7UZxyyJ5Z7HUwv5sv5avYo0dVu6hqu1wG01JUOkK//14PWwwb5y1wf6RAM28ICZVCECA==:");
            headers.put("x-ebay-signature-key",
                "eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoickVxTEpLS1pILUVoRlJjeWE2R0tCdyIsImFsZyI6IkEyNTZHQ01LVyIsIml2IjoiajJIaHRVaUl0ZVowODR1USJ9.D1JLtTpu2X5dqrR3DW5hJAP9XfkhenFBp6_fscnaqGg.MUJSNoNUCpWcq6tk.Pe-8rpk3kv1iE2fWF0hNNWf4FX-Zc7IkD7Uh6Nd0xuoRNDFJy7UUH_ZcdJ1ydlcTxveUU1ekOheEZvm_TPT0N5DFgol7xwEEiUp_Ms2QMeDenIfxJogsgde27ynMDfecEfHrjkVsn3YrUx6SI3b7G-l9c88eZvvd4Q0sJN1jBwrHd-hfjiURBhzIdHe-LAiQ7Qi_oDqXrOg05MD-44VRdYOCjw.5oSc9iXPo7ni1e72dO58uQ");
            PublicKey publicKey = verificationService
                .verifyJWT(headers, signatureConfig);
            Assert.assertNotNull(publicKey);
        } catch (SignatureException e) {
            Assert.fail("Should not throw exception");
        }
    }

    @Test
    public void verifyJWT_invalid() {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("signature-input",
                "sig1=(\"content-digest\" \"x-ebay-signature-key\" \"@method\" \"@path\" \"@authority\");created=1658440308");
            headers.put("content-digest",
                "sha-256=:R5Y7wFpTlnya0Tlfejy6BoU8XpHQv3VZyt/IQyVr+J4=:");
            headers.put("signature",
                "sig1=:tCSTMUeOL6YVBNco3Y7UZxyyJ5Z7HUwv5sv5avYo0dVu6hqu1wG01JUOkK//14PWwwb5y1wf6RAM28ICZVCECA==:");
            PublicKey publicKey = verificationService
                .verifyJWT(headers, signatureConfig);
            Assert.fail("Should throw exception");
        } catch (SignatureException e) {
            Assert.assertNotNull(e);
            Assert.assertEquals("x-ebay-signature-key header missing",
                e.getMessage());
        }
    }

    @Test
    public void calculateBase_valid() {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("signature-input",
                "sig1=(\"content-digest\" \"x-ebay-signature-key\" \"@method\" \"@path\" \"@authority\");created=1658440308");
            headers.put("content-digest",
                "sha-256=:R5Y7wFpTlnya0Tlfejy6BoU8XpHQv3VZyt/IQyVr+J4=:");
            headers.put("signature",
                "sig1=:tCSTMUeOL6YVBNco3Y7UZxyyJ5Z7HUwv5sv5avYo0dVu6hqu1wG01JUOkK//14PWwwb5y1wf6RAM28ICZVCECA==:");
            headers.put("x-ebay-signature-key",
                "eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoickVxTEpLS1pILUVoRlJjeWE2R0tCdyIsImFsZyI6IkEyNTZHQ01LVyIsIml2IjoiajJIaHRVaUl0ZVowODR1USJ9.D1JLtTpu2X5dqrR3DW5hJAP9XfkhenFBp6_fscnaqGg.MUJSNoNUCpWcq6tk.Pe-8rpk3kv1iE2fWF0hNNWf4FX-Zc7IkD7Uh6Nd0xuoRNDFJy7UUH_ZcdJ1ydlcTxveUU1ekOheEZvm_TPT0N5DFgol7xwEEiUp_Ms2QMeDenIfxJogsgde27ynMDfecEfHrjkVsn3YrUx6SI3b7G-l9c88eZvvd4Q0sJN1jBwrHd-hfjiURBhzIdHe-LAiQ7Qi_oDqXrOg05MD-44VRdYOCjw.5oSc9iXPo7ni1e72dO58uQ");
            String base = verificationService
                .calculateBase("{\"hello\": \"world1\"}",headers, signatureConfig);
            Assert.assertEquals(
                "\"content-digest\": sha-256=:R5Y7wFpTlnya0Tlfejy6BoU8XpHQv3VZyt/IQyVr+J4=:\n"
                    + "\"x-ebay-signature-key\": eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoickVxTEpLS1pILUVoRlJjeWE2R0tCdyIsImFsZyI6IkEyNTZHQ01LVyIsIml2IjoiajJIaHRVaUl0ZVowODR1USJ9.D1JLtTpu2X5dqrR3DW5hJAP9XfkhenFBp6_fscnaqGg.MUJSNoNUCpWcq6tk.Pe-8rpk3kv1iE2fWF0hNNWf4FX-Zc7IkD7Uh6Nd0xuoRNDFJy7UUH_ZcdJ1ydlcTxveUU1ekOheEZvm_TPT0N5DFgol7xwEEiUp_Ms2QMeDenIfxJogsgde27ynMDfecEfHrjkVsn3YrUx6SI3b7G-l9c88eZvvd4Q0sJN1jBwrHd-hfjiURBhzIdHe-LAiQ7Qi_oDqXrOg05MD-44VRdYOCjw.5oSc9iXPo7ni1e72dO58uQ\n"
                    + "\"@method\": POST\n" + "\"@path\": /test\n"
                    + "\"@authority\": localhost:8080\n"
                    + "\"@signature-params\": (\"content-digest\" \"x-ebay-signature-key\" \"@method\" \"@path\" \"@authority\");created=1658440308",
                base);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void calculateBase_invalid() {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("content-digest",
                "sha-256=:R5Y7wFpTlnya0Tlfejy6BoU8XpHQv3VZyt/IQyVr+J4=:");
            headers.put("signature",
                "sig1=:tCSTMUeOL6YVBNco3Y7UZxyyJ5Z7HUwv5sv5avYo0dVu6hqu1wG01JUOkK//14PWwwb5y1wf6RAM28ICZVCECA==:");
            headers.put("x-ebay-signature-key",
                "eyJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoickVxTEpLS1pILUVoRlJjeWE2R0tCdyIsImFsZyI6IkEyNTZHQ01LVyIsIml2IjoiajJIaHRVaUl0ZVowODR1USJ9.D1JLtTpu2X5dqrR3DW5hJAP9XfkhenFBp6_fscnaqGg.MUJSNoNUCpWcq6tk.Pe-8rpk3kv1iE2fWF0hNNWf4FX-Zc7IkD7Uh6Nd0xuoRNDFJy7UUH_ZcdJ1ydlcTxveUU1ekOheEZvm_TPT0N5DFgol7xwEEiUp_Ms2QMeDenIfxJogsgde27ynMDfecEfHrjkVsn3YrUx6SI3b7G-l9c88eZvvd4Q0sJN1jBwrHd-hfjiURBhzIdHe-LAiQ7Qi_oDqXrOg05MD-44VRdYOCjw.5oSc9iXPo7ni1e72dO58uQ");
            String base = verificationService
                .calculateBase("{\"hello\": \"world1\"}", headers, signatureConfig);
            Assert.fail("Should throw exception");
        } catch (SignatureException e) {
            Assert.assertNotNull(e);
            Assert.assertEquals("Signature-Input header missing",
                e.getCause().getMessage());
        }
    }
}
