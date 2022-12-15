package com.ebay.developer;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.Map;

import static com.ebay.developer.Constants.CONTENT_DIGEST_HEADER;
import static com.ebay.developer.Constants.SIGNATURE_INPUT_HEADER;
import static org.junit.Assert.*;

public class SignatureTest {

    private final VerificationService verificationService = new VerificationService();

    private SignatureConfig signatureConfigFull;

    @Before
    public void setUp() throws Exception {
        signatureConfigFull = loadSignatureConfig();
    }

    @Test
    public void test_SignatureMap_EmptyBody_WithValidation() throws SignatureException {
        final Signature classUnderTest = new Signature(signatureConfigFull);

        final Map<String, String> result = classUnderTest.getSignatureHeaderAsMap("");

        assertTrue(verificationService.verification("", result, signatureConfigFull));
    }

    @Test
    public void test_SignatureMap_WithBody_WithValidation() throws SignatureException {
        final Signature classUnderTest = new Signature(signatureConfigFull);

        final String body = "A body of the request.";
        final Map<String, String> result = classUnderTest.getSignatureHeaderAsMap(body);

        assertTrue(verificationService.verification(body, result, signatureConfigFull));
    }

    @Test
    public void test_SignatureMap_WithBody() throws SignatureException {
        final Signature classUnderTest = new Signature(signatureConfigFull);

        final String body = "A body of the request.";
        final Map<String, String> result = classUnderTest.getSignatureHeaderAsMap(body);

        assertEquals("sha-256=:rjyRGbB7QtUQsZAfGpJhgujLDMWVhaNmGgIBMRrM0q0=:", result.get(CONTENT_DIGEST_HEADER.toLowerCase()));
        assertEquals(
                "sig1=(\"content-digest\" \"x-ebay-signature-key\" \"@method\" \"@path\" \"@authority\");",
                result.get(SIGNATURE_INPUT_HEADER.toLowerCase()).split("created=")[0]
        );
    }

    @Test
    public void test_SignatureMap_EmptyBody() throws SignatureException {
        final Signature classUnderTest = new Signature(signatureConfigFull);

        final String body = "";
        final Map<String, String> result = classUnderTest.getSignatureHeaderAsMap(body);

        assertNull(result.get(CONTENT_DIGEST_HEADER.toLowerCase()));
        assertEquals(
                "sig1=(\"x-ebay-signature-key\" \"@method\" \"@path\" \"@authority\");",
                result.get(SIGNATURE_INPUT_HEADER.toLowerCase()).split("created=")[0]
        );
    }

    private SignatureConfig loadSignatureConfig() throws SignatureConfigException {
        SignatureConfig signatureConfig;
        ObjectMapper mapper = new ObjectMapper();

        // convert JSON file to map
        try {
            signatureConfig = mapper.readValue(Paths.get("./src/test/java/com/ebay/developer/example-config-full.json").toFile(), SignatureConfig.class);
        } catch (IOException e) {
            e.printStackTrace();
            throw new SignatureConfigException("Failed to load config file");
        }

        if (signatureConfig == null) {
            throw new SignatureConfigException("Failed to map config fields");
        }

        return signatureConfig;
    }
}
