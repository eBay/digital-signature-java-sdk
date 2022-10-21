package com.ebay.developer;

public class Constants {
    private Constants() {
    }

    public static final String CONTENT_DIGEST_HEADER = "Content-Digest";
    public static final String X_EBAY_SIGNATURE_HEADER = "x-ebay-signature-key";
    public static final String SIGNATURE_HEADER = "Signature";
    public static final String SIGNATURE_INPUT_HEADER = "Signature-Input";

    public static final String SIGNATURE_INPUT_PREFIX = "sig1=";
    public static final String SIGNATURE_PREFIX = "sig1=:";
    public static final String CONTENT_DIGEST = "content-digest";


    public static final String CONTENT_DIGEST_PARAM = "contentDigest";
    public static final String X_EBAY_SIGNATURE_PARAM = "signatureKeyHeader";
    public static final String SIGNATURE_PARAM = "Signature";
    public static final String SIGNATURE_INPUT_PARAM = "SignatureInput";

    public static final String ALGORITHM_RSA = "RSA";
    public static final String SHA256 = "sha-256";
    public static final String SHA512 = "sha-512";
}
