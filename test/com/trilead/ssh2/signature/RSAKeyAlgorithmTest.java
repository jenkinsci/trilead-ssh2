package com.trilead.ssh2.signature;

import com.trilead.ssh2.crypto.PEMDecoder;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author Michael Clarke
 */
public class RSAKeyAlgorithmTest {

    @Test
    public void testEncodeDecodePublicKey() throws GeneralSecurityException, IOException {
        RSAKeyAlgorithm testCase = new RSAKeyAlgorithm();
        KeyPairGenerator factory = KeyPairGenerator.getInstance("RSA");
        RSAPublicKey publicKey = (RSAPublicKey) factory.generateKeyPair().getPublic();
        byte[] encoded = testCase.encodePublicKey(publicKey);
        RSAPublicKey decoded = testCase.decodePublicKey(encoded);
        assertEquals(publicKey, decoded);
    }

    @Test
    public void testEncodeDecodeSignature() throws GeneralSecurityException, IOException {
        RSAKeyAlgorithm testCase = new RSAKeyAlgorithm();
        KeyPairGenerator factory = KeyPairGenerator.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) factory.generateKeyPair().getPrivate();
        byte[] signature = testCase.generateSignature("Sign Me".getBytes(StandardCharsets.UTF_8), privateKey, new SecureRandom());
        byte[] encoded = testCase.encodeSignature(signature);
        byte[] decoded = testCase.decodeSignature(encoded);
        assertArrayEquals(signature, decoded);
    }

    @Test
    public void testSignAndVerify() throws GeneralSecurityException, IOException {
        RSAKeyAlgorithm testCase = new RSAKeyAlgorithm();
        byte[] message = "Signature Test".getBytes(StandardCharsets.UTF_8);
        KeyPairGenerator factory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = factory.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        byte[] signature = testCase.generateSignature(message, privateKey, new SecureRandom());
        assertTrue(testCase.verifySignature(message, signature, publicKey));
    }


    @Test
    public void testSignAndVerifyFailure() throws GeneralSecurityException, IOException {
        RSAKeyAlgorithm testCase = new RSAKeyAlgorithm();
        byte[] message = "Signature Test 2".getBytes(StandardCharsets.UTF_8);
        KeyPairGenerator factory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = factory.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        byte[] signature = testCase.generateSignature("Other Message".getBytes(StandardCharsets.UTF_8), privateKey, new SecureRandom());
        assertFalse(testCase.verifySignature(message, signature, publicKey));
    }

    @Test
    public void testParsePrivateKey() throws IOException {
        KeyPair expected = PEMDecoder.decodeKeyPair(IOUtils.toCharArray(getClass().getResourceAsStream("rsa-testkey-unprotected.txt")), null);
        KeyPair actual = PEMDecoder.decodeKeyPair(IOUtils.toCharArray(getClass().getResourceAsStream("rsa-testkey-unprotected-newformat.txt")), "password");

        assertEquals(expected.getPrivate(), actual.getPrivate());
        assertEquals(expected.getPublic(), actual.getPublic());
    }
}
