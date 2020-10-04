package com.trilead.ssh2.signature;

import com.trilead.ssh2.crypto.PEMDecoder;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.KeyPairGenerator;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author Michael Clarke
 */
public class DSAKeyAlgorithmTest {

    @Test
    public void testEncodeDecodePublicKey() throws GeneralSecurityException, IOException {
        DSAKeyAlgorithm testCase = new DSAKeyAlgorithm();
        KeyPairGenerator factory = KeyPairGenerator.getInstance("DSA");
        factory.initialize(1024);
        DSAPublicKey publicKey = (DSAPublicKey) factory.generateKeyPair().getPublic();
        byte[] encoded = testCase.encodePublicKey(publicKey);
        DSAPublicKey decoded = testCase.decodePublicKey(encoded);
        assertEquals(publicKey, decoded);
    }

    @Test
    public void testEncodeDecodeSignature() throws GeneralSecurityException, IOException {
        DSAKeyAlgorithm testCase = new DSAKeyAlgorithm();
        KeyPairGenerator factory = KeyPairGenerator.getInstance("DSA");
        factory.initialize(1024);
        DSAPrivateKey privateKey = (DSAPrivateKey) factory.generateKeyPair().getPrivate();
        byte[] signature = testCase.generateSignature("Sign Me".getBytes(StandardCharsets.UTF_8), privateKey, new SecureRandom());
        byte[] encoded = testCase.encodeSignature(signature);
        byte[] decoded = testCase.decodeSignature(encoded);
        assertArrayEquals(signature, decoded);
    }

    @Test
    public void testSignAndVerify() throws GeneralSecurityException, IOException {
        DSAKeyAlgorithm testCase = new DSAKeyAlgorithm();
        byte[] message = "Signature Test".getBytes(StandardCharsets.UTF_8);
        KeyPairGenerator factory = KeyPairGenerator.getInstance("DSA");
        factory.initialize(1024);
        KeyPair keyPair = factory.generateKeyPair();
        DSAPrivateKey privateKey = (DSAPrivateKey) keyPair.getPrivate();
        DSAPublicKey publicKey = (DSAPublicKey) keyPair.getPublic();
        byte[] signature = testCase.generateSignature(message, privateKey, new SecureRandom());
        assertTrue(testCase.verifySignature(message, signature, publicKey));
    }


    @Test
    public void testSignAndVerifyFailure() throws GeneralSecurityException, IOException {
        DSAKeyAlgorithm testCase = new DSAKeyAlgorithm();
        byte[] message = "Signature Test 2".getBytes(StandardCharsets.UTF_8);
        KeyPairGenerator factory = KeyPairGenerator.getInstance("DSA");
        factory.initialize(1024);
        KeyPair keyPair = factory.generateKeyPair();
        DSAPrivateKey privateKey = (DSAPrivateKey) keyPair.getPrivate();
        DSAPublicKey publicKey = (DSAPublicKey) keyPair.getPublic();
        byte[] signature = testCase.generateSignature("Other Message".getBytes(StandardCharsets.UTF_8), privateKey, new SecureRandom());
        assertFalse(testCase.verifySignature(message, signature, publicKey));
    }


    @Test
    public void testParsePrivateKey() throws IOException {
        KeyPair oldFormat = PEMDecoder.decodeKeyPair(IOUtils.toCharArray(getClass().getResourceAsStream("dsa-testkey-unprotected.txt")), null);
        KeyPair newFormat = PEMDecoder.decodeKeyPair(IOUtils.toCharArray(getClass().getResourceAsStream("dsa-testkey-unprotected-newformat.txt")), null);
        assertEquals(oldFormat.getPublic(), newFormat.getPublic());
        assertEquals(oldFormat.getPrivate(), newFormat.getPrivate());
    }
}
