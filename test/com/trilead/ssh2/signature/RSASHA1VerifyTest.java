package com.trilead.ssh2.signature;

import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author Michael Clarke
 */
public class RSASHA1VerifyTest {

    @Test
    public void testEncodeDecodePublicKey() throws GeneralSecurityException, IOException {
        KeyPairGenerator factory = KeyPairGenerator.getInstance("RSA");
        RSAPublicKey publicKey = (RSAPublicKey) factory.generateKeyPair().getPublic();
        byte[] encoded = RSASHA1Verify.encodeSSHPublicKey(publicKey);
        RSAPublicKey decoded = RSASHA1Verify.decodeSSHPublicKey(encoded);
        assertEquals(publicKey, decoded);
    }

    @Test
    public void testEncodeDecodeSignature() throws GeneralSecurityException, IOException {
        KeyPairGenerator factory = KeyPairGenerator.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) factory.generateKeyPair().getPrivate();
        byte[] signature = RSASHA1Verify.generateSignature("Sign Me".getBytes(StandardCharsets.UTF_8), privateKey);
        byte[] encoded = RSASHA1Verify.encodeSSHSignature(signature);
        byte[] decoded = RSASHA1Verify.decodeSSHSignature(encoded);
        assertArrayEquals(signature, decoded);
    }

    @Test
    public void testSignAndVerify() throws GeneralSecurityException, IOException {
        byte[] message = "Signature Test".getBytes(StandardCharsets.UTF_8);
        KeyPairGenerator factory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = factory.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        byte[] signature = RSASHA1Verify.generateSignature(message, privateKey);
        assertTrue(RSASHA1Verify.verifySignature(message, signature, publicKey));
    }


    @Test
    public void testSignAndVerifyFailure() throws GeneralSecurityException, IOException {
        byte[] message = "Signature Test 2".getBytes(StandardCharsets.UTF_8);
        KeyPairGenerator factory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = factory.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        byte[] signature = RSASHA1Verify.generateSignature("Other Message".getBytes(StandardCharsets.UTF_8), privateKey);
        assertFalse(RSASHA1Verify.verifySignature(message, signature, publicKey));
    }
}
