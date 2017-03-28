package com.trilead.ssh2.signature;

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
public class DSASHA1VerifyTest {

    @Test
    public void testEncodeDecodePublicKey() throws GeneralSecurityException, IOException {
        KeyPairGenerator factory = KeyPairGenerator.getInstance("DSA");
        DSAPublicKey publicKey = (DSAPublicKey) factory.generateKeyPair().getPublic();
        byte[] encoded = DSASHA1Verify.encodeSSHPublicKey(publicKey);
        DSAPublicKey decoded = DSASHA1Verify.decodeSSHPublicKey(encoded);
        assertEquals(publicKey, decoded);
    }

    @Test
    public void testEncodeDecodeSignature() throws GeneralSecurityException, IOException {
        KeyPairGenerator factory = KeyPairGenerator.getInstance("DSA");
        DSAPrivateKey privateKey = (DSAPrivateKey) factory.generateKeyPair().getPrivate();
        byte[] signature = DSASHA1Verify.generateSignature("Sign Me".getBytes(StandardCharsets.UTF_8), privateKey, new SecureRandom());
        byte[] encoded = DSASHA1Verify.encodeSSHSignature(signature);
        byte[] decoded = DSASHA1Verify.decodeSSHSignature(encoded);
        assertArrayEquals(signature, decoded);
    }

    @Test
    public void testSignAndVerify() throws GeneralSecurityException, IOException {
        byte[] message = "Signature Test".getBytes(StandardCharsets.UTF_8);
        KeyPairGenerator factory = KeyPairGenerator.getInstance("DSA");
        KeyPair keyPair = factory.generateKeyPair();
        DSAPrivateKey privateKey = (DSAPrivateKey) keyPair.getPrivate();
        DSAPublicKey publicKey = (DSAPublicKey) keyPair.getPublic();
        byte[] signature = DSASHA1Verify.generateSignature(message, privateKey, new SecureRandom());
        assertTrue(DSASHA1Verify.verifySignature(message, signature, publicKey));
    }


    @Test
    public void testSignAndVerifyFailure() throws GeneralSecurityException, IOException {
        byte[] message = "Signature Test 2".getBytes(StandardCharsets.UTF_8);
        KeyPairGenerator factory = KeyPairGenerator.getInstance("DSA");
        KeyPair keyPair = factory.generateKeyPair();
        DSAPrivateKey privateKey = (DSAPrivateKey) keyPair.getPrivate();
        DSAPublicKey publicKey = (DSAPublicKey) keyPair.getPublic();
        byte[] signature = DSASHA1Verify.generateSignature("Other Message".getBytes(StandardCharsets.UTF_8), privateKey, new SecureRandom());
        assertFalse(DSASHA1Verify.verifySignature(message, signature, publicKey));
    }
}
