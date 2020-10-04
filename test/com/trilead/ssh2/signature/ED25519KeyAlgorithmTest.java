package com.trilead.ssh2.signature;

import com.trilead.ssh2.crypto.PEMDecoder;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author Michael Clarke
 */
public class ED25519KeyAlgorithmTest {

    @Test
    public void testEncodeDecodePublicKey() throws GeneralSecurityException, IOException {
        ED25519KeyAlgorithm testCase = new ED25519KeyAlgorithm();
        KeyPairGenerator factory = KeyPairGenerator.getInstance("EdDSA", new EdDSASecurityProvider());
        EdDSAPublicKey publicKey = (EdDSAPublicKey) factory.generateKeyPair().getPublic();
        byte[] encoded = testCase.encodePublicKey(publicKey);
        EdDSAPublicKey decoded = testCase.decodePublicKey(encoded);
        assertEquals(publicKey, decoded);
    }

    @Test
    public void testEncodeDecodeSignature() throws GeneralSecurityException, IOException {
        ED25519KeyAlgorithm testCase = new ED25519KeyAlgorithm();
        KeyPairGenerator factory = KeyPairGenerator.getInstance("EdDSA", new EdDSASecurityProvider());
        EdDSAPrivateKey privateKey = (EdDSAPrivateKey) factory.generateKeyPair().getPrivate();
        byte[] signature = testCase.generateSignature("Sign Me".getBytes(StandardCharsets.UTF_8), privateKey, new SecureRandom());
        byte[] encoded = testCase.encodeSignature(signature);
        byte[] decoded = testCase.decodeSignature(encoded);
        assertArrayEquals(signature, decoded);
    }

    @Test
    public void testSignAndVerify() throws GeneralSecurityException, IOException {
        ED25519KeyAlgorithm testCase = new ED25519KeyAlgorithm();
        byte[] message = "Signature Test".getBytes(StandardCharsets.UTF_8);
        KeyPairGenerator factory = KeyPairGenerator.getInstance("EdDSA", new EdDSASecurityProvider());
        KeyPair keyPair = factory.generateKeyPair();
        EdDSAPrivateKey privateKey = (EdDSAPrivateKey) keyPair.getPrivate();
        EdDSAPublicKey publicKey = (EdDSAPublicKey) keyPair.getPublic();
        byte[] signature = testCase.generateSignature(message, privateKey, new SecureRandom());
        assertTrue(testCase.verifySignature(message, signature, publicKey));
    }


    @Test
    public void testSignAndVerifyFailure() throws GeneralSecurityException, IOException {
        ED25519KeyAlgorithm testCase = new ED25519KeyAlgorithm();
        byte[] message = "Signature Test 2".getBytes(StandardCharsets.UTF_8);
        KeyPairGenerator factory = KeyPairGenerator.getInstance("EdDSA", new EdDSASecurityProvider());
        KeyPair keyPair = factory.generateKeyPair();
        EdDSAPrivateKey privateKey = (EdDSAPrivateKey) keyPair.getPrivate();
        EdDSAPublicKey publicKey = (EdDSAPublicKey) keyPair.getPublic();
        byte[] signature = testCase.generateSignature("Other Message".getBytes(StandardCharsets.UTF_8), privateKey, new SecureRandom());
        assertFalse(testCase.verifySignature(message, signature, publicKey));
    }


    @Test
    public void testParsePrivateKey() throws IOException {
        KeyPair expected = PEMDecoder.decodeKeyPair(IOUtils.toCharArray(getClass().getResourceAsStream("ed25519-testkey-unprotected.txt")), null);
        KeyPair actual = PEMDecoder.decodeKeyPair(IOUtils.toCharArray(getClass().getResourceAsStream("ed25519-testkey-protected.txt")), "password");
        KeyPair actualCtr = PEMDecoder.decodeKeyPair(IOUtils.toCharArray(getClass().getResourceAsStream("ed25519-testkey-protected-ctr.txt")), "password");

        assertEquals(expected.getPrivate(), actual.getPrivate());
        assertEquals(expected.getPublic(), actual.getPublic());

        assertEquals(expected.getPrivate(), actualCtr.getPrivate());
        assertEquals(expected.getPublic(), actualCtr.getPublic());
    }
}
