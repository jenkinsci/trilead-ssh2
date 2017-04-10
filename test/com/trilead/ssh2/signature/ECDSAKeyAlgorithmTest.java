package com.trilead.ssh2.signature;

import com.trilead.ssh2.crypto.PEMDecoder;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author Michael Clarke
 */
@RunWith(Parameterized.class)
public class ECDSAKeyAlgorithmTest {

    private final ECDSAKeyAlgorithm testCase;
    
    public ECDSAKeyAlgorithmTest(ECDSAKeyAlgorithm testCase) {
        super();
        this.testCase = testCase;
    }
    
    @Parameterized.Parameters
    public static Collection<ECDSAKeyAlgorithm[]> getAlgorithms() {
        return Arrays.asList(new ECDSAKeyAlgorithm[]{new ECDSAKeyAlgorithm.ECDSASha2Nistp256()},
                new ECDSAKeyAlgorithm[]{new ECDSAKeyAlgorithm.ECDSASha2Nistp384()},
                new ECDSAKeyAlgorithm[]{new ECDSAKeyAlgorithm.ECDSASha2Nistp521()});
    }
    
    @Test
    public void testEncodeDecodePublicKey() throws GeneralSecurityException, IOException {
        KeyPairGenerator factory = KeyPairGenerator.getInstance("EC");
        factory.initialize(testCase.getEcParameterSpec().getCurve().getField().getFieldSize());
        ECPublicKey publicKey = (ECPublicKey) factory.generateKeyPair().getPublic();
        byte[] encoded = testCase.encodePublicKey(publicKey);
        ECPublicKey decoded = testCase.decodePublicKey(encoded);
        assertEquals(publicKey, decoded);
    }

    @Test
    public void testEncodeDecodeSignature() throws GeneralSecurityException, IOException {
        KeyPairGenerator factory = KeyPairGenerator.getInstance("EC");
        factory.initialize(testCase.getEcParameterSpec().getCurve().getField().getFieldSize());
        ECPrivateKey privateKey = (ECPrivateKey) factory.generateKeyPair().getPrivate();
        byte[] signature = testCase.generateSignature("Sign Me".getBytes(StandardCharsets.UTF_8), privateKey, new SecureRandom());
        byte[] encoded = testCase.encodeSignature(signature);
        byte[] decoded = testCase.decodeSignature(encoded);
        assertArrayEquals(signature, decoded);
    }

    @Test
    public void testSignAndVerify() throws GeneralSecurityException, IOException {
        byte[] message = "Signature Test".getBytes(StandardCharsets.UTF_8);
        KeyPairGenerator factory = KeyPairGenerator.getInstance("EC");
        KeyPair keyPair = factory.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        byte[] signature = testCase.generateSignature(message, privateKey, new SecureRandom());
        assertTrue(testCase.verifySignature(message, signature, publicKey));
    }


    @Test
    public void testSignAndVerifyFailure() throws GeneralSecurityException, IOException {
        byte[] message = "Signature Test 2".getBytes(StandardCharsets.UTF_8);
        KeyPairGenerator factory = KeyPairGenerator.getInstance("EC");
        factory.initialize(testCase.getEcParameterSpec().getCurve().getField().getFieldSize());
        KeyPair keyPair = factory.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        byte[] signature = testCase.generateSignature("Other Message".getBytes(StandardCharsets.UTF_8), privateKey, new SecureRandom());
        assertFalse(testCase.verifySignature(message, signature, publicKey));
    }

    @Test
    public void testParsePrivateKey() throws IOException {
        KeyPair oldFormat = PEMDecoder.decodeKeyPair(IOUtils.toCharArray(getClass().getResourceAsStream(testCase.getKeyFormat() + "-testkey-unprotected.txt")), null);
        KeyPair newFormat = PEMDecoder.decodeKeyPair(IOUtils.toCharArray(getClass().getResourceAsStream(testCase.getKeyFormat() + "-testkey-unprotected-newformat.txt")), null);
        assertEquals(oldFormat.getPublic(), newFormat.getPublic());
        assertEquals(oldFormat.getPrivate(), newFormat.getPrivate());
    }

}