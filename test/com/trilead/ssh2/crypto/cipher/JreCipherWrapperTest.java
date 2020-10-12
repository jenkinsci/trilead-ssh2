package com.trilead.ssh2.crypto.cipher;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class JreCipherWrapperTest {

    public void shouldMatchJreBehavior(String cipherName, int blokSize, int keySize) throws Exception {
       String algorithm = cipherName.contains("/") ? cipherName.substring(0, cipherName.indexOf('/')) : cipherName;
        SecureRandom rng = new SecureRandom();
        byte[] iv = new byte[blokSize];
        rng.nextBytes(iv);
        byte[] key = new byte[keySize];
        rng.nextBytes(key);
        JreCipherWrapper cipher = JreCipherWrapper.getInstance(cipherName, new IvParameterSpec(iv));
        assertEquals(blokSize, cipher.getBlockSize());
        cipher.init(true, key);
        byte[] plaintext = new byte[256];
        rng.nextBytes(plaintext);
        byte[] ciphertext = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i += cipher.getBlockSize()) {
            cipher.transformBlock(plaintext, i, ciphertext, i);
        }

        Cipher jreCipher = Cipher.getInstance(cipherName);
        jreCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algorithm), new IvParameterSpec(iv));
        byte[] decrypted = jreCipher.doFinal(ciphertext);
        assertArrayEquals(plaintext, decrypted);

        // now the reverse
        rng.nextBytes(iv);
        rng.nextBytes(key);
        rng.nextBytes(plaintext);
        jreCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm), new IvParameterSpec(iv));
        ciphertext = jreCipher.doFinal(plaintext);

        cipher = JreCipherWrapper.getInstance(cipherName, new IvParameterSpec(iv));
        cipher.init(false, key);
        Arrays.fill(decrypted, (byte) 0);
        for (int i = 0; i < plaintext.length; i += cipher.getBlockSize()) {
            cipher.transformBlock(ciphertext, i, decrypted, i);
        }
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void testMatchBehaviorAesCtrNoPadding() throws Exception {
        shouldMatchJreBehavior("AES/CTR/NoPadding", 16, 16);
        shouldMatchJreBehavior("AES/CTR/NoPadding", 16, 24);
        shouldMatchJreBehavior("AES/CTR/NoPadding", 16, 32);
    }

    @Test
    public void testMatchBehaviorAesCbcNoPadding() throws Exception {
        shouldMatchJreBehavior("AES/CBC/NoPadding", 16,16);
        shouldMatchJreBehavior("AES/CBC/NoPadding", 16,24);
        shouldMatchJreBehavior("AES/CBC/NoPadding", 16,32);
    }

    @Test
    public void testMatchBehaviorBlowfishCtrNoPaddingg() throws Exception {
        shouldMatchJreBehavior("Blowfish/CTR/NoPadding", 8, 16);
    }

    @Test
    public void testMatchBehaviorBlowfishCbcNoPaddingg() throws Exception {
        shouldMatchJreBehavior("Blowfish/CBC/NoPadding", 8, 16);
    }

    @Test
    public void testMatchBehaviorDESedeCtrNoPadding() throws Exception {
        shouldMatchJreBehavior("DESede/CTR/NoPadding", 8, 24);
    }

    @Test
    public void testMatchBehaviorDESedeCbcNoPadding() throws Exception {
        shouldMatchJreBehavior("DESede/CBC/NoPadding", 8, 24);
    }

    @Test
    public void testMatchBehaviorDESCbcNoPadding() throws Exception {
        shouldMatchJreBehavior("DES/CBC/NoPadding", 8, 8);
    }
}
