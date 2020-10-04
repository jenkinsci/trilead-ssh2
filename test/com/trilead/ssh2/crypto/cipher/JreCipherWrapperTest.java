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

    @Test
    public void shouldMatchJreBehavior() throws Exception {
        SecureRandom rng = SecureRandom.getInstanceStrong();
        byte[] iv = new byte[16];
        rng.nextBytes(iv);
        byte[] key = new byte[16];
        rng.nextBytes(key);
        JreCipherWrapper cipher = JreCipherWrapper.getInstance("AES/CTR/NoPadding", new IvParameterSpec(iv));
        assertEquals(16, cipher.getBlockSize());
        cipher.init(true, key);
        byte[] plaintext = new byte[256];
        rng.nextBytes(plaintext);
        byte[] ciphertext = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i += cipher.getBlockSize()) {
            cipher.transformBlock(plaintext, i, ciphertext, i);
        }

        Cipher jreCipher = Cipher.getInstance("AES/CTR/NoPadding");
        jreCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] decrypted = jreCipher.doFinal(ciphertext);
        assertArrayEquals(plaintext, decrypted);

        // now the reverse
        rng.nextBytes(iv);
        rng.nextBytes(key);
        rng.nextBytes(plaintext);
        jreCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        ciphertext = jreCipher.doFinal(plaintext);

        cipher = JreCipherWrapper.getInstance("AES/CTR/NoPadding", new IvParameterSpec(iv));
        cipher.init(false, key);
        Arrays.fill(decrypted, (byte) 0);
        for (int i = 0; i < plaintext.length; i += cipher.getBlockSize()) {
            cipher.transformBlock(ciphertext, i, decrypted, i);
        }
        assertArrayEquals(plaintext, decrypted);
    }
}
