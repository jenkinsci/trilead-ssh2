package com.trilead.ssh2.crypto.cipher;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class BlockCipherTest {

    public void shouldMatchJreBehavior(String cipherName, int blokSize, int keySize) throws Exception {
        String algorithm = "";
        String jreCipherName = "";
        SecureRandom rng = new SecureRandom();
        byte[] iv = new byte[blokSize];
        rng.nextBytes(iv);
        byte[] key = new byte[keySize];
        rng.nextBytes(key);
        byte[] plaintext = new byte[256];
        rng.nextBytes(plaintext);
        byte[] ciphertext = new byte[plaintext.length];

        if(cipherName.startsWith("aes")){
            algorithm = "AES";
        } else if (cipherName.startsWith("3des")){
            algorithm = "DESede";
        } else if (cipherName.startsWith("blowfish")){
            algorithm = "Blowfish";
        }
        if(cipherName.endsWith("-ctr")){
            jreCipherName = algorithm + "/CTR/NoPadding";
        } else if (cipherName.endsWith("-cbc")){
            jreCipherName = algorithm + "/CBC/NoPadding";
        }

        BlockCipher bc = BlockCipherFactory.createCipher(cipherName, true, key, iv);
        for (int i = 0; i < plaintext.length; i += bc.getBlockSize()) {
            bc.transformBlock(plaintext, i, ciphertext, i);
        }
        Cipher jreCipher = Cipher.getInstance(jreCipherName);
        assertEquals(blokSize, jreCipher.getBlockSize());
        jreCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algorithm), new IvParameterSpec(iv));
        byte[] decrypted = jreCipher.doFinal(ciphertext);
        assertArrayEquals(plaintext, decrypted);

        // now the reverse
        rng.nextBytes(iv);
        rng.nextBytes(key);
        rng.nextBytes(plaintext);
        jreCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm), new IvParameterSpec(iv));
        ciphertext = jreCipher.doFinal(plaintext);

        bc = BlockCipherFactory.createCipher(cipherName, false, key, iv);
        for (int i = 0; i < plaintext.length; i += bc.getBlockSize()) {
            bc.transformBlock(ciphertext, i, decrypted, i);
        }
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void testMatchBehaviorAesCtrNoPadding() throws Exception {
        shouldMatchJreBehavior("aes128-ctr", 16, 16);
        shouldMatchJreBehavior("aes192-ctr", 16, 24);
        shouldMatchJreBehavior("aes256-ctr", 16, 32);
    }

    @Test
    public void testMatchBehaviorAesCbcNoPadding() throws Exception {
        shouldMatchJreBehavior("aes128-cbc", 16, 16);
        shouldMatchJreBehavior("aes192-cbc", 16, 24);
        shouldMatchJreBehavior("aes256-cbc", 16, 32);
    }

    @Test
    public void testMatchBehaviorBlowfishCtrNoPaddingg() throws Exception {
        shouldMatchJreBehavior("blowfish-ctr", 8, 16);
    }

    @Test
    public void testMatchBehaviorBlowfishCbcNoPaddingg() throws Exception {
        shouldMatchJreBehavior("blowfish-cbc", 8, 16);
    }

    @Test
    public void testMatchBehaviorDESedeCtrNoPadding() throws Exception {
        shouldMatchJreBehavior("3des-ctr", 8, 24);
    }

    @Test
    public void testMatchBehaviorDESedeCbcNoPadding() throws Exception {
        shouldMatchJreBehavior("3des-cbc", 8, 24);
    }
}
