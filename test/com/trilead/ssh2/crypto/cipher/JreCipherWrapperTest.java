package com.trilead.ssh2.crypto.cipher;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import com.trilead.ssh2.crypto.PEMDecoder;
import com.trilead.ssh2.crypto.PEMStructure;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@org.junit.Ignore
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

    @Test
    public void testEncryptedKeyDES() throws Exception {
        char[] des_cbc = IOUtils.toCharArray(getClass().getResourceAsStream("des_cbc.pem"));
        char[] unencrypted = IOUtils.toCharArray(getClass().getResourceAsStream("key.pem"));
        String password = "password";

        PEMStructure psOrg = PEMDecoder.parsePEM(unencrypted);

        PEMStructure ps = PEMDecoder.parsePEM(des_cbc);
        PEMDecoder.decryptPEM(ps, password);
        PEMDecoder.decodeKeyPair(des_cbc, password);
        assertEquals(psOrg, ps);
    }

    @Test
    public void testEncryptedKeyTripleDES() throws Exception {
        char[] des_ede3_cbc = IOUtils.toCharArray(getClass().getResourceAsStream("des_ede3_cbc.pem"));
        char[] unencrypted = IOUtils.toCharArray(getClass().getResourceAsStream("key.pem"));
        String password = "password";

        PEMStructure psOrg = PEMDecoder.parsePEM(unencrypted);

        PEMStructure ps = PEMDecoder.parsePEM(des_ede3_cbc);
        PEMDecoder.decryptPEM(ps, password);
        PEMDecoder.decodeKeyPair(des_ede3_cbc, password);
        assertEquals(psOrg, ps);
    }

    @Test
    public void testEncryptedKeyAES128() throws Exception {
        char[] aes128_cbc = IOUtils.toCharArray(getClass().getResourceAsStream("aes128_cbc.pem"));
        char[] unencrypted = IOUtils.toCharArray(getClass().getResourceAsStream("key.pem"));
        String password = "password";

        PEMStructure psOrg = PEMDecoder.parsePEM(unencrypted);

        PEMStructure ps = PEMDecoder.parsePEM(aes128_cbc);
        PEMDecoder.decryptPEM(ps, password);
        PEMDecoder.decodeKeyPair(aes128_cbc, password);
        assertEquals(psOrg, ps);
    }

    @Test
    public void testEncryptedKeyAES192() throws Exception {
        char[] aes192_cbc = IOUtils.toCharArray(getClass().getResourceAsStream("aes192_cbc.pem"));
        char[] unencrypted = IOUtils.toCharArray(getClass().getResourceAsStream("key.pem"));
        String password = "password";

        PEMStructure psOrg = PEMDecoder.parsePEM(unencrypted);

        PEMStructure ps = PEMDecoder.parsePEM(aes192_cbc);
        PEMDecoder.decryptPEM(ps, password);
        PEMDecoder.decodeKeyPair(aes192_cbc, password);
        assertEquals(psOrg, ps);
    }

    @Test
    public void testEncryptedKeyAES256() throws Exception {
        char[] aes256_cbc = IOUtils.toCharArray(getClass().getResourceAsStream("aes256_cbc.pem"));
        char[] unencrypted = IOUtils.toCharArray(getClass().getResourceAsStream("key.pem"));
        String password = "password";

        PEMStructure psOrg = PEMDecoder.parsePEM(unencrypted);

        PEMStructure ps = PEMDecoder.parsePEM(aes256_cbc);
        PEMDecoder.decryptPEM(ps, password);
        PEMDecoder.decodeKeyPair(aes256_cbc, password);
        assertEquals(psOrg, ps);
    }
}
