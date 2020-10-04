package com.trilead.ssh2.crypto.cipher;

import com.trilead.ssh2.crypto.PEMDecoder;
import com.trilead.ssh2.crypto.PEMStructure;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

/*
    Tests to read protected keys with different encryption algorithms.

    @author Kuisathaverat
 */
public class ProtectedKeys {

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
