package com.trilead.ssh2;

import com.trilead.ssh2.signature.DSAKeyAlgorithm;
import com.trilead.ssh2.signature.ECDSAKeyAlgorithm;
import com.trilead.ssh2.signature.RSAKeyAlgorithm;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * @author Michael Clarke
 */
public class KnownHostsTest {

    @Test
    public void testKnownHostsPreferredAlgorithmsSshDssOnly() throws IOException, NoSuchAlgorithmException {
        KnownHosts testCase = new KnownHosts();
        KeyPairGenerator dsaGenerator = KeyPairGenerator.getInstance("DSA");
        testCase.addHostkey(new String[]{"localhost"}, "ssh-dss", new DSAKeyAlgorithm().encodePublicKey((DSAPublicKey) dsaGenerator.generateKeyPair().getPublic()));
        assertArrayEquals(new String[]{"ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", "ssh-rsa"}, testCase.getPreferredServerHostkeyAlgorithmOrder("localhost"));
    }

    @Test
    public void testKnownHostsPreferredAlgorithmsSshRsaOnly() throws IOException, NoSuchAlgorithmException {
        KnownHosts testCase = new KnownHosts();
        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        testCase.addHostkey(new String[]{"localhost"}, "ssh-rsa", new RSAKeyAlgorithm().encodePublicKey((RSAPublicKey) rsaGenerator.generateKeyPair().getPublic()));
        assertArrayEquals(new String[]{"ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", "ssh-dss"}, testCase.getPreferredServerHostkeyAlgorithmOrder("localhost"));
    }


    @Test
    public void testKnownHostsPreferredAlgorithmsEcdsaOnly() throws IOException, NoSuchAlgorithmException {
        KnownHosts testCase = new KnownHosts();
        KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance("EC");
        testCase.addHostkey(new String[]{"localhost"}, "ecdsa-sha2-nistp256", new ECDSAKeyAlgorithm.ECDSASha2Nistp256().encodePublicKey((ECPublicKey) ecGenerator.generateKeyPair().getPublic()));
        assertArrayEquals(new String[]{"ecdsa-sha2-nistp256", "ssh-ed25519", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp384", "ssh-rsa", "ssh-dss"}, testCase.getPreferredServerHostkeyAlgorithmOrder("localhost"));
    }

    @Test
    public void testKnownHostsPreferredAlgorithmsNoKnownHosts() throws IOException {
        KnownHosts testCase = new KnownHosts();
        assertNull(testCase.getPreferredServerHostkeyAlgorithmOrder("localhost"));
    }


    /**
     * The Known Hosts implementation currently expects multiple known hosts entries for the same hosts to result in
     * a null value being returned for the preferred algorithms, rather than a list of all those known algorithms. This
     * seems an odd choice, but I'll protect that feature for now.
     *
     * @throws IOException              if failing to add the test keys
     * @throws GeneralSecurityException the general security exception
     */
    @Test
    public void testKnownHostsPreferredAlgorithmsRsaAndDssHosts() throws IOException, GeneralSecurityException {
        KnownHosts testCase = new KnownHosts();
        KeyPairGenerator dsaGenerator = KeyPairGenerator.getInstance("DSA");
        testCase.addHostkey(new String[]{"localhost"}, "ssh-dss", new DSAKeyAlgorithm().encodePublicKey((DSAPublicKey) dsaGenerator.generateKeyPair().getPublic()));
        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        testCase.addHostkey(new String[]{"localhost"}, "ssh-rsa", new RSAKeyAlgorithm().encodePublicKey((RSAPublicKey) rsaGenerator.generateKeyPair().getPublic()));
        assertNull(testCase.getPreferredServerHostkeyAlgorithmOrder("localhost"));
    }


    @Test
    public void testVerifyKnownHostKey() throws IOException, NoSuchAlgorithmException {
        KnownHosts testCase = new KnownHosts();
        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        byte[] encodedPublicKey = new RSAKeyAlgorithm().encodePublicKey((RSAPublicKey) rsaGenerator.generateKeyPair().getPublic());
        byte[] encodedPublicKey2 = new RSAKeyAlgorithm().encodePublicKey((RSAPublicKey) rsaGenerator.generateKeyPair().getPublic());
        testCase.addHostkey(new String[]{"testhost"}, "ssh-rsa", encodedPublicKey);
        assertEquals(KnownHosts.HOSTKEY_IS_NEW, testCase.verifyHostkey("testhost2", "ssh-rsa", encodedPublicKey));
        assertEquals(KnownHosts.HOSTKEY_HAS_CHANGED, testCase.verifyHostkey("testhost", "ssh-rsa", encodedPublicKey2));
        assertEquals(KnownHosts.HOSTKEY_IS_OK, testCase.verifyHostkey("testhost", "ssh-rsa", encodedPublicKey));
    }

}
