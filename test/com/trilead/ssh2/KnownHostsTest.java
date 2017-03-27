package com.trilead.ssh2;

import com.trilead.ssh2.signature.DSAPublicKey;
import com.trilead.ssh2.signature.DSASHA1Verify;
import com.trilead.ssh2.signature.RSAPublicKey;
import com.trilead.ssh2.signature.RSASHA1Verify;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;

/**
 * @author Michael Clarke
 */
public class KnownHostsTest {

    @Test
    public void testKnownHostsPreferredAlgorithmsSshDssOnly() throws IOException {
        KnownHosts testCase = new KnownHosts();
        testCase.addHostkey(new String[]{"localhost"}, "ssh-dss", DSASHA1Verify.encodeSSHDSAPublicKey(new DSAPublicKey(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE, BigInteger.ONE)));
        assertArrayEquals(new String[]{"ssh-dss", "ssh-rsa"}, testCase.getPreferredServerHostkeyAlgorithmOrder("localhost"));
    }

    @Test
    public void testKnownHostsPreferredAlgorithmsSshRsaOnly() throws IOException {
        KnownHosts testCase = new KnownHosts();
        testCase.addHostkey(new String[]{"localhost"}, "ssh-rsa", RSASHA1Verify.encodeSSHRSAPublicKey(new RSAPublicKey(BigInteger.ONE, BigInteger.ONE)));
        assertArrayEquals(new String[]{"ssh-rsa", "ssh-dss"}, testCase.getPreferredServerHostkeyAlgorithmOrder("localhost"));
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
     * @throws IOException if failing to add the test keys
     */
    @Test
    public void testKnownHostsPreferredAlgorithmsRsaAndDssHosts() throws IOException {
        KnownHosts testCase = new KnownHosts();
        testCase.addHostkey(new String[]{"localhost"}, "ssh-dss", DSASHA1Verify.encodeSSHDSAPublicKey(new DSAPublicKey(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE, BigInteger.ONE)));
        testCase.addHostkey(new String[]{"localhost"}, "ssh-rsa", RSASHA1Verify.encodeSSHRSAPublicKey(new RSAPublicKey(BigInteger.ONE, BigInteger.ONE)));
        assertNull(testCase.getPreferredServerHostkeyAlgorithmOrder("localhost"));
    }

}
