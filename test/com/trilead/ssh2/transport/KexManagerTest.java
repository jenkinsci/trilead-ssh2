package com.trilead.ssh2.transport;

import com.trilead.ssh2.DHGexParameters;
import com.trilead.ssh2.RandomFactory;
import com.trilead.ssh2.ServerHostKeyVerifier;
import com.trilead.ssh2.crypto.CryptoWishList;
import com.trilead.ssh2.packets.PacketKexInit;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.testcontainers.shaded.com.trilead.ssh2.packets.Packets;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;


@RunWith(value = MockitoJUnitRunner.class)
public class KexManagerTest {
	@Mock private TransportManager tm;
	@Mock private ClientServerHello csh;
	@Mock private ServerHostKeyVerifier keyVerifier;
	@Mock private SecureRandom rnd;
	private final CryptoWishList initialCwl = new CryptoWishList();

	private KexManager kexManager;

	@Captor
	private ArgumentCaptor<byte[]> packetCaptor;

	@Before
	public void setupMocks() {
		kexManager = new KexManager(tm, csh, initialCwl, null, 0,
			keyVerifier, rnd);
	}

	@Test(expected = IllegalArgumentException.class)
	public void invalidServerHostkeyAlgorithms_Exception() {
		KexManager.checkServerHostkeyAlgorithmsList(new String[]{"non-existent"});
	}

	@Test(expected = IllegalArgumentException.class)
	public void invalidKexAlgorithm_Exception() {
		KexManager.checkKexAlgorithmList(new String[]{"non-existent"});
	}

	@Test
	public void twoKEXCalls_OneOutputPacket() throws Exception {
		kexManager.initiateKEX(new CryptoWishList(), new DHGexParameters());
		kexManager.initiateKEX(new CryptoWishList(), new DHGexParameters());
		verify(tm, times(1)).sendKexMessage(any());
	}

	@Test(expected = IOException.class)
	public void handlePacket_BeforeKex_NotKexInit_ThrowsException() throws Exception {
		kexManager.handleMessage(new byte[] {Packets.SSH_MSG_NEWKEYS}, 1);
	}

	public static class PacketTypeMatcher extends TypeSafeMatcher<byte[]> {
		private final int packetType;

		public PacketTypeMatcher(int packetType) {
			this.packetType = packetType;
		}

		@Override
		protected boolean matchesSafely(byte[] item) {
			return item != null && item.length > 0 && item[0] == packetType;
		}

		@Override
		public void describeTo(Description description) {
			description.appendText("with packet type '" + packetType + "'");
		}
	}


	@Test(expected = IOException.class)
	public void handlePacket_KexInit_StartsKex_RejectsDoubleKexInit() throws Exception {
		PacketKexInit packetKexInit = new PacketKexInit(new CryptoWishList(),RandomFactory.create());
		byte[] payload = packetKexInit.getPayload();
		kexManager.handleMessage(payload, payload.length);
		kexManager.handleMessage(payload, payload.length);
	}

	@Test(expected = IOException.class)
	public void handlePacket_KexInit_NonMatchingProposals() throws Exception {
		PacketKexInit packetKexInit = new PacketKexInit(new CryptoWishList(),RandomFactory.create());
		packetKexInit.getKexParameters().kex_algorithms = new String[] { "non-existent" };
		byte[] payload = packetKexInit.getPayload();
		kexManager.handleMessage(payload, payload.length);
	}

	@Test
	public void handlePacket_KexInit_Guessed_NonMatchingProposals() throws Exception {
		PacketKexInit packetKexInit = new PacketKexInit(new CryptoWishList(),RandomFactory.create());

		KexParameters kp = packetKexInit.getKexParameters();
		String tmp = kp.kex_algorithms[0];
		kp.kex_algorithms[0] = kp.kex_algorithms[1];
		kp.kex_algorithms[1] = tmp;

		packetKexInit.getKexParameters().first_kex_packet_follows = true;

		byte[] payload = packetKexInit.getPayload();
		kexManager.handleMessage(payload, payload.length);

		// If this weren't ignored, it would throw an exception
		kexManager.handleMessage(new byte[] { Packets.SSH_MSG_NEWKEYS }, 1);
	}

	@Test
    public void testSuccessfulNegotiation() {
        KexParameters client = new KexParameters();
        client.kex_algorithms = new String[]{"ecdh-sha2-nistp256", "diffie-hellman-group14-sha1"};
        client.server_host_key_algorithms = new String[]{"ssh-rsa", "ssh-ed25519"};
        client.encryption_algorithms_client_to_server = new String[]{"aes128-ctr", "aes256-ctr"};
        client.encryption_algorithms_server_to_client = new String[]{"aes128-ctr", "aes256-ctr"};
        client.mac_algorithms_client_to_server = new String[]{"hmac-sha2-256", "hmac-sha1"};
        client.mac_algorithms_server_to_client = new String[]{"hmac-sha2-256", "hmac-sha1"};
        client.compression_algorithms_client_to_server = new String[]{"none", "zlib"};
        client.compression_algorithms_server_to_client = new String[]{"none", "zlib"};
        client.languages_client_to_server = new String[]{"en-US", "fr-FR"};
        client.languages_server_to_client = new String[]{"en-US", "fr-FR"};

        KexParameters server = new KexParameters();
        server.kex_algorithms = new String[]{"ecdh-sha2-nistp256", "curve25519-sha256"};
        server.server_host_key_algorithms = new String[]{"ssh-ed25519", "ssh-rsa"};
        server.encryption_algorithms_client_to_server = new String[]{"aes256-ctr", "aes128-ctr"};
        server.encryption_algorithms_server_to_client = new String[]{"aes256-ctr", "aes128-ctr"};
        server.mac_algorithms_client_to_server = new String[]{"hmac-sha2-256", "hmac-sha1"};
        server.mac_algorithms_server_to_client = new String[]{"hmac-sha2-256", "hmac-sha1"};
        server.compression_algorithms_client_to_server = new String[]{"zlib", "none"};
        server.compression_algorithms_server_to_client = new String[]{"zlib", "none"};
        server.languages_client_to_server = new String[]{"fr-FR", "en-US"};
        server.languages_server_to_client = new String[]{"fr-FR", "en-US"};

        try {
            NegotiatedParameters np = kexManager.mergeKexParameters(client, server);

            assertEquals("ecdh-sha2-nistp256", np.kex_algo);
            assertEquals("ssh-ed25519", np.server_host_key_algo);
            assertEquals("aes128-ctr", np.enc_algo_client_to_server);
            assertEquals("aes128-ctr", np.enc_algo_server_to_client);
            assertEquals("hmac-sha2-256", np.mac_algo_client_to_server);
            assertEquals("hmac-sha2-256", np.mac_algo_server_to_client);
            assertEquals("zlib", np.comp_algo_client_to_server);
            assertEquals("zlib", np.comp_algo_server_to_client);
            assertEquals("fr-FR", np.lang_client_to_server);
            assertEquals("fr-FR", np.lang_server_to_client);

        } catch (NegotiateException e) {
            fail("Negotiation should not fail: " + e.getMessage());
        }
    }

    @Test
    public void testNoMatchingKexAlgorithm() {
        KexParameters client = new KexParameters();
        client.kex_algorithms = new String[]{"diffie-hellman-group1-sha1"};

        KexParameters server = new KexParameters();
        server.kex_algorithms = new String[]{"ecdh-sha2-nistp256"};

        try {
            kexManager.mergeKexParameters(client, server);
            fail("Expected NegotiateException due to no matching key exchange algorithm.");
        } catch (NegotiateException e) {
            // Expected exception
        }
    }

    @Test
    public void testNoMatchingEncryptionAlgorithms() {
        KexParameters client = new KexParameters();
        client.encryption_algorithms_client_to_server = new String[]{"aes192-cbc"};

        KexParameters server = new KexParameters();
        server.encryption_algorithms_client_to_server = new String[]{"aes256-ctr"};

        try {
            kexManager.mergeKexParameters(client, server);
            fail("Expected NegotiateException due to no matching encryption algorithm.");
        } catch (NegotiateException e) {
            // Expected exception
        }
    }

    @Test
    public void testNoMatchingMACAlgorithms() {
        KexParameters client = new KexParameters();
        client.mac_algorithms_client_to_server = new String[]{"hmac-md5"};

        KexParameters server = new KexParameters();
        server.mac_algorithms_client_to_server = new String[]{"hmac-sha2-256"};

        try {
            kexManager.mergeKexParameters(client, server);
            fail("Expected NegotiateException due to no matching MAC algorithm.");
        } catch (NegotiateException e) {
            // Expected exception
        }
    }

    @Test
    public void testNoMatchingCompressionAlgorithms() {
        KexParameters client = new KexParameters();
        client.compression_algorithms_client_to_server = new String[]{"zlib@openssh.com"};

        KexParameters server = new KexParameters();
        server.compression_algorithms_client_to_server = new String[]{"none"};

        try {
            kexManager.mergeKexParameters(client, server);
            fail("Expected NegotiateException due to no matching compression algorithm.");
        } catch (NegotiateException e) {
            // Expected exception
        }
    }

    @Test
    public void testLanguageNegotiationFailure() {
        KexParameters client = new KexParameters();
        client.languages_client_to_server = new String[]{"es-ES"};
        client.languages_server_to_client = new String[]{"es-ES"};

        KexParameters server = new KexParameters();
        server.languages_client_to_server = new String[]{"de-DE"};
        server.languages_server_to_client = new String[]{"de-DE"};

        try {
            NegotiatedParameters np = kexManager.mergeKexParameters(client, server);
            assertEquals(null, np.lang_client_to_server);
            assertEquals(null, np.lang_server_to_client);
        } catch (NegotiateException e) {
            fail("Negotiation should not fail for language negotiation.");
        }
    }

}
