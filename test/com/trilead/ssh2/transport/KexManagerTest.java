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
    public void testMergeKexParameters() throws NegotiateException {
        // Arrange: Create sample KexParameters for client and server
        KexParameters client = new KexParameters();
        client.kex_algorithms = new String[]{"algo1", "algo2"};
        client.server_host_key_algorithms = new String[]{"key1", "key2"};
        client.encryption_algorithms_client_to_server = new String[]{"enc1", "enc2"};
        client.encryption_algorithms_server_to_client = new String[]{"enc2", "enc3"};
        client.mac_algorithms_client_to_server = new String[]{"mac1", "mac2"};
        client.mac_algorithms_server_to_client = new String[]{"mac2", "mac3"};
        client.compression_algorithms_client_to_server = new String[]{"comp1"};
        client.compression_algorithms_server_to_client = new String[]{"comp1", "comp2"};
        client.languages_client_to_server = new String[]{"lang1"};
        client.languages_server_to_client = new String[]{"lang2"};

        KexParameters server = new KexParameters();
        server.kex_algorithms = new String[]{"algo2", "algo3"};
        server.server_host_key_algorithms = new String[]{"key2", "key3"};
        server.encryption_algorithms_client_to_server = new String[]{"enc2", "enc3"};
        server.encryption_algorithms_server_to_client = new String[]{"enc1", "enc2"};
        server.mac_algorithms_client_to_server = new String[]{"mac2", "mac3"};
        server.mac_algorithms_server_to_client = new String[]{"mac1", "mac2"};
        server.compression_algorithms_client_to_server = new String[]{"comp1", "comp2"};
        server.compression_algorithms_server_to_client = new String[]{"comp1"};
        server.languages_client_to_server = new String[]{"lang1", "lang3"};
        server.languages_server_to_client = new String[]{"lang2", "lang4"};

        // Act: Call the method under test
        NegotiatedParameters result = kexManager.mergeKexParameters(client, server);

        // Assert: Validate results
        assertEquals("algo2", result.kex_algo);
        assertEquals("key2", result.server_host_key_algo);
        assertEquals("enc2", result.enc_algo_client_to_server);
        assertEquals("enc2", result.enc_algo_server_to_client);
        assertEquals("mac2", result.mac_algo_client_to_server);
        assertEquals("mac2", result.mac_algo_server_to_client);
        assertEquals("comp1", result.comp_algo_client_to_server);
        assertEquals("comp1", result.comp_algo_server_to_client);
        assertEquals("lang1", result.lang_client_to_server);
        assertEquals("lang2", result.lang_server_to_client);
    }

	 @Test
    public void testMergeKexParametersMismatch() {
        // Arrange: Create client and server parameters with no common algorithms
        KexParameters client = new KexParameters();
        client.kex_algorithms = new String[]{"algoX"};
        client.server_host_key_algorithms = new String[]{"keyX"};
        client.encryption_algorithms_client_to_server = new String[]{"encX"};
        client.encryption_algorithms_server_to_client = new String[]{"encY"};
        client.mac_algorithms_client_to_server = new String[]{"macX"};
        client.mac_algorithms_server_to_client = new String[]{"macY"};
        client.compression_algorithms_client_to_server = new String[]{"compX"};
        client.compression_algorithms_server_to_client = new String[]{"compY"};
        client.languages_client_to_server = new String[]{"langX"};
        client.languages_server_to_client = new String[]{"langY"};

        KexParameters server = new KexParameters();
        server.kex_algorithms = new String[]{"algoY"};
        server.server_host_key_algorithms = new String[]{"keyY"};
        server.encryption_algorithms_client_to_server = new String[]{"encY"};
        server.encryption_algorithms_server_to_client = new String[]{"encZ"};
        server.mac_algorithms_client_to_server = new String[]{"macY"};
        server.mac_algorithms_server_to_client = new String[]{"macZ"};
        server.compression_algorithms_client_to_server = new String[]{"compY"};
        server.compression_algorithms_server_to_client = new String[]{"compZ"};
        server.languages_client_to_server = new String[]{"langY"};
        server.languages_server_to_client = new String[]{"langZ"};


        try {
            // Act: This should throw an exception due to no common algorithms
            kexManager.mergeKexParameters(client, server);
            fail("Expected NegotiateException was not thrown.");
        } catch (NegotiateException e) {
            // Print exception content
            System.out.println("NegotiateException occurred: " + e.getMessage());
        }
    }


}
