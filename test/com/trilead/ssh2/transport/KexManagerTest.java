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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
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
}
