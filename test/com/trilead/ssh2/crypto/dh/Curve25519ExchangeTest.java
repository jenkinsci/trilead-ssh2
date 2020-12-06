package com.trilead.ssh2.crypto.dh;

import com.google.crypto.tink.subtle.X25519;

import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Created by Kenny Root on 1/23/16.
 */
public class Curve25519ExchangeTest {
	private static final byte[] ALICE_PRIVATE = toByteArray("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
	private static final byte[] ALICE_PUBLIC = toByteArray("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

	private static final byte[] BOB_PRIVATE = toByteArray("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
	private static final byte[] BOB_PUBLIC = toByteArray("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

	private static final byte[] KNOWN_SHARED_SECRET = toByteArray("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
	private static final BigInteger KNOWN_SHARED_SECRET_BI = new BigInteger(1, KNOWN_SHARED_SECRET);

	private static byte[] toByteArray(String s) {
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < b.length; i++) {
			int hexIndex = i * 2;
			int hexDigit = Integer.parseInt(s.substring(hexIndex, hexIndex + 2), 16);
			b[i] = (byte) hexDigit;
		}
		return b;
	}

	@Test
	public void selfAgreement() throws Exception {
		byte[] alicePrivKey = X25519.generatePrivateKey();
		byte[] alicePubKey = X25519.publicFromPrivate(alicePrivKey);

		byte[] bobPrivKey = X25519.generatePrivateKey();
		byte[] bobPubKey = X25519.publicFromPrivate(bobPrivKey);

		Curve25519Exchange alice = new Curve25519Exchange(alicePrivKey);
		alice.setF(bobPubKey);

		Curve25519Exchange bob = new Curve25519Exchange(bobPrivKey);
		bob.setF(alicePubKey);

		assertNotNull(alice.sharedSecret);
		assertEquals(alice.sharedSecret, bob.sharedSecret);
	}

	@Test
	public void deriveAlicePublicKey() throws Exception {
		byte[] pubKey = X25519.publicFromPrivate(ALICE_PRIVATE);
		assertArrayEquals(ALICE_PUBLIC, pubKey);
	}

	@Test
	public void deriveBobPublicKey() throws Exception {
		byte[] pubKey = X25519.publicFromPrivate(BOB_PRIVATE);
		assertArrayEquals(BOB_PUBLIC, pubKey);
	}

	@Test
	public void knownValues_Alice() throws Exception {
		Curve25519Exchange ex = new Curve25519Exchange(ALICE_PRIVATE);
		ex.setF(BOB_PUBLIC);
		assertEquals(KNOWN_SHARED_SECRET_BI, ex.sharedSecret);
	}

	@Test
	public void knownValues_Bob() throws Exception {
		Curve25519Exchange ex = new Curve25519Exchange(BOB_PRIVATE);
		ex.setF(ALICE_PUBLIC);
		assertEquals(KNOWN_SHARED_SECRET_BI, ex.sharedSecret);
	}
}
