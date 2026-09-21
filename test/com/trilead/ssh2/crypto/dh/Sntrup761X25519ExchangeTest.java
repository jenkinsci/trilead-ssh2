package com.trilead.ssh2.crypto.dh;

import com.google.crypto.tink.subtle.X25519;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for the SNTRUP761/X25519 hybrid key exchange wiring and shared secret construction.
 */
public class Sntrup761X25519ExchangeTest {

	@Test
	public void getInstanceReturnsSntrupExchangeForStandardName() {
		GenericDhExchange exchange = GenericDhExchange.getInstance(Sntrup761X25519Exchange.NAME);

		assertTrue(exchange instanceof Sntrup761X25519Exchange);
	}

	@Test
	public void getInstanceReturnsSntrupExchangeForOpenSshName() {
		GenericDhExchange exchange = GenericDhExchange.getInstance(Sntrup761X25519Exchange.ALT_NAME);

		assertTrue(exchange instanceof Sntrup761X25519Exchange);
	}

	@Test
	public void getHashAlgoUsesSha512() {
		Sntrup761X25519Exchange exchange = new Sntrup761X25519Exchange(new FakeKem());

		assertEquals("SHA-512", exchange.getHashAlgo());
	}

	@Test
	public void initBuildsClientPublicValueFromSntrupAndX25519PublicKeys() throws IOException {
		FakeKem kem = new FakeKem();
		Sntrup761X25519Exchange exchange = new Sntrup761X25519Exchange(kem);

		exchange.init(Sntrup761X25519Exchange.ALT_NAME);

		byte[] clientPublic = exchange.getE();
		assertEquals(BouncyCastleSntrup761.PUBLIC_KEY_SIZE + Curve25519Exchange.KEY_SIZE, clientPublic.length);
		assertArrayEquals(kem.publicKey, Arrays.copyOf(clientPublic, BouncyCastleSntrup761.PUBLIC_KEY_SIZE));
	}

	@Test
	public void setFComputesStringEncodedSha512HybridSharedSecret() throws Exception {
		FakeKem kem = new FakeKem();
		Sntrup761X25519Exchange exchange = new Sntrup761X25519Exchange(kem);
		exchange.init(Sntrup761X25519Exchange.NAME);

		byte[] serverPrivate = X25519.generatePrivateKey();
		byte[] serverPublic = X25519.publicFromPrivate(serverPrivate);
		byte[] clientX25519Public = Arrays.copyOfRange(exchange.getE(), BouncyCastleSntrup761.PUBLIC_KEY_SIZE,
				exchange.getE().length);
		byte[] x25519Secret = X25519.computeSharedSecret(serverPrivate, clientX25519Public);
		byte[] expected = java.security.MessageDigest.getInstance("SHA-512").digest(concat(kem.secret, x25519Secret));

		exchange.setF(concat(kem.encapsulation, serverPublic));

		assertArrayEquals(expected, exchange.getKeyMaterialSharedSecret());
		assertEquals(64, exchange.getKeyMaterialSharedSecret().length);
	}

	@Test(expected = IllegalArgumentException.class)
	public void initRejectsUnknownAlgorithmName() throws IOException {
		new Sntrup761X25519Exchange(new FakeKem()).init("sntrup761x25519-sha512@example.com");
	}

	@Test(expected = IOException.class)
	public void setFRejectsWrongServerValueLength() throws IOException {
		Sntrup761X25519Exchange exchange = new Sntrup761X25519Exchange(new FakeKem());
		exchange.init(Sntrup761X25519Exchange.NAME);

		exchange.setF(new byte[1]);
	}

	private static byte[] concat(byte[] first, byte[] second) {
		byte[] result = Arrays.copyOf(first, first.length + second.length);
		System.arraycopy(second, 0, result, first.length, second.length);
		return result;
	}

	private static final class FakeKem implements KeyEncapsulationMethod {
		private final byte[] publicKey = fill(BouncyCastleSntrup761.PUBLIC_KEY_SIZE, 1);
		private final byte[] encapsulation = fill(BouncyCastleSntrup761.ENCAPSULATION_SIZE, 2);
		private final byte[] secret = fill(BouncyCastleSntrup761.SECRET_SIZE, 3);

		@Override
		public void init() {
			// No-op.
		}

		@Override
		public byte[] getPublicKey() {
			return publicKey.clone();
		}

		@Override
		public byte[] extractSecret(byte[] encapsulated) throws IOException {
			assertArrayEquals(encapsulation, encapsulated);
			return secret.clone();
		}

		@Override
		public int getEncapsulationLength() {
			return encapsulation.length;
		}

		private static byte[] fill(int length, int seed) {
			byte[] value = new byte[length];
			for (int i = 0; i < value.length; i++) {
				value[i] = (byte) (seed + i);
			}
			return value;
		}
	}
}
