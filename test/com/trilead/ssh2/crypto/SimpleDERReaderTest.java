package com.trilead.ssh2.crypto;

import org.junit.Test;

import java.io.IOException;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

/**
 * Created by kenny on 12/25/15.
 */
public class SimpleDERReaderTest {
	@Test
	public void readLength_Extended_OverlyLongLength() throws Exception {
		byte[] vector = new byte[] {
				(byte) 0x85, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		assertEquals(-1, reader.readLength());
	}

	@Test
	public void readLength_Extended_TooLongForInt() throws Exception {
		byte[] vector = new byte[] {
				(byte) 0x84, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		assertEquals(-1, reader.readLength());
	}

	@Test
	public void readLength_Extended_Zero() throws Exception {
		byte[] vector = new byte[] {
				(byte) 0x80, (byte) 0x01
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		assertEquals(-1, reader.readLength());
	}

	@Test
	public void readLength_Extended_Valid() throws Exception {
		byte[] vector = new byte[] {
				(byte) 0x82, (byte) 0x05, (byte) 0xFF
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		assertEquals(0x5FF, reader.readLength());
	}

	@Test
	public void readLength_Short_Zero() throws Exception {
		byte[] vector = new byte[] {
				(byte) 0x00
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		assertEquals(0, reader.readLength());
	}

	@Test
	public void readLength_Short_Regular() throws Exception {
		byte[] vector = new byte[] {
				(byte) 0x09
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		assertEquals(9, reader.readLength());
	}

	@Test
	public void readInt_MaxInt() throws Exception {
		byte[] vector = new byte[] {
				(byte) 0x02, (byte) 0x04, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		assertEquals("ffffffff", reader.readInt().toString(16));
	}

	@Test
	public void readInt_NotReallyInteger() {
		byte[] vector = new byte[] {
				(byte) 0x01, (byte) 0x04, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		try {
			reader.readInt();
		} catch (IOException expected) {
			assertThat(expected.getMessage(), containsString("Expected DER Integer"));
		}
	}

	@Test
	public void readInt_InvalidLength() {
		byte[] vector = new byte[] {
				(byte) 0x02, (byte) 0x80, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		try {
			reader.readInt();
		} catch (IOException expected) {
			assertThat(expected.getMessage(), containsString("Illegal len"));
		}
	}

	@Test
	public void readInt_ShortArray() {
		byte[] vector = new byte[] {
				(byte) 0x02, (byte) 0x02, (byte) 0xFF
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		try {
			reader.readInt();
		} catch (IOException expected) {
		}
	}

	@Test
	public void readOid_InvalidLength() {
		byte[] vector = new byte[]{
				(byte) 0x02, (byte) 0x80, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		try {
			reader.readOid();
		} catch (IOException expected) {
		}
	}

	@Test
	public void readOid_TooShort() {
		byte[] vector = new byte[]{
				(byte) 0x02, (byte) 0x00
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		try {
			reader.readOid();
		} catch (IOException expected) {
		}
	}

	@Test
	public void readOid_NotOidValue() {
		byte[] vector = new byte[]{
				(byte) 0x02, (byte) 0x04, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		try {
			reader.readOid();
		} catch (IOException expected) {
		}
	}

	@Test
	public void readOid_Valid1() throws Exception {
		byte[] vector = new byte[]{
				(byte) 0x06, (byte) 0x01, (byte) 0x28
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		assertEquals("1.0", reader.readOid());
	}

	@Test
	public void readOid_Valid1Prefix() throws Exception {
		byte[] vector = new byte[]{
				(byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x01, (byte) 0x0b
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		assertEquals("1.2.840.113549.1.1.11", reader.readOid());
	}

	@Test
	public void readOid_Valid0Prefix() throws Exception {
		byte[] vector = new byte[]{
				(byte) 0x06, (byte) 0x0A, (byte) 0x09, (byte) 0x92, (byte) 0x26, (byte) 0x89, (byte) 0x93, (byte) 0xF2, (byte) 0x2C, (byte) 0x64, (byte) 0x04, (byte) 0x0D
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		assertEquals("0.9.2342.19200300.100.4.13", reader.readOid());
	}

	@Test
	public void readOid_Valid2Prefix() throws Exception {
		byte[] vector = new byte[]{
				(byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1D, (byte) 0x0E
		};
		SimpleDERReader reader = new SimpleDERReader(vector);
		assertEquals("2.5.29.14", reader.readOid());
	}
}