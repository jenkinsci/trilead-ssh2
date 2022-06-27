
package com.trilead.ssh2.transport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import com.trilead.ssh2.crypto.cipher.BlockCipher;
import com.trilead.ssh2.crypto.cipher.CipherInputStream;
import com.trilead.ssh2.crypto.cipher.CipherOutputStream;
import com.trilead.ssh2.crypto.cipher.NullCipher;
import com.trilead.ssh2.crypto.digest.MessageMac;
import com.trilead.ssh2.log.Logger;
import com.trilead.ssh2.packets.Packets;


/**
 * TransportConnection.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: TransportConnection.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 */
public class TransportConnection
{
	private static final Logger log = Logger.getLogger(TransportConnection.class);

	int send_seq_number = 0;

	int recv_seq_number = 0;

	CipherInputStream cis;

	CipherOutputStream cos;

	boolean useRandomPadding = false;

	/* Depends on current MAC and CIPHER */

	MessageMac send_mac;

	byte[] send_mac_buffer;

	int send_padd_blocksize = 8;

	MessageMac recv_mac;

	byte[] recv_mac_buffer;

	byte[] recv_mac_buffer_cmp;

	int recv_padd_blocksize = 8;

	/* won't change */

	final byte[] send_padding_buffer = new byte[256];

	final byte[] send_packet_header_buffer = new byte[5];

	final byte[] recv_padding_buffer = new byte[256];

	final byte[] recv_packet_header_buffer = new byte[5];

	boolean recv_packet_header_present = false;

	ClientServerHello csh;

	final SecureRandom rnd;

	public TransportConnection(InputStream is, OutputStream os, SecureRandom rnd)
	{
		this.cis = new CipherInputStream(new NullCipher(), is);
		this.cos = new CipherOutputStream(new NullCipher(), os);
		this.rnd = rnd;
	}

	public void changeRecvCipher(BlockCipher bc, MessageMac mac)
	{
		cis.changeCipher(bc);
		recv_mac = mac;
		recv_mac_buffer = (mac != null) ? new byte[mac.size()] : null;
		recv_mac_buffer_cmp = (mac != null) ? new byte[mac.size()] : null;
		recv_padd_blocksize = bc.getBlockSize();
		if (recv_padd_blocksize < 8)
			recv_padd_blocksize = 8;
	}

	public void changeSendCipher(BlockCipher bc, MessageMac mac)
	{
		if ((bc instanceof NullCipher) == false)
		{
			/* Only use zero byte padding for the first few packets */
			useRandomPadding = true;
			/* Once we start encrypting, there is no way back */
		}

		cos.changeCipher(bc);
		send_mac = mac;
		send_mac_buffer = (mac != null) ? new byte[mac.size()] : null;
		send_padd_blocksize = bc.getBlockSize();
		if (send_padd_blocksize < 8)
			send_padd_blocksize = 8;
	}

	public void sendMessage(byte[] message) throws IOException
	{
		sendMessage(message, 0, message.length, 0);
	}

	public void sendMessage(byte[] message, int off, int len) throws IOException
	{
		sendMessage(message, off, len, 0);
	}

	public int getPacketOverheadEstimate()
	{
		// return an estimate for the paket overhead (for send operations)
		return 5 + 4 + (send_padd_blocksize - 1) + send_mac_buffer.length;
	}

	public void sendMessage(byte[] message, int off, int len, int padd) throws IOException
	{
		if (padd < 4)
			padd = 4;
		else if (padd > 64)
			padd = 64;

		boolean encryptThenMac = send_mac != null && send_mac.isEncryptThenMac();

		int packet_len = (encryptThenMac ? 1 : 5) + len + padd; /* Minimum allowed padding is 4 */

		int slack = packet_len % send_padd_blocksize;

		if (slack != 0)
		{
			packet_len += (send_padd_blocksize - slack);
		}

		if (packet_len < 16)
			packet_len = 16;

		int padd_len = packet_len - ((encryptThenMac ? 1 : 5) + len);

		if (useRandomPadding)
		{
			for (int i = 0; i < padd_len; i = i + 4)
			{
				/*
				 * don't waste calls to rnd.nextInt() (by using only 8bit of the
				 * output). just believe me: even though we may write here up to 3
				 * bytes which won't be used, there is no "buffer overflow" (i.e.,
				 * arrayindexoutofbounds). the padding buffer is big enough =) (256
				 * bytes, and that is bigger than any current cipher block size + 64).
				 */

				int r = rnd.nextInt();
				send_padding_buffer[i] = (byte) r;
				send_padding_buffer[i + 1] = (byte) (r >> 8);
				send_padding_buffer[i + 2] = (byte) (r >> 16);
				send_padding_buffer[i + 3] = (byte) (r >> 24);
			}
		}
		else
		{
			/* use zero padding for unencrypted traffic */
			for (int i = 0; i < padd_len; i++)
				send_padding_buffer[i] = 0;
			/* Actually this code is paranoid: we never filled any
			 * bytes into the padding buffer so far, therefore it should
			 * consist of zeros only.
			 */
		}

		int payloadLength = encryptThenMac ? packet_len : packet_len - 4;
		send_packet_header_buffer[0] = (byte) (packet_len >> 24);
		send_packet_header_buffer[1] = (byte) (payloadLength >> 16);
		send_packet_header_buffer[2] = (byte) (payloadLength >> 8);
		send_packet_header_buffer[3] = (byte) (payloadLength);
		send_packet_header_buffer[4] = (byte) padd_len;

		if (send_mac != null && send_mac.isEncryptThenMac()) {
			cos.writePlain(send_packet_header_buffer, 0, 4);
			cos.startRecording();
			cos.write(send_packet_header_buffer, 4, 1);
		} else {
			cos.write(send_packet_header_buffer, 0, 5);
		}
		cos.write(message, off, len);
		cos.write(send_padding_buffer, 0, padd_len);

		if (send_mac != null)
		{
			send_mac.initMac(send_seq_number);
			
			
			if (send_mac.isEncryptThenMac()) {
				send_mac.update(send_packet_header_buffer, 0, 4);
				byte[] encryptedMessage = cos.getRecordedOutput();
				send_mac.update(encryptedMessage, 0, encryptedMessage.length);
			} else {
				send_mac.update(send_packet_header_buffer, 0, 5);
				send_mac.update(message, off, len);
				send_mac.update(send_padding_buffer, 0, padd_len);
			}

			send_mac.getMac(send_mac_buffer, 0);
			cos.writePlain(send_mac_buffer, 0, send_mac_buffer.length);
		}

		cos.flush();

		if (log.isEnabled())
		{
			log.log(90, "Sent " + Packets.getMessageName(message[off] & 0xff) + " " + len + " bytes payload");
		}

		send_seq_number++;
	}

	public int peekNextMessageLength() throws IOException
	{
		if (recv_packet_header_present == false)
		{
			cis.read(recv_packet_header_buffer, 0, 5);
			recv_packet_header_present = true;
		}

		int packet_length = ((recv_packet_header_buffer[0] & 0xff) << 24)
				| ((recv_packet_header_buffer[1] & 0xff) << 16) | ((recv_packet_header_buffer[2] & 0xff) << 8)
				| ((recv_packet_header_buffer[3] & 0xff));

		int padding_length = recv_packet_header_buffer[4] & 0xff;

		if (packet_length > TransportManager.MAX_PACKET_SIZE || packet_length < 12)
			throw new IOException("Illegal packet size! (" + packet_length + ")");

		int payload_length = packet_length - padding_length - 1;

		if (payload_length < 0)
			throw new IOException("Illegal padding_length in packet from remote (" + padding_length + ")");

		return payload_length;
	}

	public int receiveMessage(byte buffer[], int off, int len) throws IOException
	{
		final int packetLength;
		final int payloadLength;
		
		if (recv_mac != null && recv_mac.isEncryptThenMac()) {
			cis.readPlain(recv_packet_header_buffer, 0, 4);
			packetLength = getPacketLength(recv_packet_header_buffer, true);

			recv_mac.initMac(recv_seq_number);
			recv_mac.update(recv_packet_header_buffer, 0, 4);

			cis.peekPlain(buffer, off, packetLength + recv_mac_buffer.length);
			System.arraycopy(buffer, off + packetLength, recv_mac_buffer, 0, recv_mac_buffer.length);

			recv_mac.update(buffer, off, packetLength);
			recv_mac.getMac(recv_mac_buffer_cmp, 0);

			checkMacMatches(recv_mac_buffer, recv_mac_buffer_cmp);

			cis.read(recv_packet_header_buffer, 4, 1);
		} else {
			cis.read(recv_packet_header_buffer, 0, 5);
			packetLength = getPacketLength(recv_packet_header_buffer, false);
		}

		int paddingLength = recv_packet_header_buffer[4] & 0xff;

		payloadLength = calculatePayloadLength(len, packetLength, paddingLength);

		cis.read(buffer, off, payloadLength);
		cis.read(recv_padding_buffer, 0, paddingLength);

		if (recv_mac != null) {
			cis.readPlain(recv_mac_buffer, 0, recv_mac_buffer.length);

			if (!recv_mac.isEncryptThenMac()) {
				recv_mac.initMac(recv_seq_number);
				recv_mac.update(recv_packet_header_buffer, 0, 5);
				recv_mac.update(buffer, off, payloadLength);
				recv_mac.update(recv_padding_buffer, 0, paddingLength);
				recv_mac.getMac(recv_mac_buffer_cmp, 0);

				checkMacMatches(recv_mac_buffer, recv_mac_buffer_cmp);
			}
		}

		recv_seq_number++;

		if (log.isEnabled())
		{
			log.log(90, "Received " + Packets.getMessageName(buffer[off] & 0xff) + " " + payloadLength
					+ " bytes payload");
		}

		return payloadLength;
	}
	
	private static int calculatePayloadLength(int bufferLength, int packetLength, int paddingLength) throws IOException {
		int payloadLength = packetLength - paddingLength - 1;

		if (payloadLength < 0)
			throw new IOException("Illegal padding_length in packet from remote (" + paddingLength + ")");

		if (payloadLength >= bufferLength)
			throw new IOException("Receive buffer too small (" + bufferLength + ", need " + payloadLength + ")");

		return payloadLength;
	}

	private static void checkMacMatches(byte[] buf1, byte[] buf2) throws IOException {
		int difference = 0;
		for (int i = 0; i < buf1.length; i++) {
			difference |= buf1[i] ^ buf2[i];
		}
		if (difference != 0)
			throw new IOException("Remote sent corrupt MAC.");
	}

	private static int getPacketLength(byte[] packetHeader, boolean isEtm) throws IOException {
		int packetLength = ((packetHeader[0] & 0xff) << 24)
						| ((packetHeader[1] & 0xff) << 16) | ((packetHeader[2] & 0xff) << 8)
						| ((packetHeader[3] & 0xff));

		if (packetLength > 35000 || packetLength < (isEtm ? 8 : 12))
			throw new IOException("Illegal packet size! (" + packetLength + ")");

		return packetLength;
	}
}
