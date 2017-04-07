package com.trilead.ssh2.packets;

/**
 * PacketKexDHInitNew.
 */
public class PacketKexDHInitNew
{
	byte[] payload;

	byte[] publicKey;

	public PacketKexDHInitNew(byte[] publicKey)
	{
		this.publicKey = publicKey;
	}

	public byte[] getPayload()
	{
		if (payload == null)
		{
			TypesWriter tw = new TypesWriter();
			tw.writeByte(Packets.SSH_MSG_KEXDH_INIT);
			tw.writeString(publicKey, 0, publicKey.length);
			payload = tw.getBytes();
		}
		return payload;
	}
}
