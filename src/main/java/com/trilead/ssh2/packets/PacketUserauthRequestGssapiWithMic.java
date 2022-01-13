package com.trilead.ssh2.packets;

public class PacketUserauthRequestGssapiWithMic {

	private static final String GSSAPI_WITH_MIC = "gssapi-with-mic";

	private static final String SSH_CONNECTION = "ssh-connection";

	byte[][] supported_oid={
		    // OID 1.2.840.113554.1.2.2 in DER
		    {(byte)0x6,(byte)0x9,(byte)0x2a,(byte)0x86,(byte)0x48,
		     (byte)0x86,(byte)0xf7,(byte)0x12,(byte)0x1,(byte)0x2,
		     (byte)0x2}
		  };
	
	byte[] payload;

	private String user;

	public PacketUserauthRequestGssapiWithMic(String user)
	{
		this.user = user;
	}

	public byte[] getPayload()
	{
		if (payload == null)
		{
			TypesWriter tw = new TypesWriter();
			tw.writeByte(Packets.SSH_MSG_USERAUTH_REQUEST);
			tw.writeString(user);
			tw.writeString(SSH_CONNECTION);
			tw.writeString(GSSAPI_WITH_MIC);
			tw.writeUINT32(supported_oid.length);
			for(int i=0; i<supported_oid.length; i++)
				tw.writeString(supported_oid[i], 0, supported_oid[i].length);

			payload = tw.getBytes();
		}
		return payload;
	}
}
