package com.trilead.ssh2.packets;

import com.trilead.ssh2.auth.GSSContextKrb5;

public class PacketUserauthTokenGssapiWithMic {
	
	private static final String GSSAPI_WITH_MIC = "gssapi-with-mic";
	private static final String SSH_CONNECTION = "ssh-connection";
	private String user;
	private String host;
	private byte[] payload;
	GSSContextKrb5 context = null;

	public PacketUserauthTokenGssapiWithMic(String user, String host) {
		
		this.user = user;
		this.host = host;
		
		context = new GSSContextKrb5();
		
		try 
		{
			context.create(this.host);
		} catch (Exception e) 
		{
			e.printStackTrace();
		}
		
		
		
	}

	public byte[] getTokenPayload() 
	{
		
		if (payload == null)
		{
						
			byte[] token = new byte[0];
			
			while(!context.isEstablished())
			{
				try 
				{
					token=context.init(token, 0, token.length);
					if (token.length > 1) //take the first generated token and send it to the server
						break;
				} catch (Exception e) 
				{
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			
			if(token!=null)
			{
				TypesWriter tw = new TypesWriter();
				tw.writeByte(Packets.SSH_MSG_USERAUTH_INFO_RESPONSE);
				tw.writeString(token,0,token.length);
				payload = tw.getBytes();
			}
		
		}
		return payload;
	}

	public byte[] getMicPayload(byte[] sessionIdentifier) {
		
		payload = null;
		
		TypesWriter tw = new TypesWriter();
		
		tw.writeString(sessionIdentifier, 0, sessionIdentifier.length);
		tw.writeByte(Packets.SSH_MSG_USERAUTH_REQUEST);
		tw.writeString(user);
		tw.writeString(SSH_CONNECTION);
		tw.writeString(GSSAPI_WITH_MIC);
	    
		byte[] message = tw.getBytes();
		byte[] mic;
		try 
		{
			mic = context.getMIC(message, 0, message.length);
		} catch (Exception e) 
		{
			e.printStackTrace();
			mic = null;
		}
		
		if(mic==null)
		{
			return null;
		}
				
		tw = new TypesWriter();
		tw.writeByte(Packets.SSH_MSG_USERAUTH_GSSAPI_MIC);
		tw.writeString(mic, 0, mic.length);
		
		payload = tw.getBytes();
		
		return payload;
	}

}
