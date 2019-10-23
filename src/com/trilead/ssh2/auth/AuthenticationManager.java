package com.trilead.ssh2.auth;

import com.trilead.ssh2.InteractiveCallback;
import com.trilead.ssh2.crypto.PEMDecoder;
import com.trilead.ssh2.packets.*;
import com.trilead.ssh2.signature.KeyAlgorithm;
import com.trilead.ssh2.signature.KeyAlgorithmManager;
import com.trilead.ssh2.transport.MessageHandler;
import com.trilead.ssh2.transport.TransportManager;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Vector;
import java.util.concurrent.TimeUnit;

import org.ietf.jgss.GSSContext;


/**
 * AuthenticationManager.
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: AuthenticationManager.java,v 1.1 2007/10/15 12:49:57 cplattne Exp $
 */
public class AuthenticationManager implements MessageHandler
{
	public static final String PROPERTY_TIMEOUT = AuthenticationManager.class.getName() + ".timeout";
	public static final long TIMEOUT = Long.valueOf(System.getProperty(PROPERTY_TIMEOUT,"120000"));
	TransportManager tm;

	Vector packets = new Vector();
	boolean connectionClosed = false;

	String banner;

	String[] remainingMethods = new String[0];
	boolean isPartialSuccess = false;

	boolean authenticated = false;
	boolean initDone = false;

	public AuthenticationManager(TransportManager tm)
	{
		this.tm = tm;
	}

	boolean methodPossible(String methName)
	{
		if (remainingMethods == null)
			return false;

		for (String remainingMethod : remainingMethods) {
			if (remainingMethod.compareTo(methName) == 0)
				return true;
		}
		return false;
	}

	byte[] deQueue() throws IOException
	{
		synchronized (packets)
		{
			long waitUntil = System.currentTimeMillis() + TIMEOUT;
			long now = System.currentTimeMillis();

			while (packets.size() == 0 && now < waitUntil)
			{
				if (connectionClosed)
					throw new IOException("The connection is closed.", tm.getReasonClosedCause());

				try
				{
					packets.wait(TIMEOUT);
				}
				catch (InterruptedException ign)
				{
                    throw new InterruptedIOException(ign.getMessage());
				}
				now = System.currentTimeMillis();
			}
			
			if(packets.size()==0){
				throw new IOException("No valid packets after " + TIMEOUT + " milliseconds, " +
						"you can increase the timeout by setting the property -D" + PROPERTY_TIMEOUT + "=<MILLISECONDS>");
			}
			/* This sequence works with J2ME */
			byte[] res = (byte[]) packets.firstElement();
			packets.removeElementAt(0);
			return res;
		}
	}

	byte[] getNextMessage() throws IOException
	{
		while (true)
		{
			byte[] msg = deQueue();

			if (msg[0] != Packets.SSH_MSG_USERAUTH_BANNER)
				return msg;

			PacketUserauthBanner sb = new PacketUserauthBanner(msg, 0, msg.length);

			banner = sb.getBanner();
		}
	}

	public String[] getRemainingMethods(String user) throws IOException
	{
		initialize(user);
		return remainingMethods;
	}

	public boolean getPartialSuccess()
	{
		return isPartialSuccess;
	}

	private boolean initialize(String user) throws IOException
	{
		if (!initDone)
		{
			tm.registerMessageHandler(this, 0, 255);

			PacketServiceRequest sr = new PacketServiceRequest("ssh-userauth");
			tm.sendMessage(sr.getPayload());

			PacketUserauthRequestNone urn = new PacketUserauthRequestNone("ssh-connection", user);
			tm.sendMessage(urn.getPayload());

			byte[] msg = getNextMessage();
			new PacketServiceAccept(msg, 0, msg.length);
			msg = getNextMessage();

			initDone = true;

			if (msg[0] == Packets.SSH_MSG_USERAUTH_SUCCESS)
			{
				authenticated = true;
				tm.removeMessageHandler(this, 0, 255);
				return true;
			}

			if (msg[0] == Packets.SSH_MSG_USERAUTH_FAILURE)
			{
				PacketUserauthFailure puf = new PacketUserauthFailure(msg, 0, msg.length);

				remainingMethods = puf.getAuthThatCanContinue();
				isPartialSuccess = puf.isPartialSuccess();
				return false;
			}

			throw new IOException("Unexpected SSH message (type " + msg[0] + ")");
		}
		return authenticated;
	}

	public boolean authenticateGssapiWithMic(String user, String host) throws IOException
	{
		
		//packet exchange based on: http://www.openssh.com/txt/rfc4462.txt
		initialize(user);
		
		PacketUserauthRequestGssapiWithMic ua = new PacketUserauthRequestGssapiWithMic(user);	
		tm.sendMessage(ua.getPayload());
		
		byte[] message = getNextMessage();
		
		if(message[0]==Packets.SSH_MSG_USERAUTH_FAILURE )
		{
			return false;
		}
		
		if(message[0] == Packets.SSH_MSG_USERAUTH_INFO_REQUEST)
		{
			//	The server responds to the SSH_MSG_USERAUTH_REQUEST with either an
			//	SSH_MSG_USERAUTH_FAILURE if none of the mechanisms(OIDs) are supported or
			//	with an SSH_MSG_USERAUTH_GSSAPI_RESPONSE with the select OID
			//	Since we are sending only one OID, there is no need to check which OID the 
			//	server selected
			
			PacketUserauthTokenGssapiWithMic uat = new PacketUserauthTokenGssapiWithMic(user,host);			
			tm.sendMessage(uat.getTokenPayload());			
			message = getNextMessage();
			
			if(message[0]==Packets.SSH_MSG_USERAUTH_INFO_RESPONSE)
			{
				
				tm.sendMessage(uat.getMicPayload(tm.getSessionIdentifier()));			
				message = getNextMessage();
				
				if(message[0]==Packets.SSH_MSG_USERAUTH_SUCCESS)
				{
					authenticated = true;
					tm.removeMessageHandler(this, 0, 255);
					return true;
			    }
				else if(message[0]==Packets.SSH_MSG_USERAUTH_FAILURE)
				{
					PacketUserauthFailure puf = new PacketUserauthFailure(message,0,message.length);
					remainingMethods = puf.getAuthThatCanContinue();
					isPartialSuccess = puf.isPartialSuccess();
					return false;					
				}
			}
			
		}
		
		throw new IOException("Unexpected SSH message (type " + message[0] + ")");
	}
	
	public boolean authenticatePublicKey(String user, AgentProxy proxy) throws IOException {
		initialize(user);

		boolean success;
		for (AgentIdentity identity : (Collection<AgentIdentity>) proxy.getIdentities()) {
			success = authenticatePublicKey(user, proxy, identity);
			if (success) {
				return true;
			}
		}
		return false;
	}

	boolean authenticatePublicKey(String user, AgentProxy proxy, AgentIdentity identity) throws IOException {

		if (!methodPossible("publickey"))
			throw new IOException("Authentication method publickey not supported by the server at this stage.");

		byte[] pubKeyBlob = identity.getPublicKeyBlob();
		if(pubKeyBlob == null) {
			return false;
		}

		TypesWriter tw = new TypesWriter();
		byte[] H = tm.getSessionIdentifier();

		tw.writeString(H, 0, H.length);
		tw.writeByte(Packets.SSH_MSG_USERAUTH_REQUEST);
		tw.writeString(user);
		tw.writeString("ssh-connection");
		tw.writeString("publickey");
		tw.writeBoolean(true);
		tw.writeString(identity.getAlgName());
		tw.writeString(pubKeyBlob, 0, pubKeyBlob.length);

		byte[] msg = tw.getBytes();
		byte[] response = identity.sign(msg);

		PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey(
				"ssh-connection", user, identity.getAlgName(), pubKeyBlob, response);
		tm.sendMessage(ua.getPayload());

		byte[] ar = getNextMessage();

		if (ar[0] == Packets.SSH_MSG_USERAUTH_SUCCESS)
		{
			authenticated = true;
			tm.removeMessageHandler(this, 0, 255);
			return true;
		}

		if (ar[0] == Packets.SSH_MSG_USERAUTH_FAILURE)
		{
			PacketUserauthFailure puf = new PacketUserauthFailure(ar, 0, ar.length);

			remainingMethods = puf.getAuthThatCanContinue();
			isPartialSuccess = puf.isPartialSuccess();

			return false;
		}

		throw new IOException("Unexpected SSH message (type " + ar[0] + ")");
	}


	public boolean authenticatePublicKey(String user, char[] PEMPrivateKey, String password, SecureRandom rnd)
			throws IOException
	{
		try
		{
			initialize(user);

			if (!methodPossible("publickey"))
				throw new IOException("Authentication method publickey not supported by the server at this stage.");

			KeyPair keyPair = PEMDecoder.decodeKeyPair(PEMPrivateKey, password);
			PrivateKey key = keyPair.getPrivate();

			boolean supportedKey = false;

			for (KeyAlgorithm<PublicKey, PrivateKey> algorithm : KeyAlgorithmManager.getSupportedAlgorithms()) {
				if (algorithm.supportsKey(key)) {

					byte[] encodedKey = algorithm.encodePublicKey(keyPair.getPublic());
					TypesWriter tw = new TypesWriter();

					byte[] H = tm.getSessionIdentifier();

					tw.writeString(H, 0, H.length);
					tw.writeByte(Packets.SSH_MSG_USERAUTH_REQUEST);
					tw.writeString(user);
					tw.writeString("ssh-connection");
					tw.writeString("publickey");
					tw.writeBoolean(true);
					tw.writeString(algorithm.getKeyFormat());
					tw.writeString(encodedKey, 0, encodedKey.length);

					byte[] msg = tw.getBytes();

					byte[] ds = algorithm.generateSignature(msg, keyPair.getPrivate(), rnd);

					byte[] ds_enc = algorithm.encodeSignature(ds);

					PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey("ssh-connection", user,
							algorithm.getKeyFormat(), encodedKey, ds_enc);
					tm.sendMessage(ua.getPayload());

					supportedKey = true;
					break;
				}
			}

			if (!supportedKey) {
				throw new IOException("Unknown private key type returned by the PEM decoder.");
			}

			byte[] ar = getNextMessage();

			if (ar[0] == Packets.SSH_MSG_USERAUTH_SUCCESS)
			{
				authenticated = true;
				tm.removeMessageHandler(this, 0, 255);
				return true;
			}

			if (ar[0] == Packets.SSH_MSG_USERAUTH_FAILURE)
			{
				PacketUserauthFailure puf = new PacketUserauthFailure(ar, 0, ar.length);

				remainingMethods = puf.getAuthThatCanContinue();
				isPartialSuccess = puf.isPartialSuccess();

				return false;
			}

			throw new IOException("Unexpected SSH message (type " + ar[0] + ")");

		}
		catch (IOException e)
		{
			tm.close(e, false);
			throw new IOException("Publickey authentication failed.", e);
		}
	}

	public boolean authenticateNone(String user) throws IOException
	{
		try
		{
			initialize(user);
			return authenticated;
		}
		catch (IOException e)
		{
			tm.close(e, false);
			throw new IOException("None authentication failed.", e);
		}
	}

	public boolean authenticatePassword(String user, String pass) throws IOException
	{
		try
		{
			initialize(user);

			if (!methodPossible("password"))
				throw new IOException("Authentication method password not supported by the server at this stage.");

			PacketUserauthRequestPassword ua = new PacketUserauthRequestPassword("ssh-connection", user, pass);
			tm.sendMessage(ua.getPayload());

			byte[] ar = getNextMessage();

			if (ar[0] == Packets.SSH_MSG_USERAUTH_SUCCESS)
			{
				authenticated = true;
				tm.removeMessageHandler(this, 0, 255);
				return true;
			}

			if (ar[0] == Packets.SSH_MSG_USERAUTH_FAILURE)
			{
				PacketUserauthFailure puf = new PacketUserauthFailure(ar, 0, ar.length);

				remainingMethods = puf.getAuthThatCanContinue();
				isPartialSuccess = puf.isPartialSuccess();

				return false;
			}

			throw new IOException("Unexpected SSH message (type " + ar[0] + ")");

		}
		catch (IOException e)
		{
			tm.close(e, false);
			throw new IOException("Password authentication failed.", e);
		}
	}

	public boolean authenticateInteractive(String user, String[] submethods, InteractiveCallback cb) throws IOException
	{
		try
		{
			initialize(user);

			if (!methodPossible("keyboard-interactive"))
				throw new IOException(
						"Authentication method keyboard-interactive not supported by the server at this stage.");

			if (submethods == null)
				submethods = new String[0];

			PacketUserauthRequestInteractive ua = new PacketUserauthRequestInteractive("ssh-connection", user,
					submethods);

			tm.sendMessage(ua.getPayload());

			while (true)
			{
				byte[] ar = getNextMessage();

				if (ar[0] == Packets.SSH_MSG_USERAUTH_SUCCESS)
				{
					authenticated = true;
					tm.removeMessageHandler(this, 0, 255);
					return true;
				}

				if (ar[0] == Packets.SSH_MSG_USERAUTH_FAILURE)
				{
					PacketUserauthFailure puf = new PacketUserauthFailure(ar, 0, ar.length);

					remainingMethods = puf.getAuthThatCanContinue();
					isPartialSuccess = puf.isPartialSuccess();

					return false;
				}

				if (ar[0] == Packets.SSH_MSG_USERAUTH_INFO_REQUEST)
				{
					PacketUserauthInfoRequest pui = new PacketUserauthInfoRequest(ar, 0, ar.length);

					String[] responses;

					try
					{
						responses = cb.replyToChallenge(pui.getName(), pui.getInstruction(), pui.getNumPrompts(), pui
								.getPrompt(), pui.getEcho());
					}
					catch (Exception e)
					{
						throw new IOException("Exception in callback.", e);
					}

					if (responses == null)
						throw new IOException("Your callback may not return NULL!");

					PacketUserauthInfoResponse puir = new PacketUserauthInfoResponse(responses);
					tm.sendMessage(puir.getPayload());

					continue;
				}

				throw new IOException("Unexpected SSH message (type " + ar[0] + ")");
			}
		}
		catch (IOException e)
		{
			tm.close(e, false);
			throw new IOException("Keyboard-interactive authentication failed.", e);
		}
	}

	public void handleMessage(byte[] msg, int msglen) throws IOException
	{
		synchronized (packets)
		{
            byte[] tmp = new byte[msglen];
            System.arraycopy(msg, 0, tmp, 0, msglen);
            packets.addElement(tmp);

			packets.notifyAll();

			if (packets.size() > 5)
			{
				connectionClosed = true;
				throw new IOException("Error, peer is flooding us with authentication packets.");
			}
		}
	}

    public void handleEndMessage(Throwable cause) throws IOException {
        synchronized (packets) {
            connectionClosed = true;
            packets.notifyAll();
        }
    }
}
