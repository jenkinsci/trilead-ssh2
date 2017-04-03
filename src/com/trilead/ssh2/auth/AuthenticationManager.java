package com.trilead.ssh2.auth;

import com.trilead.ssh2.InteractiveCallback;
import com.trilead.ssh2.crypto.PEMDecoder;
import com.trilead.ssh2.packets.*;
import com.trilead.ssh2.signature.*;
import com.trilead.ssh2.transport.MessageHandler;
import com.trilead.ssh2.transport.TransportManagerNew;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Vector;


/**
 * AuthenticationManager.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: AuthenticationManager.java,v 1.1 2007/10/15 12:49:57 cplattne Exp $
 */
public class AuthenticationManager implements MessageHandler
{
	TransportManagerNew tm;

	Vector packets = new Vector();
	boolean connectionClosed = false;

	String banner;

	String[] remainingMethods = new String[0];
	boolean isPartialSuccess = false;

	boolean authenticated = false;
	boolean initDone = false;

	public AuthenticationManager(TransportManagerNew tm)
	{
		this.tm = tm;
	}

	boolean methodPossible(String methName)
	{
		if (remainingMethods == null)
			return false;

		for (int i = 0; i < remainingMethods.length; i++)
		{
			if (remainingMethods[i].compareTo(methName) == 0)
				return true;
		}
		return false;
	}

	byte[] deQueue() throws IOException
	{
		synchronized (packets)
		{
			while (packets.size() == 0)
			{
				if (connectionClosed)
					throw (IOException) new IOException("The connection is closed.").initCause(tm
							.getReasonClosedCause());

				try
				{
					packets.wait();
				}
				catch (InterruptedException ign)
				{
                    throw new InterruptedIOException();
				}
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
		if (initDone == false)
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

	public boolean authenticatePublicKey(String user, AgentProxy proxy) throws IOException {
		initialize(user);

		boolean success = false;
		Iterator agentIdentities = proxy.getIdentities().iterator();
		while(agentIdentities.hasNext()) {
			AgentIdentity identity = (AgentIdentity)agentIdentities.next();
			success = authenticatePublicKey(user, proxy, identity);
			if(success) {
				return true;
			}
		}
		return false;
	}

	boolean authenticatePublicKey(String user, AgentProxy proxy, AgentIdentity identity) throws IOException {

		if (methodPossible("publickey") == false)
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

			if (methodPossible("publickey") == false)
				throw new IOException("Authentication method publickey not supported by the server at this stage.");

			Object key = PEMDecoder.decode(PEMPrivateKey, password);

			if (key instanceof DSAPrivateKey)
			{
				DSAPrivateKey pk = (DSAPrivateKey) key;

				byte[] pk_enc = DSASHA1Verify.encodeSSHDSAPublicKey(pk.getPublicKey());

				TypesWriter tw = new TypesWriter();

				byte[] H = tm.getSessionIdentifier();

				tw.writeString(H, 0, H.length);
				tw.writeByte(Packets.SSH_MSG_USERAUTH_REQUEST);
				tw.writeString(user);
				tw.writeString("ssh-connection");
				tw.writeString("publickey");
				tw.writeBoolean(true);
				tw.writeString("ssh-dss");
				tw.writeString(pk_enc, 0, pk_enc.length);

				byte[] msg = tw.getBytes();

				DSASignature ds = DSASHA1Verify.generateSignature(msg, pk, rnd);

				byte[] ds_enc = DSASHA1Verify.encodeSSHDSASignature(ds);

				PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey("ssh-connection", user,
						"ssh-dss", pk_enc, ds_enc);
				tm.sendMessage(ua.getPayload());
			}
			else if (key instanceof RSAPrivateKey)
			{
				RSAPrivateKey pk = (RSAPrivateKey) key;

				byte[] pk_enc = RSASHA1Verify.encodeSSHRSAPublicKey(pk.getPublicKey());

				TypesWriter tw = new TypesWriter();
				{
					byte[] H = tm.getSessionIdentifier();

					tw.writeString(H, 0, H.length);
					tw.writeByte(Packets.SSH_MSG_USERAUTH_REQUEST);
					tw.writeString(user);
					tw.writeString("ssh-connection");
					tw.writeString("publickey");
					tw.writeBoolean(true);
					tw.writeString("ssh-rsa");
					tw.writeString(pk_enc, 0, pk_enc.length);
				}

				byte[] msg = tw.getBytes();

				RSASignature ds = RSASHA1Verify.generateSignature(msg, pk);

				byte[] rsa_sig_enc = RSASHA1Verify.encodeSSHRSASignature(ds);

				PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey("ssh-connection", user,
						"ssh-rsa", pk_enc, rsa_sig_enc);
				tm.sendMessage(ua.getPayload());
			}
			else
			{
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
			throw (IOException) new IOException("Publickey authentication failed.").initCause(e);
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
			throw (IOException) new IOException("None authentication failed.").initCause(e);
		}
	}

	public boolean authenticatePassword(String user, String pass) throws IOException
	{
		try
		{
			initialize(user);

			if (methodPossible("password") == false)
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
			throw (IOException) new IOException("Password authentication failed.").initCause(e);
		}
	}

	public boolean authenticateInteractive(String user, String[] submethods, InteractiveCallback cb) throws IOException
	{
		try
		{
			initialize(user);

			if (methodPossible("keyboard-interactive") == false)
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
						throw (IOException) new IOException("Exception in callback.").initCause(e);
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
			throw (IOException) new IOException("Keyboard-interactive authentication failed.").initCause(e);
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
