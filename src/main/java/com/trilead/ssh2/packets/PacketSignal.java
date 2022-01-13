package com.trilead.ssh2.packets;

import java.util.HashMap;
import java.util.Map;

/**
 * Delivers a signal from client to server.
 *
 * See section 6.9 of RFC 4254.
 *
 * @author Kohsuke Kawaguchi
 */
public class PacketSignal {
    byte[] payload;

   	public int recipientChannelID;
   	public String signalName;

   	public PacketSignal(int recipientChannelID, String signalName) {
   		this.recipientChannelID = recipientChannelID;

        if (signalName.startsWith("SIG"))   signalName=signalName.substring(3);
        this.signalName = signalName;
   	}

   	public byte[] getPayload()
   	{
   		if (payload == null)
   		{
   			TypesWriter tw = new TypesWriter();
   			tw.writeByte(Packets.SSH_MSG_CHANNEL_REQUEST);
   			tw.writeUINT32(recipientChannelID);
   			tw.writeString("signal");
            tw.writeBoolean(false);
   			tw.writeString(signalName);

   			payload = tw.getBytes();
   		}
   		return payload;
   	}

    private static final Map<Integer,String> SIGNALS = new HashMap<Integer, String>();

    public static String strsignal(int i) {
        return SIGNALS.get(i);
    }

    static {
        SIGNALS.put(14,"ALRM");
        SIGNALS.put( 1,"HUP");
        SIGNALS.put( 2,"INT");
        SIGNALS.put( 9,"KILL");
        SIGNALS.put(13,"PIPE");
        SIGNALS.put(15,"TERM");
        SIGNALS.put( 6,"ABRT");
        SIGNALS.put( 8,"FPE");
        SIGNALS.put( 4,"ILL");
        SIGNALS.put( 3,"QUIT");
        SIGNALS.put(11,"SEGV");
        SIGNALS.put( 5,"TRAP");
    }
}
