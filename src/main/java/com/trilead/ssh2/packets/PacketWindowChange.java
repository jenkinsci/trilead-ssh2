package com.trilead.ssh2.packets;

/**
 * Indicates that that size of the terminal (window) size has changed on the client side.
 *
 * See section 6.7 of RFC 4254.
 *
 * @author Kohsuke Kawaguchi
 */
public class PacketWindowChange {
    byte[] payload;

   	public int recipientChannelID;
   	public int character_width;
   	public int character_height;
   	public int pixel_width;
   	public int pixel_height;

   	public PacketWindowChange(int recipientChannelID,
                              int character_width, int character_height, int pixel_width, int pixel_height)
   	{
   		this.recipientChannelID = recipientChannelID;
   		this.character_width = character_width;
   		this.character_height = character_height;
   		this.pixel_width = pixel_width;
   		this.pixel_height = pixel_height;
   	}

   	public byte[] getPayload()
   	{
   		if (payload == null)
   		{
   			TypesWriter tw = new TypesWriter();
   			tw.writeByte(Packets.SSH_MSG_CHANNEL_REQUEST);
   			tw.writeUINT32(recipientChannelID);
   			tw.writeString("window-change");
            tw.writeBoolean(false);
   			tw.writeUINT32(character_width);
   			tw.writeUINT32(character_height);
   			tw.writeUINT32(pixel_width);
   			tw.writeUINT32(pixel_height);

   			payload = tw.getBytes();
   		}
   		return payload;
   	}
}
