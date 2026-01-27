package com.trilead.ssh2;

import com.trilead.ssh2.channel.ConnectionRule;
import com.trilead.ssh2.jenkins.SFTPClient;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.NullInputStream;
import org.junit.Rule;
import org.junit.Test;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Random;

import static org.junit.Assert.*;

public class SFTPClientTest {
    public static final String TMP_TEST = "/tmp/test";
    public static final String PATH_FILE = TMP_TEST + "/file";
    public static final String PATH_FILE2 = TMP_TEST + "/file2";
    public static final int POSIX_PERMISSION = 0700;
    public static final String FILE_CONTENT = "test";
    public static final int sftpPacketSize = 32 * 1024; // 32 KiB
    public static final int largeBufferSize = 128 * 1024; // 128 KiB

    @Rule
    public ConnectionRule con = new ConnectionRule();

    @Test
    public void connectionTest() throws Exception {
        SFTPClient sftpClient = new SFTPClient(con.getConnection());
        sftpClient.mkdirs(TMP_TEST, POSIX_PERMISSION);

        OutputStream out = sftpClient.writeToFile(PATH_FILE);
        assertNotNull(out);
        IOUtils.write(FILE_CONTENT, out);
        out.close();

        InputStream in = sftpClient.read(PATH_FILE);
        assertNotNull(in);
        assertNotNull(IOUtils.readLines(in));
        in.close();

        sftpClient.chmod(PATH_FILE, POSIX_PERMISSION);
        assertTrue(sftpClient.exists(PATH_FILE));
        sftpClient.close();
    }

    @Test
    public void sizeLimitsTest() throws Exception {
        SFTPClient sftpClient = new SFTPClient(con.getConnection());
        sftpClient.mkdirs(TMP_TEST, POSIX_PERMISSION);
        String path = TMP_TEST + "/largefile";

        byte[] emptyBuffer = new byte[0];
        byte[] largeBuffer = new byte[largeBufferSize];
        // Use deterministic content, not just zeros
        new Random(1234L).nextBytes(largeBuffer);

        try (OutputStream out = sftpClient.writeToFile(path)) {
            assertNotNull("OutputStream must not be null", out);
            // Zero-length writes must be no-ops
            out.write(emptyBuffer);
            out.write(largeBuffer, 0, 0);
            // Write exactly one packet
            out.write(largeBuffer, 0, sftpPacketSize);
            // Write the remainder (crossing packet boundaries)
            out.write(largeBuffer, sftpPacketSize, largeBufferSize - sftpPacketSize);
            // Zero-length write at end of file must also be a no-op
            out.write(largeBuffer, largeBufferSize, 0);
        }

        try (InputStream in = sftpClient.read(path)) {
            assertNotNull("InputStream must not be null", in);
            byte[] readBuffer = new byte[largeBufferSize];
            // Zero-length read must return 0 and not touch the buffer
            assertEquals("Zero-length read must return 0",
                    0, in.read(readBuffer, 0, 0));
            // Read up to the packet boundary
            IOUtils.readFully(in, readBuffer, 0, sftpPacketSize);
            // Read the remainder
            IOUtils.readFully(in, readBuffer, sftpPacketSize, largeBufferSize - sftpPacketSize);
            // Zero-length read with offset at buffer end is still valid
            assertEquals("Zero-length read must return 0",
                    0, in.read(readBuffer, largeBufferSize, 0));
            // Now we must be at EOF
            assertEquals("Stream must be at EOF", -1, in.read());
            // Verify round-trip content
            assertArrayEquals("Data written and read back via SFTP must match",
                    largeBuffer, readBuffer);
        }
    }

    @Test
    public void writePipelineTest() throws Exception {
        SFTPClient sftpClient = new SFTPClient(con.getConnection());
        sftpClient.mkdirs(TMP_TEST, POSIX_PERMISSION);

        final byte[] buf = new byte[largeBufferSize];
        buf[0] = 1;
        buf[sftpPacketSize] = 2; //in second packet
        buf[largeBufferSize - 1] = 3; //last byte

        SFTPv3FileHandle destinationFile = sftpClient.openFile(PATH_FILE2, 0x00000018 | 0x00000002,
                null); // SSH_FXF_CREAT | SSH_FXF_TRUNC | SSH_FXF_WRITE

        //file is 4 packets but pipeline only 3
        sftpClient.writePipelined(destinationFile, 0, buf, 0, largeBufferSize, 3);
        sftpClient.closeFile(destinationFile);

        byte[] readBuffer = new byte[largeBufferSize];
        try (InputStream in = sftpClient.read(PATH_FILE2)) {
            IOUtils.readFully(in, readBuffer);
        }

        assertEquals("First byte must be 1", 1, readBuffer[0]);
        assertEquals("Byte at packet boundary must be 2", 2, readBuffer[sftpPacketSize]);
        assertEquals("Last byte must be 3", 3, readBuffer[largeBufferSize - 1]);

        sftpClient.close();
    }

}
