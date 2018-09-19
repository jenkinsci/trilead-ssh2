package com.trilead.ssh2;

import com.trilead.ssh2.channel.ConnectionRule;
import com.trilead.ssh2.jenkins.SFTPClient;
import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.containers.GenericContainer;

import java.io.InputStream;
import java.io.OutputStream;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class SFTPClientTest {
    public static final String TMP_TEST = "/tmp/test";
    public static final String PATH_FILE = TMP_TEST + "/file";
    public static final int POSIX_PERMISSION = 0700;
    public static final String FILE_CONTENT = "test";

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
}
