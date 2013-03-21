import com.trilead.ssh2.Connection;
import com.trilead.ssh2.Session;
import com.trilead.ssh2.channel.ConnectionRule;

import java.util.Random;
import java.util.concurrent.TimeUnit;

/**
 * Test the throughput of the data transmission.
 *
 * @author Kohsuke Kawaguchi
 */
public class Sender {
    public static void main(String[] args) throws Exception {
        Connection connection = new ConnectionRule().getConnection();
        final Session session = connection.openSession();

        session.execCommand("cat > /dev/null");
        session.getStdout().close();
        session.getStderr().close();

        Random r = new Random();
        byte[] buf = new byte[10*1024*1024];

        while (true) {
            r.nextBytes(buf);
            long start = System.nanoTime();
            session.getStdin().write(buf);
            long end = System.nanoTime();
            System.out.println("Took "+TimeUnit.NANOSECONDS.toMillis(end-start));
        }
    }
}
