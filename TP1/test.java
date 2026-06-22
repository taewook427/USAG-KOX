/*
* structure:
*   lib/bclib.jar, Bencrypt.java, Opsec.java, TP1.java, test.java
* windows:
*   javac -cp ".;lib/*" Bencrypt.java Opsec.java TP1.java test.java
*   java -cp ".;lib/*" test
* mac/linux:
*   javac -cp ".:lib/*" Bencrypt.java Opsec.java TP1.java test.java
*   java -cp ".:lib/*" test
*/
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;

public class test {
    public static void main(String[] args) {
        // 1. Helpers Test
        try {
            List<String> ips = TP1.GetIPs(false);
            for (String ip : ips) {
                System.out.println(ip);
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        System.out.println(TP1.CleanPath("<path>\\.txt"));

        // 2. Protocol Test
        CountDownLatch latch = new CountDownLatch(2); // waiting threads

        // Receive thread
        Thread recvThread = new Thread(() -> {
            TP1.TCPsocket sock = new TP1.TCPsocket();
            try {
                sock.MakeListener(8080);
                TP1 tp = new TP1(0, true, true, "secret".getBytes(), sock.Conn);
                ByteArrayOutputStream dst = new ByteArrayOutputStream();
                TP1.TP1Result res = tp.Receive(dst, null);

                if (res.Err != null) {
                    System.out.println(res.Err);
                } else {
                    System.out.println("recv success");
                    byte[] expected = new byte[1048576];
                    System.out.println(Arrays.equals(expected, dst.toByteArray()));
                    System.out.println("secret".equals(res.Smsg));

                    // peerPub is sender, myPub is receiver
                    System.out.println("from: " + Opsec.Crc32(res.FromPub) + " to: " + Opsec.Crc32(res.ToPub));
                }
            } catch (Exception e) {
                System.out.println(e.getMessage());
            } finally {
                sock.Close();
                latch.countDown();
            }
        });

        // Send thread
        Thread sendThread = new Thread(() -> {
            TP1.TCPsocket sock = new TP1.TCPsocket();
            try {
                sock.MakeConnection("127.0.0.1", 8080);
                byte[] data = new byte[1048576];
                int mode = TP1.HASH_ARG2_ST + TP1.SYM_GCM1 + TP1.ASYM_PQC1;
                TP1 tp = new TP1(mode, true, true, "secret".getBytes(), sock.Conn);
                ByteArrayInputStream src = new ByteArrayInputStream(data);
                TP1.TP1Result res = tp.Send(src, data.length, "secret", null);

                if (res.Err != null) {
                    System.out.println(res.Err);
                } else {
                    // myPub is sender, peerPub is receiver
                    System.out.println("send success");
                    System.out.println("from: " + Opsec.Crc32(res.FromPub) + " to: " + Opsec.Crc32(res.ToPub));
                }
            } catch (Exception e) {
                System.out.println(e.getMessage());
            } finally {
                sock.Close();
                latch.countDown();
            }
        });

        // start recvthread, wait 200ms then start sendthread
        recvThread.start();
        try {
            Thread.sleep(200);
        } catch (InterruptedException ignored) {
        }
        sendThread.start();
        try {
            latch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
