import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class FileDigest {

	public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java FileDigest <filename>");
            System.exit(1);
        }

        String fileName = args[0];
        byte[] myBuffer;
        int bR;
        byte[] myDigest;
        String myEncodedDigest;
        try (FileInputStream fistream = new FileInputStream(fileName)) {
            HandshakeDigest myHandshakeDigest = new HandshakeDigest();
            myBuffer = new byte[1024];
            

            while ((bR = fistream.read(myBuffer)) != -1) {
                myHandshakeDigest.update(myBuffer, 0, bR);
            }

            myDigest = myHandshakeDigest.digest();
            myEncodedDigest = Base64.getEncoder().encodeToString(myDigest);

            System.out.println(myEncodedDigest);
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
