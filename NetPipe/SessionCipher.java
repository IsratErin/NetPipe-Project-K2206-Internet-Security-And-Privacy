import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import javax.crypto.Cipher;

public class SessionCipher {
    private   SessionKey myKey;
    private   IvParameterSpec myiv;
    //static Cipher mycipher;
    byte[] myivBytes ;
    static String parameter = "AES/CTR/NoPadding";

    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) {
        this.myKey = key;
    	this.myiv = generateIV();

    }
   
    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes) {
        this.myKey = key;
        this.myiv = new IvParameterSpec(ivbytes);
    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        SessionKey mySessionKey = new SessionKey(myKey.getKeyBytes());
    	return mySessionKey;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return myiv.getIV();
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os) {
        try {
            Cipher mycipher = Cipher.getInstance(parameter);
            mycipher.init(Cipher.ENCRYPT_MODE, myKey.getSecretKey(), myiv);
            return new CipherOutputStream(os, mycipher);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

     CipherInputStream openDecryptedInputStream(InputStream inputstream) {
        try {
            Cipher mycipher = Cipher.getInstance(parameter);
            mycipher.init(Cipher.DECRYPT_MODE, myKey.getSecretKey(), myiv);
            return new CipherInputStream(inputstream, mycipher);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

     /*
     * Method to generate a random IV
     */
    private IvParameterSpec generateIV() {
    	SecureRandom random = new SecureRandom();
        myivBytes = random.generateSeed(16);     
        return new IvParameterSpec(myivBytes);
        
    }
}