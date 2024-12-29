import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/*
 * Skeleton code for class SessionKey
 */
/*edited again */
class SessionKey {
	
	private SecretKey mysecretKey;
	
    /*
     * Constructor to create a secret key of a given length
     */
   
    	
	public SessionKey(Integer length) {	
		try {
            KeyGenerator mykeyGenerator = KeyGenerator.getInstance("AES");
            mykeyGenerator.init(length);
            this.mysecretKey = mykeyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace(); 
        }
    }
    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) {
    	this.mysecretKey = new SecretKeySpec(keybytes, "AES");
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return this.mysecretKey;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
    	byte[] mykeybytes = mysecretKey.getEncoded();
    	return mykeybytes;
    	
    	
        
    }
}


