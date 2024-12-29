import java.io.IOException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;

public class HandshakeCrypto {

    private PublicKey mypublicKey;
    private PrivateKey myprivateKey;
    

    /*
     * Constructor to create an instance for encryption/decryption with a public key.
     * The public key is given as a X509 certificate.
     */
    public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
        this.mypublicKey = handshakeCertificate.getCertificate().getPublicKey();
        System.out.println("Public key:" + mypublicKey);
    }

    /*
     * Constructor to create an instance for encryption/decryption with a private key.
     * The private key is given as a byte array in PKCS#8/DER format.
     */
    public HandshakeCrypto(byte[] keyBytes) throws GeneralSecurityException, IOException { 	
    	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        this.myprivateKey= keyFactory.generatePrivate(keySpec);
        
    }

    /*
     * Decrypt byte array with the key, return result as a byte array
     */
    public byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException {
        if (myprivateKey == null) {
        	System.out.println("No Private key");      	
        	 Cipher cipher = Cipher.getInstance("RSA");
             cipher.init(Cipher.DECRYPT_MODE, mypublicKey);
             return cipher.doFinal(ciphertext);
        }else {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, myprivateKey);
        return cipher.doFinal(ciphertext);
        }
    }

    /*
     * Encrypt byte array with the key, return result as a byte array
     */
    public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException {
        if (mypublicKey == null) {
        	System.out.println("No Public key");  
        	Cipher cipher = Cipher.getInstance("RSA");
        	cipher.init(Cipher.ENCRYPT_MODE, myprivateKey);
              
        	 return cipher.doFinal(plaintext);
     
        }else {
               
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, mypublicKey);
        return cipher.doFinal(plaintext);
        }
            
    }
    
}
