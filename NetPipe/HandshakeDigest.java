import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class HandshakeDigest extends MessageDigest {

    private MessageDigest myMessageDigest;
    static String s ="SHA-256";
    
    public HandshakeDigest() throws NoSuchAlgorithmException {
    	super(s);
        this.myMessageDigest = MessageDigest.getInstance(s);
    }
    

    @Override
    protected void engineUpdate(byte input) {
        update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        myMessageDigest.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        return digest();
    }
    
    @Override
    protected void engineReset() {
        myMessageDigest.reset();
    }
    
    
    public byte[] digest() {
        return myMessageDigest.digest();
    }
    public void update(byte[] input) {
    	myMessageDigest.update(input);
    }   
    
};