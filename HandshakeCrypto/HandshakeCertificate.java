import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {

    private X509Certificate myCertificate;
    String c = "X.509";

    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    public HandshakeCertificate(InputStream instream) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance(c);
        this.myCertificate = (X509Certificate) certificateFactory.generateCertificate(instream);
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    public HandshakeCertificate(byte[] certbytes) throws CertificateException {
        this(new ByteArrayInputStream(certbytes));
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() throws CertificateException {
        return myCertificate.getEncoded();
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return myCertificate;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        this.myCertificate.verify(cacert.getCertificate().getPublicKey());
    }
    

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
        return myCertificate.getSubjectX500Principal().getName().split(",")[1].split("=")[1];
    }

    /*
     * return email address of subject
     */
    public String getEmail() {
    	String email = myCertificate.getSubjectX500Principal().getName().split(",")[0].split("=")[1];
        return hexStringToString(email);
    }

    public static String hexStringToString(String hex) {
        hex = hex.startsWith("#") ? hex.substring(1) : hex;
        StringBuilder sboutput = new StringBuilder();
        int ourdecimalValue;
        for (int i = 0; i < hex.length(); i += 2) {
            String p = hex.substring(i, i + 2);
            ourdecimalValue = Integer.parseInt(p, 16);
            if (ourdecimalValue != 16) {
                sboutput.append((char) ourdecimalValue);
            }
        }
        int cchar = 0;
        while (cchar < sboutput.length() && Character.isISOControl(sboutput.charAt(cchar))) {
            cchar++;
        }
        int endChar = sboutput.length() - 1;
        while (endChar >= 0 && Character.isWhitespace(sboutput.charAt(endChar))) {
            endChar--;
        }

        return sboutput.substring(cchar, endChar + 1);
    }
} 
