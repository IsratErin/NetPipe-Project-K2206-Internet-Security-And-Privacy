import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;


import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class ClientHandshake {

    

    public static  HandshakeMessage SERVERHELLO;

   
    public static HandshakeMessage SESSION;
    public static HandshakeMessage CLIENTHELLO;
    public  String clientCertificate;
    public static HandshakeMessage CLIENTFINISHED;
    public static  HandshakeMessage SERVERFINISHED;
    
    public static byte[] sessionKeyinBytes;
    public static  byte[] sessionIVinBytes;
        
    
   
    public static void ClientHello(Socket socket, String clientcert) throws FileNotFoundException, CertificateException, CertificateEncodingException, IOException, GeneralSecurityException {
    	
    	
    	CLIENTHELLO = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        
        /* Read user certificate from file and create HandshakeCertificate */
		FileInputStream i = null;
		i = new FileInputStream(clientcert);
		
        HandshakeCertificate handshakeCertificate = new HandshakeCertificate(i);
        
        /* Extract X509 certificate and encode it as a byte array */
        X509Certificate cert = handshakeCertificate.getCertificate();
        byte[] certBytes = handshakeCertificate.getBytes();
        
        //byte[] certBytes = clientCertificate.getEncoded();
        String certInBase64 = java.util.Base64.getEncoder().encodeToString(certBytes);
        CLIENTHELLO.putParameter("Certificate", certInBase64) ;
        
        
        try {
        CLIENTHELLO.send(socket) ;
        
        }  catch (IOException e) {
        e.printStackTrace();
        System.err.println("Error sending ClientHello: " + e.getMessage());
        }
        
    }
    
    public  static HandshakeMessage getclientCerSer(Socket socket) throws ClassNotFoundException, IOException {
    	
    	
    	SERVERHELLO = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
    	
    	//System.out.println("Serverhello started and rceieved client certificate  in socket:::...");
    	HandshakeMessage s = HandshakeMessage.recv(socket);
    	
    	//System.out.println("s.getBytes() in ServerHello"+ Arrays.toString(s.getBytes()));
    		return s;        
       
    }
   
    public static void ServerHello(Socket socket, String serverCert, String clientcer,String caCer) throws IOException, GeneralSecurityException, ClassNotFoundException {
       
       /* Read server certificate from file and create HandshakeCertificate */
		FileInputStream i = null;
		i = new FileInputStream(serverCert);
		
       HandshakeCertificate serverCertificate = new HandshakeCertificate(i);
      
       /* Extract  server X509 certificate and encode it as a byte array */
       X509Certificate servercert = serverCertificate.getCertificate();
       byte[] servercertBytes = serverCertificate.getBytes();
       //byte[] servercertBytes1 = servercert1.getBytes();
       
       
       /* Decode the client certificate from Base64 */
       byte[] decodedClientCertBytes = java.util.Base64.getDecoder().decode(clientcer);

       /* Create a ByteArrayInputStream from the decoded client certificate */
       ByteArrayInputStream clientCertInputStream = new ByteArrayInputStream(decodedClientCertBytes);

       /* Create HandshakeCertificate from the ByteArrayInputStream */
       HandshakeCertificate clientCertificate = new HandshakeCertificate(clientCertInputStream);
       
       /* Read ca certificate from file and create HandshakeCertificate */
       FileInputStream causerinstream = null;
		causerinstream = new FileInputStream(caCer);
       HandshakeCertificate cahandshakeCertificate = new HandshakeCertificate(causerinstream);
		/* Read CA certificate from file and create HandshakeCertificate */
       
		/* Verify that user certificate is signed by CA */
       clientCertificate.verify(cahandshakeCertificate);
       
       String certBase64 = java.util.Base64.getEncoder().encodeToString(servercertBytes);
      
       SERVERHELLO.putParameter("Certificate",certBase64);
       
       // Send the ServerHello message
       SERVERHELLO.send(socket);
       //SERVERHELLO.recv(socket);
       
       //System.out.println("Server Hello got client Certificate");
      // System.out.println("Then Server Hello message Sent Succesfully");
       
        //System.out.println("Server CERTIFICATE IN BASE64"+ certBase64 );
       
       //System.out.println("Time for Next which is Serverfinished");
       
      
       
   }
    
    
    public static  String getServerCertificate(Socket socket) throws ClassNotFoundException, IOException {
    	
    	SESSION = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
    	
    	String c= HandshakeMessage.recv(socket).getParameter("Certificate");
    	
    	//System.out.println("Session started and We RETRIVED the Server CERTIFICATE in base64 ");
    	return c;        
       
    }
    
    
    
    public static void ClientVerifyServerCertificateAndSetSession(Socket socket, String serverCert, String caCert) throws IOException, GeneralSecurityException
	{
		try {
			
			
			
			 /* Decode the server certificate from Base64 */
		byte[] decodedserverCertBytes = java.util.Base64.getDecoder().decode(serverCert);

		ByteArrayInputStream serverCertInputStream = new ByteArrayInputStream(decodedserverCertBytes);

		 HandshakeCertificate handshakeServerCertificate = new HandshakeCertificate(serverCertInputStream);
		
		// Read the CA's X.509 certificate from file
       
        FileInputStream cain = new FileInputStream(caCert);
        
        HandshakeCertificate CACertificate = new HandshakeCertificate(cain);
		/* Verify that server certificate is signed by CA */
        handshakeServerCertificate.verify(CACertificate);
        SessionKey mysessionKey = new SessionKey(128);
        SessionCipher mycipher = new SessionCipher(mysessionKey);
        
        
        // byte encoded
        sessionKeyinBytes = mysessionKey.getKeyBytes();
        sessionIVinBytes = mycipher.getIVBytes();
       // System.out.println("sessionKeyinBytes:  "+ sessionKeyinBytes);
        //System.out.println("sessionIVinBytes:  "+ sessionIVinBytes);
        
        //System.out.println("Sever's Public Key::::::::::::");
        HandshakeCrypto handshakeCrypto = new HandshakeCrypto(handshakeServerCertificate); 
        
       
        byte[] thesessionkeyEncrypted = handshakeCrypto.encrypt(sessionKeyinBytes);
        byte[] thesessionIVEncrypted = handshakeCrypto.encrypt(sessionIVinBytes);
        //System.out.println("KeyENcrypted:  "+ thesessionkeyEncrypted);
        //byte to string encode
        String sessionkeyinbase64= Base64.getEncoder().encodeToString(thesessionkeyEncrypted);
        String sessionIVinbase64 = Base64.getEncoder().encodeToString(thesessionIVEncrypted);
       // System.out.println("KeyIN64:  "+ sessionkeyinbase64);
       
        //System.out.println("sessionIVinbas64:  "+ sessionIVinbase64);
        
        //SESSION.putParameter("MessageType","Session");
        SESSION.putParameter("SessionKey",sessionkeyinbase64 );
        SESSION.putParameter("SessionIV", sessionIVinbase64);
        SESSION.send(socket);
        
        
       
        //System.out.println("Session Key and IV Sent Successfully");
          
        
	} catch (IOException | GeneralSecurityException e) {
       
        e.printStackTrace();
    }
	}
    
    
    
    

    public static  void sendClientFinished(Socket socket, String clientPrivateKey, String servercert) throws GeneralSecurityException, IOException, ClassNotFoundException {
        CLIENTFINISHED = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
         
        HandshakeMessage.recv(socket);
        
        //System.out.println("ClientFinished started");        
        HandshakeDigest digest = new HandshakeDigest();
    
        HandshakeMessage e = HandshakeMessage.fromBytes(CLIENTHELLO.getBytes());
        HandshakeMessage s = HandshakeMessage.fromBytes(SESSION.getBytes());
        
         digest.update(e.getBytes());
         digest.update(s.getBytes());
         //digest.update(decodeIV);
       
        
         byte[] keybytes = Files.readAllBytes(Paths.get(clientPrivateKey));
	     HandshakeCrypto encrypter = new HandshakeCrypto(keybytes);
         
         byte[] hashdigestBytes = digest.digest();
      // Compute the Signature parameter
         byte[] signature = encrypter.encrypt(hashdigestBytes);    		
 		String signatureInBase64 = Base64.getEncoder().encodeToString(signature);
 		//System.out.println("Digest in base64 in ClientFINIShed"+ signatureInBase64 );      
        		
		 StringBuilder hexString2 = new StringBuilder();
         for (byte b : hashdigestBytes) {
             hexString2.append(String.format("%02x", b));
         }

         //System.out.println("IN CLIENTFINISHED Computedclientdigesthex: " + hexString2.toString());
		
		
			String timeStamp = getCurrentTimeStamp();
			byte[] timeStampBytes = timeStamp.getBytes(StandardCharsets.UTF_8);
			byte[] encryptedTimeStamp = encrypter.encrypt(timeStampBytes);
			String timeStampBase64 = Base64.getEncoder().encodeToString(encryptedTimeStamp);

			// Set parameters in the ClientFinished message
			
			CLIENTFINISHED.putParameter("Signature", signatureInBase64);
			CLIENTFINISHED.putParameter("TimeStamp", timeStampBase64);
		
		// Send the ClientFinished message
			
           CLIENTFINISHED.send(socket);
           
           //HandshakeMessage.recv(socket);
          // System.out.println("Client Finished Sent Successfully");
    }
    private static String getCurrentTimeStamp() {
		LocalDateTime currentDateTime = LocalDateTime.now();
	    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
	    return currentDateTime.format(formatter);      
	}
    
    
    
    public static void sendServerFinished(Socket socket, String serverPrivateKey, String clientcert, byte[] data, String servercert) throws GeneralSecurityException, IOException, ClassNotFoundException {
    	//System.out.println("ServerFinished started");
        SERVERFINISHED = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);


        byte[] serverprivatekeybytes = Files.readAllBytes(Paths.get(serverPrivateKey));
        HandshakeCrypto encrypter = new HandshakeCrypto(serverprivatekeybytes);
        
        HandshakeMessage e = HandshakeMessage.fromBytes(SERVERHELLO.getBytes());
       // Include SERVERHELLO digest
       HandshakeDigest digest = new HandshakeDigest();
       
      
         //System.out.println("LENGTH:" + SERVERHELLO.getParameter("Certificate").length());
         //System.out.println("LENGTH:" + SERVERHELLO.getBytes().length);
       digest.update(e.getBytes());
        
			//System.out.println("s:  "+ s);
			// Compute the Signature parameter
         
        
	   byte[] serverdigestBytes = digest.digest();
			
			//System.out.println("serverdigestBytes lenghth: " + serverdigestBytes.length);
			
				
				byte[] serversignature = encrypter.encrypt(serverdigestBytes);
				String serversignatureBase64 = Base64.getEncoder().encodeToString(serversignature);
				
				//System.out.println("ServersentSIG:"+ serversignatureBase64);
				StringBuilder hexString1 = new StringBuilder();
				 for (byte b : serverdigestBytes) {
				     hexString1.append(String.format("%02x", b));
				 }

				 //System.out.println("serverdigestinHex: " + hexString1.toString());

				// Compute the TimeStamp parameter
				String timeStamp = getCurrentTimeStamp();
				byte[] timeStampBytes = timeStamp.getBytes(StandardCharsets.UTF_8);
				byte[] encryptedTimeStamp = encrypter.encrypt(timeStampBytes);
				String timeStampBase64 = Base64.getEncoder().encodeToString(encryptedTimeStamp);

				// Set parameters in the serverFinished message
				
				SERVERFINISHED.putParameter("Signature", serversignatureBase64);
				SERVERFINISHED.putParameter("TimeStamp", timeStampBase64);
				//System.out.println("Server signature: " + serversignatureBase64);
				//HandshakeMessage.recv(socket).getParameter("SessionKey");
			
	        // Send the serverFinished message
       SERVERFINISHED.send(socket);
      
       //System.out.println("ServerFinished Sent Successfully");
       
       
       //HandshakeMessage.recv(socket);
       //System.out.println("Server also got Client's Signature and timestamp");
    }
    
    
	 public static byte[]  clientgetsSessionKey(Socket socket) {
		 //System.out.println("Inside");
		 HandshakeMessage s = SESSION;
	    	String sessionKeyinBase64 = s.getParameter("SessionKey");
	    	//System.out.println("sessionKeyinBase64"+ sessionKeyinBase64);
	    	
	    	// string to byte decode and also it is in encrypted form
	        byte[] sessionKeyBytes = Base64.getDecoder().decode(sessionKeyinBase64);

	        return sessionKeyBytes;
	    	
	    }
	    public static byte[]  clientgetsSessionIV(Socket socket) {
	    	 HandshakeMessage s = SESSION;
		    	String sessionIVinBase64 = s.getParameter("SessionIV");
		    	//System.out.println("sessionIVinBase64");
		    	
		    	// string to byte decode and also it is in encrypted form
		        byte[] sessionIVBytes = Base64.getDecoder().decode(sessionIVinBase64);

		        return sessionIVBytes;
	    	
	    }
	    
	    
	
	
}