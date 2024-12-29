import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.io.*;

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;
    public static String clientcert;
    private static SessionCipher cipher;
    
   
   // static SessionCipher cipher;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<client certificate PEM file>");
        System.err.println(indent + "--cacert=<CA certificate PEM file>");
        System.err.println(indent + "--key=<client private key DER file>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
       
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "filename");
        arguments.setArgumentSpec("cacert", "filename");
        arguments.setArgumentSpec("key", "filename");
        

        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }
    
    /*
     * Main program.
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main( String[] args) {
    	
    	try {
        parseArgs(args);
        ServerSocket serverSocket = null;
        //System.out.println("Server strated");

        int port = Integer.parseInt(arguments.get("port"));
        try {
            serverSocket = new ServerSocket(port);
            
            //System.out.println("Listening on port");
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            ex.printStackTrace();
            System.err.println("Error in server: " + ex.getMessage());
            
            System.exit(1);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
            
           // System.out.println("Server has accepted connection");
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            ex.printStackTrace();
            System.err.println("Error in server: " + ex.getMessage());
            System.exit(1);
        }
        //
        try{
            /*
             * arguments input
             */
            String servercert = arguments.get("usercert");
            String cacert = arguments.get("cacert");
            String key = arguments.get("key");
            
             
            //System.out.println("We are in server");
            
            
            
           
            
                  HandshakeMessage m = ClientHandshake.getclientCerSer(socket);
                  clientcert= m.getParameter("Certificate");
                  
                    byte [] data = m.getBytes();
                    
                    
                  
			if (clientcert != null) {
		        //System.out.println("We got the client Certificate from CLIENTHELLO");
		        
		        //System.out.println("Client Hello was successful");
		    } else {
		        //System.err.println("Client certificate is null. Unable to proceed.");
		        System.exit(1);
		    }
			
			
            ClientHandshake.ServerHello(socket,servercert,clientcert,cacert);
           
            
            HandshakeMessage session = HandshakeMessage.recv(socket);
            
            ClientHandshake.sendServerFinished(socket, key, clientcert, data, servercert);
            
            //HandshakeMessage.recv(socket);//check also serverfinished if confuse
            
            	
            HandshakeMessage receivedMessage = HandshakeMessage.recv(socket);
            
           
            		
            		
            		
                    // Retrieve parameters from the received message
                    String param1 = session.getParameter("SessionKey");
                    String param2 = session.getParameter("SessionIV");

                    // Do something with the retrieved parameters
                   // System.out.println("SessionKEY: " + param1);
                    //System.out.println("SessionIV: " + param2);
               
                    byte[] serverprivatekeybytes = Files.readAllBytes(Paths.get(key));
                    HandshakeCrypto decrypter = new HandshakeCrypto(serverprivatekeybytes);
                
                 byte[]  byteIV =Base64.getDecoder().decode(param2);
                 byte[]  byteKey =Base64.getDecoder().decode(param1);
                 byte[] decryptedsessionIVBytes  = decrypter.decrypt(byteIV);
                 byte[] decryptedsessionKeyBytes  = decrypter.decrypt(byteKey);
                //System.out.println("Decryptor worked");
                SessionKey keyy = new SessionKey(decryptedsessionKeyBytes);
               // SessionKey keyy = new SessionKey(skey.getBytes());
                 cipher = new SessionCipher(keyy, decryptedsessionIVBytes);
               // SessionCipher cipher = new SessionCipher(keyy, decryptedsessionIVBytes);
                //System.out.println("Cipher"+cipher);
    		 
               
           
        } catch (Exception e) {
            throw new RuntimeException(e);
            
        }
                
        try {
        	
        	//System.out.println("Cipher:"+ cipher);
        	InputStream socketInDecrypt = cipher.openDecryptedInputStream(socket.getInputStream());
            OutputStream socketOutEncrypt = cipher.openEncryptedOutputStream(socket.getOutputStream());

            Forwarder.forwardStreams(System.in, System.out, socketInDecrypt, socketOutEncrypt, socket);
        	
           // Forwarder.forwardStreams(System.in, System.out, socket.getInputStream(), socket.getOutputStream(), socket);
        
         //System.out.println("Forward happened");
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
        
    	} catch (Exception e) {
    	    e.printStackTrace();
    	    System.err.println("Unexpected error in server: " + e.getMessage());
    	}
    	
    }
    
}