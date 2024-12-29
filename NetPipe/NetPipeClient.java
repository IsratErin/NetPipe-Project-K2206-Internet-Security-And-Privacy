import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherOutputStream;

import java.io.*;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;
    static SessionCipher cipher;
    
    public static String clientcert;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        //
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
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        //
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
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) {
        Socket socket = null;

        parseArgs(args);
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        try {
            socket = new Socket(host, port);
            //System.out.println("Connected to the server");
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }
        
        //
        
        try{
            String usercert = arguments.get("usercert");
            String cacert = arguments.get("cacert");
            String key = arguments.get("key");
 	
            ClientHandshake.ClientHello(socket, usercert); 
            String servercert= ClientHandshake.getServerCertificate(socket);//in bas64 form
           
            ClientHandshake.ClientVerifyServerCertificateAndSetSession(socket,servercert,cacert);
            //String skeyy= HandshakeMessage.recv(socket).getParameter("SessionKey");
            
            //HandshakeMessage s = HandshakeMessage.
            
            ClientHandshake.sendClientFinished(socket,key,servercert);
           // System.out.println("Everything finished");
            //HandshakeMessage receivedMessage = HandshakeMessage.recv(socket); //***Don't know if correct
           
            
            
            
            
            
           byte [] sskeyy = ClientHandshake.sessionKeyinBytes;
           byte [] siv = ClientHandshake.sessionIVinBytes;
            
            
            
            //System.out.println("Session Key: "+ sskeyy);
           // System.out.println("Session IV: "+ siv);
           
          
            
            
            SessionKey keyy = new SessionKey(sskeyy);
            cipher = new SessionCipher(keyy, siv);
            // SessionCipher cipher = new SessionCipher(keyy, decryptedsessionIVBytes);
             //System.out.println("Cipher"+cipher);
            
           // InputStream socketInDecrypt = cipher.openDecryptedInputStream(socket.getInputStream());
            
            
             
            
        }catch (IOException ex){
            System.out.println("Client Hello Error\n");
            System.exit(1);
        } catch (CertificateException e) {
            System.out.println("Server Hello Error\n");
            System.exit(1);
        } catch (Exception e) {
            System.out.println("Session Setup Error\n");
            System.exit(1);
        }
        
        try {
        	InputStream socketInDecrypt = cipher.openDecryptedInputStream(socket.getInputStream());
            OutputStream socketOutEncrypt = cipher.openEncryptedOutputStream(socket.getOutputStream());

            Forwarder.forwardStreams(System.in, System.out, socketInDecrypt, socketOutEncrypt, socket);
        	
            //Forwarder.forwardStreams(System.in, System.out, socket.getInputStream(), socket.getOutputStream(), socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }
    public static String getClientCertificate() {
    	return arguments.get("usercert");
    }

}