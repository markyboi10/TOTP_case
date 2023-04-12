
package Comm;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import packets.AuthnHello;
import packets.AuthnPass;
import packets.AuthnStatus;
import packets.CreateChallenge;
import packets.CreateResponse;
import packets.Packet;
import packets.PacketType;
import packets.PassResponse;
import packets.SendKey;
import packets.SendTOTP;


/**
 * Utility class used for sending packets across servers
 * @author Alex Elguezabal
 */
public class Comm {
    /**
     * Used to send a message to a socket {@code peer}
     * @param peer
     * @param message
     * @throws IOException 
     */
    public static void send(Socket peer, Packet message) throws IOException {
        new PrintWriter(peer.getOutputStream(), true).println(message.send());
        peer.getOutputStream().flush(); // Flush after each message
    }
    
    private static final SSLSocketFactory fac = (SSLSocketFactory)SSLSocketFactory.getDefault();
    
    /**
     * Connects to a socket and sends a packet
     * Used for client-side messaging where we are sending single message instances.
     * 
     * @param address Address of the server
     * @param port Port to connect too on the server
     * @param messgae Packet to be sent
     */
    public static SSLSocket connectAndSend(String address, int port, Packet messgae) throws IOException {
        
        // This method will only ever be called from a client
        // Set the trust store properties.
        
        // Create an SSL socket.
        SSLSocket peerSocket = null;
    
        try {
            // Set up a secure connection to the echo server running on the same machine.
            peerSocket = (SSLSocket) fac.createSocket(address, port);
            // Requires JDK 11 or higher.
            peerSocket.setEnabledProtocols(new String[]{"TLSv1.3"});

            // Start up the SSL handshake.
            peerSocket.startHandshake();
            System.out.println("Connecting to : "+address+":" + port);
        } catch (UnknownHostException ex) {
            System.out.println("Host ["+address+" "+port+"] connected could not be established.");
        } catch (IOException ioe) {
            System.out.println("Host ["+address+" "+port+"] connected could not be established.");
            ioe.printStackTrace();
        }
        
        send(peerSocket, messgae);
        return peerSocket;
    }
    
    
    /**
     * Used to reed a message from a socket {@code peer}
     * Must update the switch statement with all packet types.
     * **Note: This method is blocking, it will wait for a response before allowing the thread too continue.
     * @param peer
     * @return
     * @throws IOException
     * @throws NoSuchMethodException 
     */
    public static Packet read(Socket peer) throws IOException, NoSuchMethodException {
        BufferedReader br = new BufferedReader(new InputStreamReader(peer.getInputStream()));
        
        // Input from peer
        String line = br.readLine(); // Blocking call, will not run anything until this finished on thread.
        System.out.println(line);
        
        // Determine the type of packet.
        JSONObject object = JsonIO.readObject(line); // All packets are type JSON object with identifier "packetType"
        String identifier = object.getString("packetType");
        PacketType packetType = PacketType.getPacketTypeFromString(identifier);
       
        // Assure we have the packet type
        if(packetType == null) {
            throw new NullPointerException("No packet called ["+identifier+"] found.");
        }
       
        // Switch over all of the packet types
        // Using a switch statement to avoid reflection
        switch(packetType) {
            case AuthnHello: return new AuthnHello(line, packetType);
            case CreateChallenge: return new CreateChallenge(line, packetType);
            case CreateResponse: return new CreateResponse(line, packetType);
            case SendKey: return new SendKey(line, packetType);
            case AuthnPass: return new AuthnPass(line, packetType);
            case PassResponse: return new PassResponse(line, packetType);
            case SendTOTP: return new SendTOTP(line, packetType);
            case AuthnStatus: return new AuthnStatus(line, packetType);
            default: return null;
        }    
        
    }
    
}
