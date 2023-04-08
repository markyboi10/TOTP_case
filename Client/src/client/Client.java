package client;

import ClientConfig.Config;
import ClientConfig.Host;
import Comm.Comm;
import java.io.Console;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.json.types.JSONObject;
import merrimackutil.util.Tuple;
import packets.AuthnHello;
import packets.CreateChallenge;
import packets.CreateResponse;
import packets.SendKey;



/**
 *
 * @author Mark Case
 */
public class Client {

    public static ArrayList<Host> hosts = new ArrayList<>();
    private static Config config;
    private static String pw;
    private static String user;
    private static String service;

    public static void main(String[] args) throws NoSuchAlgorithmException, FileNotFoundException, InvalidObjectException, IOException, NoSuchMethodException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        // Initializing the CLI
        boolean shortlen = false;

        OptionParser op = new OptionParser(args);
        op.setLongAndShortOpts(new LongOption[]{
            new LongOption("hosts", true, 'h'),
            new LongOption("user", true, 'u'),
            new LongOption("service", true, 's')
        });

        // op.setLongOpts(ar);
        op.setOptString("h:u:s:");

        Tuple<Character, String> opt = op.getLongOpt(false);
        System.out.println(opt.getSecond());
        if (opt == null) {
            System.out.println("usage:\n"
                    + "   client --hosts <configfile> --user <user> --service <service>\n"
                    + "   client --user <user> --service <service>\n"
                    + "options:\n"
                    + "   -h, --hosts Set the hosts file.\n"
                    + "   -u, --user The user name.\n"
                    + "   -s, --service The name of the service");
            System.exit(0);
        } else if (Objects.equals(opt.getFirst(), 'h')) {
            config = new Config(opt.getSecond());
        } else if (Objects.equals(opt.getFirst(), 'u')) {
            // If the host is not specified then it is the local hosts.json file
            user = opt.getSecond();
            config = new Config("hosts.json");
        }

        Tuple<Character, String> opt2 = op.getLongOpt(false);
        System.out.println(opt2.getSecond());
        if (Objects.equals(opt2.getFirst(), 'u')) {
            user = opt2.getSecond();
        } else if (Objects.equals(opt2.getFirst(), 's')) {
            service = opt2.getSecond();
            shortlen = true;
        }

        if (shortlen != true) {
            Tuple<Character, String> opt3 = op.getLongOpt(false);
            System.out.println(opt3.getSecond());
            if (opt3.getSecond() != null && Objects.equals(opt3.getFirst(), 's')) {
                // Init the username and service
                System.out.println("SERVICE " + service);
                service = opt3.getSecond();
            }
        }

        // Check the service type and operate such.
        if (service.equalsIgnoreCase("authenticate")) { // KDC --> EchoService

            System.out.println("Running Auth.");
            
            Authn();
            
//            // Runs the CHAP protocol
//            // If chap returns true, run session key request
//            if (CHAP()) {
//                SessionKeyRequest();
//                Ticket toSend = SessionKeyRequest();
//                //Handshake(toSend);
//                if (Handshake(toSend)) {
//                    comm();
//                }
//                //find kdcd address
//            } else { // If chap returns false
//                System.exit(0);
//            }
        } else if (service.equalsIgnoreCase("create")) {
            // to do
            System.out.println("Running Create");
            Create();
        } else {
            System.out.println("Service not found with name [" + service + "]. Closing program ");
            System.exit(0);
        } // If we do the bonus then we add another condition here.

    }

    
    /**
     * Finds a host based off {@code host_name}
     *
     * @param host_name
     */
    private static Host getHost(String host_name) {
        return hosts.stream().filter(n -> n.getService().equalsIgnoreCase(host_name)).findFirst().orElse(null);
    }

    
        private static boolean Authn() throws IOException, NoSuchMethodException, NoSuchAlgorithmException {

        Host host = getHost("authenticate");
        boolean AuthnStatus = false;
            
        // MESSAGE 1
        AuthnHello hello = new AuthnHello(user, "authenticate"); // Construct the packet
        System.out.println("Sending hello packet");
        Socket peer1 = Comm.connectAndSend(host.getAddress(), host.getPort(), hello); // Send the packet
        
        
        
        return AuthnStatus;

        }
        
            
        private static boolean Create() throws IOException, NoSuchMethodException, NoSuchAlgorithmException {

        Host host = getHost("create");
        boolean AuthnStatus = false;
            
        // MESSAGE 1
        AuthnHello hello = new AuthnHello(user, "create"); // Construct the packet
        System.out.println("Sending hello packet");
        Socket peer1 = Comm.connectAndSend(host.getAddress(), host.getPort(), hello); // Send the packet
        
        System.out.println("reading packet");
        // MESSAGE 2
        CreateChallenge createChallenge_Packet = (CreateChallenge) Comm.read(peer1); // 
        String receivedcreatePassRequest = createChallenge_Packet.getcreatePassRequest();
        System.out.println(receivedcreatePassRequest);
        // MESSAGE 3
        // Client plain text password
        Console console = System.console();
        pw = new String(console.readPassword("Create your Password: "));

        System.out.println("The password: " + pw);
        System.out.println("Password Created");

        CreateResponse createResponse_packet = new CreateResponse(pw, user);
        Socket peer2 = Comm.connectAndSend(host.getAddress(), host.getPort(), createResponse_packet);
        SendKey sendKey_Packet = (SendKey) Comm.read(peer2); 
        String key = sendKey_Packet.getKey();
        System.out.println("Base32 key: " + key);
        
        return AuthnStatus;

        }
        


}
