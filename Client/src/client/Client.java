package client;

import ClientConfig.Config;
import ClientConfig.Host;
import Comm.Comm;
import java.io.Console;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Objects;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLSocket;
import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.util.Tuple;
import packets.AuthnHello;
import packets.AuthnPass;
import packets.AuthnStatus;
import packets.CreateChallenge;
import packets.CreateResponse;
import packets.PassResponse;
import packets.SendKey;
import packets.SendTOTP;

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
                service = opt3.getSecond();
            }
        }

       // System.out.println("File "+ "Config/truststore.jks" + " exists [" + new File("ClientConfig/mytruststore.jks").exists()+"]");

        System.setProperty("javax.net.ssl.trustStore", "ClientConfig/myTruststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "dasSicheresteSchluesselUfDaeGanzeWaelt");
        // Check the service type and operate such.
        if (service.equalsIgnoreCase("authenticate")) { // KDC --> EchoService

            System.out.println("Running Auth.");
            Authn(); // Run authenticate protocol

        } else if (service.equalsIgnoreCase("create")) {
            // to do
            System.out.println("Running Create");
            Create(); // Run create protocol
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

        // MESSAGE 1: Send server request to authenticate
        AuthnHello hello = new AuthnHello(user, "authenticate"); // Construct the packet
        SSLSocket s1 = Comm.connectAndSend(host.getAddress(), host.getPort(), hello); // Send the packet

        // MESSAGE 2: Read in packet from server, extracts msg for password
        CreateChallenge createChallenge_Packet = (CreateChallenge) Comm.read(s1); // 
        String receivedcreatePassRequest = createChallenge_Packet.getcreatePassRequest();

        // MESSAGE 3: Send server p.t. password
        Console console = System.console();
        pw = new String(console.readPassword("Enter your Password: "));

        AuthnPass authnPass_packet = new AuthnPass(pw, user); //send pw and username off
        SSLSocket s2 = Comm.connectAndSend(host.getAddress(), host.getPort(), authnPass_packet);

        // MESSAGE 3: Receive status and extract outcome
        PassResponse passResp = (PassResponse) Comm.read(s2);
        Scanner scanner = new Scanner(System.in);
        String totp;
        boolean status = passResp.getMsg();
        SSLSocket s3 = null;   
        if (status) {
            // MESSAGE 3: Send server totp password
            System.out.print("Enter your TOTP: ");
            totp = scanner.nextLine();
            SendTOTP sendTOTP_packet = new SendTOTP(totp, user);
            s3 = Comm.connectAndSend(host.getAddress(), host.getPort(), sendTOTP_packet);
        } else { // If false
            System.out.println("Invalid totp config, goodbye ;) ");
            System.exit(0);
        }
        
        //MESSAGE $: Receive totp verification status
        AuthnStatus authnStatus_packet = (AuthnStatus) Comm.read(s3);
        boolean finalStatus = authnStatus_packet.getMsg();
        if (finalStatus) {
            System.out.print("Authentification was successful :)) ");
        } else {
            System.out.print("Authentification failed. . . (≖_≖ )");
        }
        return AuthnStatus;

    }

    /*
    Create new account protocol
     */
    private static boolean Create() throws IOException, NoSuchMethodException, NoSuchAlgorithmException {

        Host host = getHost("create"); //Grab host create from hosts.json
        boolean CreateStatus = false; // Status of protocol

        // MESSAGE 1: Send server request to make a new account
        AuthnHello hello = new AuthnHello(user, "create"); // Construct the packet
        SSLSocket peer1 = Comm.connectAndSend(host.getAddress(), host.getPort(), hello); // Send the packet


        // MESSAGE 2: Read in packet from server, extracts msg for password
        CreateChallenge createChallenge_Packet = (CreateChallenge) Comm.read(peer1); // 
        String receivedcreatePassRequest = createChallenge_Packet.getcreatePassRequest();
        System.out.println(receivedcreatePassRequest);

        // MESSAGE 3: Send server p.t. password
        Console console = System.console();
        pw = new String(console.readPassword("Create your Password: "));

        CreateResponse createResponse_packet = new CreateResponse(pw, user); //send pw and username off
        SSLSocket peer2 = Comm.connectAndSend(host.getAddress(), host.getPort(), createResponse_packet);

        // MESSAGE 4: Receive base32 totp key and print it out
        SendKey sendKey_Packet = (SendKey) Comm.read(peer2);
        String key = sendKey_Packet.getKey();
        System.out.println("Base32 key: " + key);

        return CreateStatus;

    }

}
