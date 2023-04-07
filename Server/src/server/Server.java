package server;

import Comm.Comm;
import ServerConfig.Config;
import ServerConfig.Password;
import ServerConfig.PasswordConfig;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Objects;
import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.util.Tuple;
import packets.AuthnHello;
import packets.Packet;
import static packets.PacketType.AuthnHello;

/**
 *
 * @author Mark Case
 */
public class Server {

    private static ServerSocket server;
    private static Config config;
    private static PasswordConfig passwordConfig;
    public static ArrayList<Password> secrets = new ArrayList<>();

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws FileNotFoundException, InvalidObjectException, IOException, NoSuchAlgorithmException {
        OptionParser op = new OptionParser(args);
        LongOption[] ar = new LongOption[2];
        ar[0] = new LongOption("config", true, 'c');
        ar[1] = new LongOption("help", false, 'h');
        op.setLongOpts(ar);
        op.setOptString("hc:");
        Tuple<Character, String> opt = op.getLongOpt(false);
        if (opt == null || Objects.equals(opt.getFirst(), 'h')) {
            System.out.println("usage:\n"
                    + "authserver\n"
                    + " authserver --config <configfile>\n"
                    + " authserver --help\n"
                    + "options:\n"
                    + " -c, --config Set the config file.\n"
                    + " -h, --help Display the help.");
            System.exit(0);
        } else if (Objects.equals(opt.getFirst(), 'c')) {
            // Initialize config
            config = new Config(opt.getSecond());
            // Initialize the Secrets config from the path "secrets_file" of config.
            System.out.println(config.getPassword_file());
            passwordConfig = new PasswordConfig(config.getPassword_file());
        }

        try {
            // Initializie the server with the config port
            server = new ServerSocket(config.getPort());
            
            System.out.println("SERVER PORT NUM: " + config.getPort());
            
            // Accept packets & communicate
            poll();

            // Close the socket when polling is completed or an error is thrown.
            server.close();

        } catch (IOException ioe) {
            ioe.printStackTrace();
            server.close();
            System.out.println("Server IOException error, closing down.");
            System.exit(0);
        } catch (NoSuchMethodException ex) {
            ex.printStackTrace();
            server.close();
            System.out.println("Server IOException error, closing down.");
            System.exit(0);
        }

    }

    private static void poll() throws IOException, NoSuchMethodException, NoSuchAlgorithmException {
        System.out.println("Server running . . . ");
        while (true) { // Consistently accept connections

            // Establish the connection & read the message
            Socket peer = server.accept();

            // Determine the packet type.
            System.out.println("Waiting for a packet...");
            final Packet packet = Comm.read(peer);

            System.out.println("Packet Recieved: [" + packet.getType().name() + "]");
            
            

            // Switch statement only goes over packets expected by the KDC, any other packet will be ignored.
            switch (packet.getType()) {

                case AuthnHello: {
                    // Check if the user exists in the secretes && send a challenge back.
                    AuthnHello AuthnHello_packet = (AuthnHello) packet;
                    System.out.println("PACKET UNAME: " + AuthnHello_packet);
                    System.out.println("Entries UNAME: " + secrets);
                    if (secrets.stream().anyMatch(n -> n.getUser().equalsIgnoreCase(AuthnHello_packet.getuName()))) {

                        System.out.println("Authn_packet received, here is the username: " + AuthnHello_packet.getuName());

                        // Create the packet and send
//                        CHAPChallenge chapChallenge_packet = new CHAPChallenge(nonce);
//                        Communication.send(peer, chapChallenge_packet);
                    }
                }; break;
            }
        }
    }

}
