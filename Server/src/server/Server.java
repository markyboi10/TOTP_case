package server;

import ClientSideCrypto.Scrypt;
import Comm.Comm;
import ServerConfig.Account;
import ServerConfig.Config;
import ServerConfig.Password;
import ServerConfig.PasswordConfig;
import ServerConfig.Vault;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.codec.Base32;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.util.Tuple;
import packets.AuthnHello;
import packets.CreateChallenge;
import packets.CreateResponse;
import packets.Packet;
import static packets.PacketType.AuthnHello;
import packets.SendKey;

/**
 *
 * @author Mark Case
 */
public class Server {

    private static ServerSocket server;
    private static Config config;
    private static PasswordConfig passwordConfig;
    public static ArrayList<Password> passwd = new ArrayList<>();
    private static Vault vault = null;

    /**
     * @param args the command line arguments
     * @throws java.io.FileNotFoundException
     * @throws java.io.InvalidObjectException
     * @throws java.security.NoSuchAlgorithmException
     */
    public static void main(String[] args) throws FileNotFoundException, InvalidObjectException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        
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
            passwordConfig = new PasswordConfig(config.getPassword_file());
        }

        try {
            // Initializie the server with the config port
            server = new ServerSocket(config.getPort());
            
            // Accept packets & communicate
            poll();

            // Close the socket when polling is completed or an error is thrown.
            server.close();

        } catch (IOException | NoSuchMethodException ioe) {
            server.close();
            System.out.println("Server IOException error, closing down.");
            System.exit(0);
        }

    }

    private static void poll() throws IOException, NoSuchMethodException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Server running . . . ");
        while (true) { // Consistently accept connections

            // Establish the connection & read the message
            Socket peer = server.accept();

            // Determine the packet type
            final Packet packet = Comm.read(peer);

            System.out.println("Packet Recieved: [" + packet.getType().name() + "]");
            
            
            String create = "create";
            String authenticate = "authenticate";
            // Switch statement only goes over packets expected by the KDC, any other packet will be ignored.
            switch (packet.getType()) {

                case AuthnHello: {
                    
                    // Check if the user exists in the secretes, if they do, they exist there we authencticate
                    AuthnHello AuthnHello_packet = (AuthnHello) packet;
                             
                    if (passwd.stream().anyMatch(n -> n.getUser().equalsIgnoreCase(AuthnHello_packet.getuName())) && authenticate.equalsIgnoreCase(AuthnHello_packet.getAccType())) {

                        System.out.println("Authn_packet received, here is the type: " + AuthnHello_packet.getAccType());
                        System.out.println("Authn_packet received, here is the username: " + AuthnHello_packet.getuName());

                        // Create the packet and send
//                        CHAPChallenge chapChallenge_packet = new CHAPChallenge(nonce);
//                        Communication.send(peer, chapChallenge_packet);
                    } else if (passwd.stream().noneMatch(n -> n.getUser().equalsIgnoreCase(AuthnHello_packet.getuName())) && create.equalsIgnoreCase(AuthnHello_packet.getAccType())){
                        //user doesn't exist, we create
                        System.out.println("Authn_packet received, here is the type: " + AuthnHello_packet.getAccType());
                        System.out.println("Authn_packet received, here is the username: " + AuthnHello_packet.getuName());
                        // Create the packet and send
                        String createPassRequest = ("Create your password creation");
                        CreateChallenge createChallenge_packet = new CreateChallenge(createPassRequest);
                        Comm.send(peer, createChallenge_packet);
                    } else {
                        System.out.println("Incorrect input");
                        System.exit(0);
                    }
                }; break;
                
                case CreateResponse: {
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    
                    CreateResponse createResponse_packet = (CreateResponse) packet;
                    String clientPass = createResponse_packet.getclientPass();
                    String user = createResponse_packet.getUser();
                   
                    loadVault();
                    
                    System.out.println("Received client pass: " + clientPass);
                    //vault =  new Vault("C:\\Users\\Mark Case\\Documents\\NetBeansProjects\\TOTP_case\\Config\\passwd.json");
                    
                    byte[] preHashClientPassBytes = Base64.getDecoder().decode(clientPass);
                    byte[] hashedClientPassBytes = digest.digest(preHashClientPassBytes);
                    
                    String hashedClientPassString = Base64.getEncoder().encodeToString(hashedClientPassBytes);
                    SecretKey key = Scrypt.genKey(hashedClientPassString, user);
                    String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
                    byte[] saltBytes = Scrypt.getSalt();
                    String saltString = Base64.getEncoder().encodeToString(saltBytes);

                    byte[] secretKey = new byte[32];
                    SecureRandom secureRandom = new SecureRandom();
                    secureRandom.nextBytes(secretKey);

                    String totpKey = Base64.getEncoder().encodeToString(secretKey);

                    // check if addition was successful
                    String base32Key = Base32.encodeToString(secretKey, false).replaceAll("=", "");

                    System.out.println(base32Key);


                    
                    vault.addAccount("Nothing", saltString, encodedKey, totpKey, user);
                    System.out.println("Check json");
                    
                    saveVault();
                    
                    SendKey SendKey_packet = new SendKey(base32Key);
                    Comm.send(peer, SendKey_packet);

                    
                }; break;
            }
        }
    }

    public static void saveVault() {
        try {
            JsonIO.writeSerializedObject(vault, new File("Config\\passwd.json"));
        } catch (FileNotFoundException ex) {
            System.out.println("Could not save vault to disk.");
            System.out.println(ex);
        }
    }
    
      public static void loadVault() throws InvalidObjectException
  {
    JSONObject obj = null;
    File vaultFile = new File("Config\\passwd.json");
 String pass = "";
    // If there is no vault create one.
    if (!vaultFile.exists())
    {
        vault = new Vault(pass, obj);
      return;
    }

    try
    {
      obj = JsonIO.readObject(vaultFile);
      vault = new Vault("", obj);
    }
    catch (FileNotFoundException ex)
    {
      System.out.println("Could not access the vault file.");
      System.exit(1);
    }
    catch (InvalidObjectException ex)
    {
      System.out.println(ex);
      System.exit(1);
    }
  }

}
