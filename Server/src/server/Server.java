package server;

import ClientSideCrypto.Scrypt;
import Comm.Comm;
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
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.codec.Base32;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.util.Tuple;
import packets.AuthnHello;
import packets.AuthnPass;
import packets.CreateChallenge;
import packets.CreateResponse;
import packets.Packet;
import static packets.PacketType.AuthnHello;
import static packets.PacketType.PassResponse;
import packets.PassResponse;
import packets.SendKey;
import packets.SendTOTP;

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
        private static final int TIME_STEP = 30; // in seconds
    private static final int TOTP_LENGTH = 6; // in digits
    private static final String HMAC_ALGORITHM = "HmacSHA1";

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

    /*
    Server loop
     */
    private static void poll() throws IOException, NoSuchMethodException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Server running . . . "); // confirm it's running
        while (true) { // Consistently accept connections

            // Establish the connection & read the message
            Socket peer = server.accept();

            // Determine the packet type
            final Packet packet = Comm.read(peer);

            System.out.println("Packet Recieved: [" + packet.getType().name() + "]");

            // Two types of packets coming in
            String create = "create";
            String authenticate = "authenticate";
            // Switch statement only goes over packets expected by the KDC, any other packet will be ignored.
            switch (packet.getType()) {

                // Case user makes contact with server
                case AuthnHello: {

                    AuthnHello AuthnHello_packet = (AuthnHello) packet;

                    // Authn
                    if (passwd.stream().anyMatch(n -> n.getUser().equalsIgnoreCase(AuthnHello_packet.getuName())) && authenticate.equalsIgnoreCase(AuthnHello_packet.getAccType())) { //user exists and type authn
                        // Confirm auth and create are seperate
                        System.out.println("Authn_packet received, here is the type: " + AuthnHello_packet.getAccType());
                        System.out.println("Authn_packet received, here is the username: " + AuthnHello_packet.getuName());
                        String createPassRequest = ("Enter your password:");
                        CreateChallenge createChallenge_packet = new CreateChallenge(createPassRequest);
                        Comm.send(peer, createChallenge_packet);                              
                    // Create
                    } else if (passwd.stream().noneMatch(n -> n.getUser().equalsIgnoreCase(AuthnHello_packet.getuName())) && create.equalsIgnoreCase(AuthnHello_packet.getAccType())) { // user doesn't exist and type create
                        // Confirm auth and create are seperate
                        System.out.println("Authn_packet received, here is the type: " + AuthnHello_packet.getAccType());
                        System.out.println("Authn_packet received, here is the username: " + AuthnHello_packet.getuName());
                        // Create the packet and send
                        String createPassRequest = ("Create your password creation:");
                        // Send out a request for user 
                        CreateChallenge createChallenge_packet = new CreateChallenge(createPassRequest);
                        Comm.send(peer, createChallenge_packet);
                    } else {
                        // If neither case matches, user either already exists or command lines have been mixed up
                        System.out.println("Incorrect input");
                        System.exit(0);
                    }
                }
                ;
                break;

                // Case, we get a response containing a password creation
                case CreateResponse: {
                    //SHA 256 hash function
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");

                    // Read in packet
                    CreateResponse createResponse_packet = (CreateResponse) packet;
                    //Extract contents
                    String clientPass = createResponse_packet.getclientPass();
                    String user = createResponse_packet.getUser();

                    loadVault(); //open our vault

                    // Byte forums of pw
                    byte[] preHashClientPassBytes = Base64.getDecoder().decode(clientPass);
                    byte[] hashedClientPassBytes = digest.digest(preHashClientPassBytes);
                    // String for of hashed pw
                    String hashedClientPassString = Base64.getEncoder().encodeToString(hashedClientPassBytes);
                    // Run scrypt
                    SecretKey key = Scrypt.genKey(hashedClientPassString, user);
                    // Convert returned key into a string form
                    String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
                    // Grab salt
                    byte[] saltBytes = Scrypt.getSalt();
                    String saltString = Base64.getEncoder().encodeToString(saltBytes);

                    // Create totp key and dervied base32 version
                    byte[] secretKey = new byte[16];
                    SecureRandom secureRandom = new SecureRandom();
                    secureRandom.nextBytes(secretKey);
                    //String totp key
                    String totpKey = Base64.getEncoder().encodeToString(secretKey);

                    // Base32 converted totp key
                    String base32Key = Base32.encodeToString(secretKey, false).replaceAll("=", "");
                    // Add to json
                    vault.addAccount("Nothing", saltString, encodedKey, totpKey, user);
                    // Update json
                    saveVault();

                    // Send off base32 key to user
                    SendKey SendKey_packet = new SendKey(base32Key);
                    Comm.send(peer, SendKey_packet);

                }
                ;
                break;
                
                case AuthnPass: {
                    //SHA 256 hash function
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    
                    boolean status = false;
                    
                    AuthnPass authnPass_packet = (AuthnPass) packet;
                    String userIs = authnPass_packet.getUser();
                    String passIs = authnPass_packet.getclientPass();
                    
                    byte[] preHashClientPassBytes = Base64.getDecoder().decode(passIs);
                    byte[] hashedClientPassBytes = digest.digest(preHashClientPassBytes);
                    // String for of hashed pw
                    String hashedClientPassString = Base64.getEncoder().encodeToString(hashedClientPassBytes);
                    // Run scrypt
                    SecretKey key = Scrypt.genKey(hashedClientPassString, userIs);
                    // Convert returned key into a string form
                    String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
                    // Grab salt
                    byte[] saltBytes = Scrypt.getSalt();
                    String saltString = Base64.getEncoder().encodeToString(saltBytes);

                    
                    if (passwd.stream().anyMatch(secret -> {
                        // byte array and combine the two like the client did when they sent their challenge response
                        String databasePass = secret.getPass();

                        System.out.println(databasePass);
                        System.out.println(encodedKey);
                        
                            // Compare the final hash with the received hash
                            System.out.println(databasePass.equalsIgnoreCase(encodedKey));
                        return databasePass.equalsIgnoreCase(encodedKey);
                    })) {
                        // If valid password, boolean is true 
                        status = true;
                        System.out.println("SUCCESS");
                        // Create the packet and send
                        PassResponse passResponse_packet = new PassResponse(status);
                        Comm.send(peer, passResponse_packet);
                    } else {
                        // If invalid password, boolean remains false
                        // Create the packet and send
                        System.out.println("FAILURE");
                        System.exit(0);

                    }
                }; break;
                
                case SendTOTP: {
                    SendTOTP sendTOTP_packet = (SendTOTP) packet;
                    String totp = sendTOTP_packet.getTotp();
                    String user = sendTOTP_packet.getUser();
                    System.out.println("RECEIVED TOTP: " + totp);
                    String totp_Key = null;
                    int totpInt = Integer.parseInt(totp);
                    for (Password pass : passwd) {
                        if (pass.getUser().equalsIgnoreCase(user)) {

                            totp_Key = pass.getTotp_key();

                            //sendSessionKey(user, sessionName, pw);
                            break;
                        }
                    }
                    
                    //String totp key
                    byte[] totpKey = Base64.getDecoder().decode(totp_Key);

                    // Base32 converted totp key
                    String base32Key = Base32.encodeToString(totpKey, false).replaceAll("=", "");
                    
                    if (verifyOTP(base32Key, totpInt)) {
                        System.out.println("TOTP VERIFICATION SUCCESSFULL");
                    } else {
                        System.out.println("TOTP VERIFICATION FAILED");
                    }
                    
                    
                    
                }; break;
            
            }
        }
    }

    // Updates vault
    public static void saveVault() {
        try {
            JsonIO.writeSerializedObject(vault, new File("Config\\passwd.json"));
        } catch (FileNotFoundException ex) {
            System.out.println("Could not save vault to disk.");
            System.out.println(ex);
        }
    }

    // Loads vault
    public static void loadVault() throws InvalidObjectException {
        JSONObject obj = null;
        File vaultFile = new File("Config\\passwd.json");
        String pass = "";
        // If there is no vault create one.
        if (!vaultFile.exists()) {
            vault = new Vault(pass, obj);
            return;
        }

        try {
            obj = JsonIO.readObject(vaultFile);
            vault = new Vault("", obj);
        } catch (FileNotFoundException ex) {
            System.out.println("Could not access the vault file.");
            System.exit(1);
        } catch (InvalidObjectException ex) {
            System.out.println(ex);
            System.exit(1);
        }
    }
    private static byte[] generateTOTP(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static int truncateHash(byte[] hash) {
        int offset = hash[hash.length - 1] & 0xf;
        return ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

    }

    
    public static boolean verifyOTP(String base32Key, int otp) {
        byte[] key = Base32.decode(base32Key); // convert the base32 key to bytes
        long time = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis()) / TIME_STEP; // current time in time step units
        byte[] data = ByteBuffer.allocate(8).putLong(time).array(); // convert the time to 8-byte array
        byte[] hash = generateTOTP(key, data); // generate the TOTP hash
        int expectedOTP = truncateHash(hash) % (int) Math.pow(10, TOTP_LENGTH); // truncate the hash and convert to a 6-digit number
        System.out.println(expectedOTP);
        
        return expectedOTP == otp; // compare with the entered OTP
    }
    
} // end class
