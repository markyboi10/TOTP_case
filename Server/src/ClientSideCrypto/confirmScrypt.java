/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ClientSideCrypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Mark Case
 */
public class confirmScrypt {

    /**
     * Derives the AES-128 key from the password.
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static byte[] salt = null;

    public static SecretKey genKey(String password, String salt) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        final int COST = 2048;          // A.K.A Iterations
        final int BLK_SIZE = 8;
        final int PARALLELIZATION = 1;  // Number of parallel threads to use.
        final int KEY_SIZE = 128;
        ScryptKeySpec scryptSpec;

        // Register bouncy castle provider.
        Security.addProvider(new BouncyCastleProvider());

        SecretKeyFactory factory = SecretKeyFactory.getInstance("SCRYPT");

        byte[] salt2 = Base64.getDecoder().decode(salt);
        
        scryptSpec = new ScryptKeySpec(password.toCharArray(), salt2, COST, BLK_SIZE,
                PARALLELIZATION, KEY_SIZE);

        // Generate the secrete key.
        SecretKey tmp = factory.generateSecret(
                scryptSpec);
        SecretKey key = new SecretKeySpec(tmp.getEncoded(), "AES");
        return key;
    }

    public static byte[] getSalt() {
        return salt;
    }

}