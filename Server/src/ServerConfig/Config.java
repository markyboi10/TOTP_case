package ServerConfig;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InvalidObjectException;
import merrimackutil.json.JSONSerializable;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

/**
 *
 * @author Mark Case
 */
public class Config implements JSONSerializable {

    private String path;
    
    private String password_file;
    private String keyStore_file;
    private String keystore_pass;
    private int port;

    public Config(String path) throws FileNotFoundException, InvalidObjectException {
        this.path = path;

        // Construct file
        File file = new File(path);

        if (file == null || !file.exists()) {
            throw new FileNotFoundException("File from path for Config does not point to a vadlid configuration json file.");
        }

        // Construct JSON Object and load configuration
        JSONObject obj = JsonIO.readObject(file);
        deserialize(obj);
    }

    @Override
    public String serialize() {
        return toJSONType().getFormattedJSON();// We should never be serializing the JSON.
    }

    @Override
    public void deserialize(JSONType type) throws InvalidObjectException {

        JSONObject obj;
        if (type instanceof JSONObject) {
            obj = (JSONObject) type;
        } else {
            throw new InvalidObjectException("Expected Config Type - JsonObject. ");
        }

        if (obj.containsKey("password-file")) {
            this.password_file = obj.getString("password-file");
        } else {
            throw new InvalidObjectException("Expected an Config object -- password-file expected.");
        }

        if (obj.containsKey("port")) {
            this.port = obj.getInt("port");
        } else {
            throw new InvalidObjectException("Expected an Config object -- port expected.");
        }

        if (obj.containsKey("keystore-pass")) {
            this.keystore_pass = obj.getString("keystore-pass");
        } else {
            throw new InvalidObjectException("Expected an Config object -- keystore-pass expected.");
        }

        if (obj.containsKey("keystore-file")) {
            this.keyStore_file = obj.getString("keystore-file");
        } else {
            throw new InvalidObjectException("Expected an Config object -- keystore-file expected.");
        }

    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("port", this.port);
        obj.put("keystore-file", this.keyStore_file);
        obj.put("keystore-pass", this.keystore_pass);
        obj.put("password-file", this.password_file);

        return obj; // We are never reading this file to JSON.
    }

    public String getPath() {
        return path;
    }

    public String getPassword_file() {
        return password_file;
    }

    public String getKeyStore_file() {
        return keyStore_file;
    }

    public String getKeystore_pass() {
        return keystore_pass;
    }

    public int getPort() {
        return port;
    }

}
