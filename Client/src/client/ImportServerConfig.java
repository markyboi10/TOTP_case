/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package client;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InvalidObjectException;
import merrimackutil.json.JSONSerializable;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

/**
/**
 *
 * @author Mark Case
 */
public class ImportServerConfig implements JSONSerializable {


    private String path;
    
    private String password_file;
    private String trustStore_file;
    private String trustStore_pass;
    private int port;

    public ImportServerConfig(String path) throws FileNotFoundException, InvalidObjectException {
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

        if (obj.containsKey("trustStore_file")) {
            this.trustStore_file = obj.getString("trustStore_file");
        } else {
            throw new InvalidObjectException("Expected an Config object -- trustStore_file expected.");
        }

        if (obj.containsKey("trustStore_pass")) {
            this.trustStore_pass = obj.getString("trustStore_pass");
        } else {
            throw new InvalidObjectException("Expected an Config object -- trustStore_pass expected.");
        }

    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("port", this.port);
        obj.put("trustStore_file", this.trustStore_file);
        obj.put("trustStore_pass", this.trustStore_pass);
        obj.put("password-file", this.password_file);

        return obj; // We are never reading this file to JSON.
    }

    public String getPath() {
        return path;
    }

    public String getPassword_file() {
        return password_file;
    }

    public String getTrustStore_file() {
        return trustStore_file;
    }

    public String getTrustStore_pass() {
        return trustStore_pass;
    }


    public int getPort() {
        return port;
    }

}
