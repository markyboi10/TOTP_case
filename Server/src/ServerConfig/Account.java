package ServerConfig;

import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;
import merrimackutil.json.JSONSerializable;
import java.io.InvalidObjectException;

/**
 * This class represents an account record for the password manager. This
 * consists of the URL, the username, and the password.
 */
public class Account implements JSONSerializable {

    private String salt;			
    private String pass;		
    private String totp_key;		
    private String user;        

    /**
     * Constructs a new Account from the given JSON object.
     *
     * @param obj
     * @throws InvalidObjectException if the object is not a proper Account
     * object.
     */
    public Account(JSONObject obj) throws InvalidObjectException {
        deserialize(obj);
    }

    /**
     * Construct a new Account.
     *
     * @param salt
     * @param user the user name for the account.
     * @param totp_key
     * @param pass the encrypted password associated with the account.
     */
    public Account(String salt, String pass, String totp_key, String user) {
        this.salt = salt;
        this.pass = pass;
        this.totp_key = totp_key;
        this.user = user;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getPass() {
        return pass;
    }

    public void setPass(String pass) {
        this.pass = pass;
    }

    public String getTotp_key() {
        return totp_key;
    }

    public void setTotp_key(String totp_key) {
        this.totp_key = totp_key;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    /**
     * Serializes the object into a JSON encoded string.
     *
     * @return a string representing the JSON form of the object.
     */
    @Override
    public String serialize() {
        return toJSONType().getFormattedJSON();
    }

    /**
     * Coverts json data to an object of this type.
     *
     * @param obj a JSON type to deserialize.
     * @throws InvalidObjectException the type does not match this object.
     */
    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        JSONObject tmp;

        if (obj instanceof JSONObject) {
            tmp = (JSONObject) obj;
            if (tmp.containsKey("salt")) {
                salt = tmp.getString("salt");
            } else {
                throw new InvalidObjectException("Expected an Account object -- salt expected.");
            }
            if (tmp.containsKey("pass")) {
                pass = tmp.getString("pass");
            } else {
                throw new InvalidObjectException("Expected an Account object -- pass expected.");
            }
            if (tmp.containsKey("totp-key")) {
                totp_key = tmp.getString("totp-key");
            } else {
                throw new InvalidObjectException("Expected an Account object -- totp-key expected.");
            }
            if (tmp.containsKey("user")) {
                user = tmp.getString("user");
            } else {
                throw new InvalidObjectException("Expected an Account object -- user expected.");
            }
            
        } else {
            throw new InvalidObjectException("Expected a Photograph object -- recieved array");
        }

    }


    /**
     * Converts the object to a JSON type.
     *
     * @return a JSON type either JSONObject or JSONArray.
     */
    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();

        obj.put("salt", salt);
        obj.put("pass", pass);
        obj.put("totp-key", totp_key);
        obj.put("user", user);

        return obj;
    }

}
