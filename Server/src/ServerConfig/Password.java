package ServerConfig;
import java.io.InvalidObjectException;
import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

/**
 *
 * @author Mark Case
 */
public class Password implements JSONSerializable {
        
    private String salt;
    private String pass;
    private String totp_key;
    private String user;

    public Password(JSONObject obj) throws InvalidObjectException {
        deserialize(obj); // Deserialize a host into this host object
    }         

    @Override
    public String serialize() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void deserialize(JSONType jsont) throws InvalidObjectException {
        if(jsont instanceof JSONObject) {
            JSONObject obj = (JSONObject) jsont;

            if (obj.containsKey("salt")) {
                this.salt = obj.getString("salt");
            } else {
                throw new InvalidObjectException("Expected an Secret object -- secret expected.");
            }

            if (obj.containsKey("pass")) {
                this.pass = obj.getString("pass");
            } else {
                throw new InvalidObjectException("Expected an Secret object -- secret expected.");
            }

            if (obj.containsKey("user")) {
                this.user = obj.getString("user");
            } else {
                throw new InvalidObjectException("Expected an Secret object -- user expected.");
            }

            if (obj.containsKey("totp-key")) {
                this.totp_key = obj.getString("totp-key");
            } else {
                throw new InvalidObjectException("Expected an Secret object -- secret expected.");
            }


        }
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("user", this.getUser());
        obj.put("salt", this.getSalt());
        obj.put("pass", this.getPass());
        obj.put("totp-key", this.getTotp_key());


        return obj; // We should never be writing to a file.
    }

    public String getSalt() {
        return salt;
    }

    public String getPass() {
        return pass;
    }

    public String getTotp_key() {
        return totp_key;
    }

    public String getUser() {
        return user;
    }
    
}
