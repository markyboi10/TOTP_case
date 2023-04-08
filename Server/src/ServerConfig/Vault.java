package ServerConfig;

import java.util.HashMap;
import java.io.InvalidObjectException;

import merrimackutil.json.types.JSONType;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.JSONSerializable;

/**
 * This class represents the vault data structure for the password manager.
 *
 * @author Zach Kissel
 */
public class Vault implements JSONSerializable {

    private HashMap<String, Account> accounts;

    /**
     * Construct a new vault from a JSON Object.
     *
     * @param pass the password associated with the vault.
     * @param obj the JSON object representing a vault.
     * @throws InvalidObjectException when {@code obj} doesn't represent a valid
     * Vault object.
     */
    public Vault(String pass, JSONObject obj) throws InvalidObjectException {

        accounts = new HashMap<>();
        deserialize(obj);

    }

    public void addAccount(String entries, String salt, String pass, String totp_key, String user) {
        accounts.put(entries, new Account(salt, pass, totp_key, user));
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
        JSONArray accountsArray;
        if (obj instanceof JSONObject) {
            tmp = (JSONObject) obj;
            if (tmp.containsKey("entries")) {
                accountsArray = tmp.getArray("entries");
            } else {
                throw new InvalidObjectException("Expected a Vault object -- entries expected.");
            }
        } else {
            throw new InvalidObjectException("Expected a Vault object -- recieved array");
        }

        for (int i = 0; i < accountsArray.size(); i++) {
            JSONObject currAccount = accountsArray.getObject(i);
            accounts.put(currAccount.getString("url"), new Account(currAccount));
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
        JSONArray accountsArray = new JSONArray();

        for (String url : accounts.keySet()) {
            accountsArray.add(accounts.get(url).toJSONType());
        }

        obj.put("entries", accountsArray);
        return obj;
    }

}
