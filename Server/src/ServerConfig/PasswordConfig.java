package ServerConfig;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InvalidObjectException;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

/**
 *
 * @author Mark Case
 */
public class PasswordConfig {

    private String path;

    public PasswordConfig(String path) throws FileNotFoundException, InvalidObjectException {
        this.path = path;

        System.out.println("PATH: " + path);

        // Construct file
        File file = new File(path);

        if (file == null || !file.exists()) {
            throw new FileNotFoundException("File from path for PasswordConfig does not point to a vadlid configuration json file.");
        }

        // Construct JSON Object and load hosts
        JSONObject obj = JsonIO.readObject(file);
        JSONArray array = obj.getArray("entries");
        // deserialize
        deserialize(array);
    }

    public String serialize() {
        return toJSONType().getFormattedJSON();// We should never be converting this file to JSON, only read.
    }

    public void deserialize(JSONType type) throws InvalidObjectException {
        if (type instanceof JSONArray) {
            JSONArray array = (JSONArray) type;

            // Construct a list of hosts
            List<Password> passwords = array.stream()
                    .filter(n -> n instanceof JSONObject)
                    .map(n -> (JSONObject) n)
                    .map(n -> {
                        try {
                            return new Password(n);
                        } catch (InvalidObjectException e) {
                            return null;
                        }
                    })
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());

            // Add all hosts to the SSO Client.
            server.Server.entries.addAll(passwords);
        }
    }

    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        JSONArray arr = new JSONArray();

        arr.addAll(server.Server.entries); // Add all hosts to the array.

        obj.put("entries", arr); // Assign the hosts array.
        return obj; // We are never reading this file to JSON.
    }

}
