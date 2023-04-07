package ClientConfig;

import java.io.InvalidObjectException;
import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

public class Host implements JSONSerializable {

    // Host Data
    private String service;
    private String address;
    private int port;

    public Host(JSONObject obj) throws InvalidObjectException {
        deserialize(obj); // Deserialize a host into this host object
    }

    @Override
    public String serialize() {
        return toJSONType().getFormattedJSON(); // Should never be called
    }

    @Override
    public void deserialize(JSONType jsont) throws InvalidObjectException {
        if (jsont instanceof JSONObject) {
            JSONObject obj = (JSONObject) jsont;

            if (obj.containsKey("service")) {
                this.service = obj.getString("service");
            } else {
                throw new InvalidObjectException("Expected an Host object -- host-name expected.");
            }

            if (obj.containsKey("address")) {
                this.address = obj.getString("address");
            } else {
                throw new InvalidObjectException("Expected an Host object -- address expected.");
            }

            if (obj.containsKey("port")) {
                this.port = obj.getInt("port");
            } else {
                throw new InvalidObjectException("Expected an Host object -- port expected.");
            }
        }
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("service", this.getService());
        obj.put("address", this.getAddress());
        obj.put("port", this.getPort());

        return obj; // We should never be writing to a file.
    }

    /**
     * @return the service
     */
    public String getService() {
        return service;
    }

    /**
     * @return the address
     */
    public String getAddress() {
        return address;
    }

    /**
     * @return the port
     */
    public int getPort() {
        return port;
    }

}
