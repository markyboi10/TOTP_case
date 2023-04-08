package packets;

import java.io.InvalidObjectException;
import java.util.logging.Level;
import java.util.logging.Logger;
import merrimackutil.json.JSONSerializable;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

/**
 *
 * @author Mark Case
 */
public class AuthnHello implements Packet, JSONSerializable {
        
    // Packet Type
    private static final PacketType PACKET_TYPE = PacketType.AuthnHello;
    
    // Packet Data
    private String uName;
    private String accType;

    /**
     * Default Constructor for a SessionKeyResponse
     * @param uName
     * @param accType
     */
    public AuthnHello(String uName, String accType) {
        this.uName = uName;
        this.accType = accType;
    }

    public String getAccType() {
        return accType;
    }

    public String getuName() {
        return uName;
    }

    /**
     * Converts a JSONObject into a ticket object
     * @param packet byte[] of information representing this packet
     * @param packetType1
     * @throws InvalidObjectException Thrown if {@code object} is not a Ticket JSONObject
     */
    public AuthnHello(String packet, PacketType packetType1) throws InvalidObjectException {
        recieve(packet);
    }

    /**
     * JSONSerializable implementations
     */
    
    /**
     * Serializes the object into a JSON String
     * @return 
     */
    @Override
    public String serialize() {
        return toJSONType().toJSON();
    }

    /**
     * Converts a JSON type to this object
     * Converts types of Byte[] into strings for travel
     * @param obj
     * @throws InvalidObjectException 
     */
    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        JSONObject tmp;

        if (obj instanceof JSONObject)
          {
            tmp = (JSONObject)obj;
            if (tmp.containsKey("user"))
              this.uName = tmp.getString("user");
            else
              throw new InvalidObjectException("Expected an Ticket object -- uName expected.");
            
                        
            if (tmp.containsKey("accType"))
              this.accType = tmp.getString("accType");
            else
              throw new InvalidObjectException("Expected an Ticket object -- accType expected.");
            
          }
          else 
            throw new InvalidObjectException("Expected a Ticket - Type JSONObject not found.");
    }

    /**
     * Constructs a JSON object representing this Ticket.
     * @return 
     */
    @Override
    public JSONType toJSONType() {
        JSONObject object = new JSONObject();
        object.put("packetType", PACKET_TYPE.toString());
        object.put("user", this.uName);
        object.put("accType", this.accType);

        return object;
    }

    /**
     * Packet implementations.
     */
    
    /**
     * Constructs a packet based off of this object
     * A packet is a byte[], we are using JSON to store the packet data.
     * @return A byte[] of packet information
     */    
    @Override
    public String send() {
        
        String jsonString = serialize(); // Convert to String from this class.
        return jsonString; // Convert JSON string to byte[]
    }

    /**
     * Constructs an object T based off of the given packet
     * Generally, this should be used when reading packets in.
     * @param packet input byte[]
     */
    @Override
    public void recieve(String packet) {
        
        try {
             JSONObject jsonObject = JsonIO.readObject(packet); // String to JSONObject
             deserialize(jsonObject); // Deserialize jsonObject
        } catch (InvalidObjectException ex) {
            Logger.getLogger(AuthnHello.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    /**
     * The PacketType value of this packet.
     * @return 
     */
    @Override
    public PacketType getType() {
        return PACKET_TYPE;
    }
    
}     
