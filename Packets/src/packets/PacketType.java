package packets;

import java.util.Arrays;
import static packets.PacketType.values;

/**
 * Represents the type of packet being sent/received
 * Uses for determining responses & information.
 * @author Mark Case
 */
public enum PacketType {
      AuthnHello(packets.AuthnHello.class),
      CreateChallenge(packets.CreateChallenge.class),
      CreateResponse(packets.CreateResponse.class),
      SendKey(packets.SendKey.class),
      AuthnPass(packets.AuthnPass.class),
      PassResponse(packets.PassResponse.class),
      SendTOTP(packets.SendTOTP.class),
      AuthnStatus(packets.AuthnStatus.class)
      ;

      
    private Class packetClass;
    
    PacketType(Class packetClass) {
        this.packetClass = packetClass;
    }
    
    /**
     * The associated class representing a PacketType
     * @return 
     */
    public Class getPacketClass() {
        return this.packetClass;
    }
    
    /**
     * Gets a packet from a String {@code name}
     * @param name
     * @return 
     */
    public static PacketType getPacketTypeFromString(String name) {
        return Arrays.stream(values())
                .filter(n -> n.toString().equalsIgnoreCase(name))
                .findFirst()
                .orElse(null);
    }
    
}

