
/**
 *
 * @author Greddy
 */
public class Log {

    public String l_typ_header, l_Time, l_IP_Source, l_IP_Destination, l_other_content;
    public int l_IDs, l_Port_Source, l_Port_Destination;

    public Log(int s_IDs, String s_typ_header, String s_Time, String s_IP_Source, int s_Port_Source,
            String s_IP_Destination, int s_Port_Destination, String s_other_content) {

        this.l_IDs = s_IDs;
        this.l_typ_header = s_typ_header;
        this.l_Time = s_Time;
        this.l_IP_Source = s_IP_Source;
        this.l_Port_Source = s_Port_Source;
        this.l_IP_Destination = s_IP_Destination;
        this.l_Port_Destination = s_Port_Destination;
        this.l_other_content = s_other_content;
        

    }

    @Override
    public String toString() {
        return "";
    }
    public Object toObject() {
        return 1+2;
    }
}