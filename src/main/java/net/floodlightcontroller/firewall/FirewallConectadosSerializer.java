package net.floodlightcontroller.firewall;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import net.floodlightcontroller.core.types.Host;
import org.python.antlr.ast.Str;

import java.io.IOException;

public class FirewallConectadosSerializer extends JsonSerializer<Host> {

    @Override
    public void serialize(Host hostsito, JsonGenerator jGen, SerializerProvider arg2) throws IOException, JsonProcessingException {
        jGen.writeStartObject();

        jGen.writeFieldName("IP");
        jGen.writeStartObject();
        jGen.writeStringField("IP",hostsito.getIP().toString());
        jGen.writeEndObject();

        jGen.writeFieldName("MAC");
        jGen.writeStartObject();
        jGen.writeStringField("MAC",hostsito.getMAC());
        jGen.writeEndObject();

        jGen.writeFieldName("switch");
        jGen.writeStartObject();
        jGen.writeStringField("DPID",hostsito.getSW());
        jGen.writeEndObject();

        jGen.writeFieldName("Puerto_SW");
        jGen.writeStartObject();
        jGen.writeStringField("Puerto_SW", String.valueOf(hostsito.getPortSW()));
        jGen.writeEndObject();


        jGen.writeEndObject();
    }

}
