package net.floodlightcontroller.firewall;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;
import net.floodlightcontroller.core.types.Host;
import org.restlet.data.Status;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

public class FirewallPermisosActualizarHostsResource extends ServerResource {
    protected static Logger logger = LoggerFactory.getLogger(FirewallPermisosActualizarHostsResource.class);

    @Post
    public String permisosActualizar(String rulesJson) {
        IFirewallService firewallService = (IFirewallService)getContext().getAttributes().get(IFirewallService.class.getCanonicalName());

        String username = (String) getRequestAttributes().get("username");
        HashMap<String, ArrayList<String>> permisos = new HashMap<>();

        MappingJsonFactory f = new MappingJsonFactory();
        JsonParser jp;

        try {
            try {
                jp = f.createParser(rulesJson);
            } catch (JsonParseException e) {
                setStatus(Status.CLIENT_ERROR_BAD_REQUEST);
                return "{\"Status\" : \"Unable to create parser!\"}";
            }

            jp.nextToken();
            if (jp.getCurrentToken() != JsonToken.START_OBJECT) {
                setStatus(Status.CLIENT_ERROR_BAD_REQUEST);
                return "{\"Status\" : \"Expected START_OBJECT!\"}";
            }

            while (jp.nextToken() != JsonToken.END_OBJECT) {
                if (jp.getCurrentToken() != JsonToken.FIELD_NAME) {
                    setStatus(Status.CLIENT_ERROR_BAD_REQUEST);
                    return "{\"Status\" : \"Expected FIELD_NAME!\"}";
                }

                String nameResource = jp.getCurrentName();

                jp.nextToken();
                if (jp.getText().equals("")) {
                    continue;
                }else{
                    ArrayList<String> ipsResource = new ArrayList<>();

                    String listasResultadoStr = jp.getText();
                    listasResultadoStr = listasResultadoStr.replace("[","");
                    listasResultadoStr = listasResultadoStr.replace("]","");

                    String[] listaIps = null;

                    if(listasResultadoStr.contains(",")){
                        listaIps = listasResultadoStr.split(",");

                    }else{
                        listaIps = new String[1];
                        listaIps[0] = listasResultadoStr;
                    }

                    for(int i=0; i < listaIps.length;i++){
                        String ipStr = listaIps[i];

                        String ip = ipStr.replace("'","");
                        ipsResource.add(ip);
                    }

                    permisos.put(nameResource,ipsResource);
                }

            }
        } catch (IOException e) {
            setStatus(Status.CLIENT_ERROR_BAD_REQUEST);
            return "{\"Status\" : \"Unable to parse JSON string!\"}";
        }


        try {
            firewallService.actualizarPermisosUsername(username,permisos);
            setStatus(Status.SUCCESS_OK);
            return "{\"Status\" : \"Permisos seteados correctamente!\"}";
        } catch (Exception e){
            setStatus(Status.CLIENT_ERROR_BAD_REQUEST);
            return "{\"Status\" : \"An exception has ocurred!\"}";
        }

    }

}
