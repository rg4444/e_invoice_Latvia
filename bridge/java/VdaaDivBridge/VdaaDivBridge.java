import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;

import lv.gov.vraa.div.uui._2011._11.UnifiedServiceInterface;
import lv.gov.vraa.xmlschemas.div.uui._2011._11.GetInitialAddresseeRecordListInput;
import lv.gov.vraa.xmlschemas.div.uui._2011._11.GetInitialAddresseeRecordListOutput;
import lv.gov.vraa.xmlschemas.div.uui._2011._11.ObjectFactory;
import vraa.div.client.ClientConfiguration;
import vraa.div.client.IntegrationClientContext;
import vraa.div.client.StoreLocation;
import vraa.div.client.configuration.InternalConfiguration;

public class VdaaDivBridge {
    private static final String OP_GET_INITIAL_ADDRESSEE = "GetInitialAddresseeRecordList";

    public static void main(String[] args) {
        Map<String, String> opts = parseArgs(args);
        String operation = opts.get("operation");
        String endpoint = opts.get("endpoint");
        String token = opts.getOrDefault("token", "");
        String outDir = opts.get("out-dir");
        String pfxPath = opts.get("pfx");
        String pfxPass = opts.getOrDefault("pfx-pass", "");

        if (operation == null || operation.isEmpty()) {
            printError("Missing --operation");
            return;
        }
        if (endpoint == null || endpoint.isEmpty()) {
            printError("Missing --endpoint");
            return;
        }
        if (outDir == null || outDir.isEmpty()) {
            printError("Missing --out-dir");
            return;
        }

        if (!OP_GET_INITIAL_ADDRESSEE.equals(operation)) {
            printError("Unsupported operation: " + operation);
            return;
        }

        try {
            Files.createDirectories(Path.of(outDir));
            String timestamp = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());
            String requestFile = operation + "_java_" + timestamp + "_request.xml";
            String responseFile = operation + "_java_" + timestamp + "_response.xml";
            Path requestPath = Path.of(outDir, requestFile);
            Path responsePath = Path.of(outDir, responseFile);

            ObjectFactory factory = new ObjectFactory();
            GetInitialAddresseeRecordListInput input = new GetInitialAddresseeRecordListInput();
            input.setToken(factory.createGetInitialAddresseeRecordListInputToken(token));

            String requestXml = marshalToXml(input);
            if (requestXml != null) {
                Files.writeString(requestPath, requestXml, StandardCharsets.UTF_8);
            }

            ClientConfiguration config = new ClientConfiguration();
            config.setServiceAddress(endpoint);
            config.setTimeout(60000);
            if (pfxPath != null && !pfxPath.isEmpty()) {
                char[] pass = pfxPass == null ? new char[0] : pfxPass.toCharArray();
                config.getCertificates().add("", StoreLocation.PKCS12, pfxPath, pass);
            }

            InternalConfiguration internal = InternalConfiguration.fromClientConfig(config);
            IntegrationClientContext context = new IntegrationClientContext(internal);
            UnifiedServiceInterface service = context.call();

            GetInitialAddresseeRecordListOutput output = service.getInitialAddresseeRecordList(input);
            String responseXml = marshalToXml(output);
            if (responseXml != null) {
                Files.writeString(responsePath, responseXml, StandardCharsets.UTF_8);
            }

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("ok", true);
            payload.put("engine", "java");
            payload.put("operation", operation);
            payload.put("endpoint", endpoint);
            if (requestXml != null) {
                payload.put("request_xml", requestXml);
            }
            if (responseXml != null) {
                payload.put("response_xml", responseXml);
            }
            payload.put("request_saved_path", requestPath.toString());
            payload.put("response_saved_path", responsePath.toString());
            payload.put("saved_request_path", requestPath.toString());
            payload.put("saved_response_path", responsePath.toString());
            payload.put("stderr", "");

            System.out.println(toJson(payload));
        } catch (Exception exc) {
            printError("Exception: " + exc.getMessage(), exc);
        }
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> opts = new LinkedHashMap<>();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (!arg.startsWith("--")) {
                continue;
            }
            String key = arg.substring(2);
            String value = "";
            if (key.contains("=")) {
                String[] parts = key.split("=", 2);
                key = parts[0];
                value = parts[1];
            } else if (i + 1 < args.length) {
                value = args[++i];
            }
            opts.put(key, value);
        }
        return opts;
    }

    private static String marshalToXml(Object obj) throws Exception {
        if (obj == null) {
            return null;
        }
        JAXBContext ctx = JAXBContext.newInstance(obj.getClass());
        Marshaller marshaller = ctx.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        StringWriter writer = new StringWriter();
        marshaller.marshal(obj, writer);
        return writer.toString();
    }

    private static void printError(String message) {
        printError(message, null);
    }

    private static void printError(String message, Exception exc) {
        String stack = "";
        if (exc != null) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            exc.printStackTrace(pw);
            stack = sw.toString();
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("ok", false);
        payload.put("engine", "java");
        payload.put("fault_reason", message);
        payload.put("stderr", stack);

        System.out.println(toJson(payload));
    }

    private static String toJson(Map<String, Object> payload) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : payload.entrySet()) {
            if (!first) {
                sb.append(",");
            }
            first = false;
            sb.append("\"").append(escapeJson(entry.getKey())).append("\":");
            Object value = entry.getValue();
            if (value == null) {
                sb.append("null");
            } else if (value instanceof Boolean || value instanceof Number) {
                sb.append(value.toString());
            } else {
                sb.append("\"").append(escapeJson(value.toString())).append("\"");
            }
        }
        sb.append("}");
        return sb.toString();
    }

    private static String escapeJson(String value) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\\\");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
}
