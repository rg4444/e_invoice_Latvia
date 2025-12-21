import java.io.FileInputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBIntrospector;
import javax.xml.bind.Marshaller;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import lv.gov.vraa.div.uui._2011._11.UnifiedServiceInterface;
import lv.gov.vraa.xmlschemas.div.uui._2011._11.GetInitialAddresseeRecordListInput;
import lv.gov.vraa.xmlschemas.div.uui._2011._11.ObjectFactory;
import vraa.div.client.ClientConfiguration;
import vraa.div.client.IntegrationClientContext;
import vraa.div.client.StoreLocation;
import vraa.div.client.configuration.InternalConfiguration;

public class VdaaDivBridge {
    private static final String OP_GET_INITIAL_ADDRESSEE = "GetInitialAddresseeRecordList";
    private static final String SOAP_ACTION_GET_INITIAL =
        "http://vraa.gov.lv/div/uui/2011/11/UnifiedServiceInterface/GetInitialAddresseeRecordList";

    public static void main(String[] args) {
        Map<String, String> opts = parseArgs(args);
        String operation = opts.get("operation");
        String endpoint = opts.get("endpoint");
        String token = opts.getOrDefault("token", "");
        String outDir = opts.get("out-dir");
        String pfxPath = opts.get("pfx");
        String pfxPass = opts.getOrDefault("pfx-pass", "");
        String configPath = opts.getOrDefault("config", "/data/config.json");
        String timeoutStr = opts.getOrDefault("timeout-seconds", "60");
        int timeoutSeconds = 60;
        try {
            timeoutSeconds = Integer.parseInt(timeoutStr);
        } catch (Exception ignore) {
            timeoutSeconds = 60;
        }
        if (timeoutSeconds < 0) {
            timeoutSeconds = 0;
        }
        if (timeoutSeconds > 3600) {
            timeoutSeconds = 3600;
        }

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

            JAXBElement<GetInitialAddresseeRecordListInput> requestElement =
                factory.createGetInitialAddresseeRecordListInput(input);
            marshalPayload(requestElement, requestPath);

            ClientConfiguration config = new ClientConfiguration();
            config.setServiceAddress(endpoint);
            config.setTimeout(timeoutSeconds);
            String certThumbprint = null;
            if (pfxPath != null && !pfxPath.isEmpty()) {
                char[] pass = (pfxPass == null) ? new char[0] : pfxPass.toCharArray();
                certThumbprint = sha1ThumbprintFromPfx(pfxPath, pass);
                config.getCertificates().add(certThumbprint, StoreLocation.PKCS12, pfxPath, pass);
            }

            InternalConfiguration internal = InternalConfiguration.fromClientConfig(config);
            IntegrationClientContext context = new IntegrationClientContext(internal);
            UnifiedServiceInterface service = context.call();

            SoapTraceHandler traceHandler = new SoapTraceHandler(outDir, operation, timestamp);
            BindingProvider bindingProvider = (BindingProvider) service;
            Binding binding = bindingProvider.getBinding();
            List<Handler> existing = binding.getHandlerChain();
            List<Handler> updated = new ArrayList<>();
            if (existing != null) {
                updated.addAll(existing);
            }
            updated.add(traceHandler);
            binding.setHandlerChain(updated);

            long callStarted = System.nanoTime();
            Object response = service.getInitialAddresseeRecordList(input);
            long tookMs = Math.max(0, (System.nanoTime() - callStarted) / 1_000_000);
            marshalPayload(response, responsePath);

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("ok", true);
            payload.put("engine", "java");
            payload.put("operation", operation);
            payload.put("endpoint", endpoint);
            payload.put("endpoint_mode", endpointMode(endpoint));
            payload.put("sent_utc", isoUtcNow());
            payload.put("took_ms", tookMs);
            payload.put("http_status", extractHttpStatus(bindingProvider));
            payload.put("soap_action", SOAP_ACTION_GET_INITIAL);
            payload.put("request_saved_path", requestPath.toString());
            payload.put("response_saved_path", responsePath.toString());
            payload.put("soap_request_path", traceHandler.getRequestPath());
            payload.put("soap_response_path", traceHandler.getResponsePath());
            payload.put("trace_error", traceHandler.getTraceError());
            payload.put("message_id", extractMessageId(traceHandler.getRequestPath()));
            FaultInfo faultInfo = extractFaultInfo(traceHandler.getResponsePath());
            payload.put("fault_code", faultInfo.code);
            payload.put("fault_reason", faultInfo.reason);
            if (certThumbprint != null) {
                payload.put("cert_thumbprint_sha1", certThumbprint);
            }
            payload.put("stderr", "");

            System.out.println(toJson(payload));
        } catch (Exception exc) {
            printError("Exception: " + exc.getMessage(), exc);
        }
    }

    private static String endpointMode(String endpoint) {
        if (endpoint == null) {
            return "normal";
        }
        String normalized = endpoint.toLowerCase();
        return normalized.contains("debug") ? "debug" : "normal";
    }

    private static String isoUtcNow() {
        return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").format(new Date());
    }

    private static Integer extractHttpStatus(BindingProvider provider) {
        if (provider == null) {
            return null;
        }
        Object value = provider.getResponseContext().get("javax.xml.ws.http.response.code");
        if (value instanceof Integer) {
            return (Integer) value;
        }
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return null;
    }

    private static String extractMessageId(String path) {
        Document doc = loadXml(path);
        if (doc == null) {
            return null;
        }
        XPath xpath = XPathFactory.newInstance().newXPath();
        try {
            Node node = (Node) xpath.evaluate("//*[local-name()='MessageID']",
                                              doc, XPathConstants.NODE);
            if (node != null) {
                String text = node.getTextContent();
                if (text != null && !text.trim().isEmpty()) {
                    return text.trim();
                }
            }
        } catch (XPathExpressionException ignore) {
            return null;
        }
        return null;
    }

    private static FaultInfo extractFaultInfo(String path) {
        Document doc = loadXml(path);
        if (doc == null) {
            return new FaultInfo(null, null);
        }
        XPath xpath = XPathFactory.newInstance().newXPath();
        try {
            Node fault = (Node) xpath.evaluate("//*[local-name()='Fault']",
                                               doc, XPathConstants.NODE);
            if (fault == null) {
                return new FaultInfo(null, null);
            }
            String code = (String) xpath.evaluate(
                ".//*[local-name()='Code']/*[local-name()='Value']/text() | .//*[local-name()='faultcode']/text()",
                fault,
                XPathConstants.STRING
            );
            String reason = (String) xpath.evaluate(
                ".//*[local-name()='Reason']/*[local-name()='Text']/text() | .//*[local-name()='faultstring']/text()",
                fault,
                XPathConstants.STRING
            );
            code = (code == null || code.trim().isEmpty()) ? null : code.trim();
            reason = (reason == null || reason.trim().isEmpty()) ? null : reason.trim();
            return new FaultInfo(code, reason);
        } catch (XPathExpressionException ignore) {
            return new FaultInfo(null, null);
        }
    }

    private static Document loadXml(String path) {
        if (path == null) {
            return null;
        }
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            return factory.newDocumentBuilder().parse(Files.newInputStream(Path.of(path)));
        } catch (Exception ignore) {
            return null;
        }
    }

    private static class FaultInfo {
        private final String code;
        private final String reason;

        private FaultInfo(String code, String reason) {
            this.code = code;
            this.reason = reason;
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

    private static void marshalPayload(Object payload, Path outputPath) throws Exception {
        if (payload == null) {
            Files.writeString(outputPath, "", StandardCharsets.UTF_8);
            return;
        }
        Object toMarshal = payload;
        JAXBContext context;
        if (payload instanceof JAXBElement) {
            context = JAXBContext.newInstance(((JAXBElement<?>) payload).getDeclaredType());
        } else {
            context = JAXBContext.newInstance(payload.getClass());
            JAXBIntrospector introspector = context.createJAXBIntrospector();
            if (introspector.getElementName(payload) == null) {
                toMarshal = wrapWithObjectFactory(payload);
                if (toMarshal instanceof JAXBElement) {
                    context = JAXBContext.newInstance(((JAXBElement<?>) toMarshal).getDeclaredType());
                } else {
                    context = JAXBContext.newInstance(toMarshal.getClass());
                }
            }
        }
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        try (OutputStream output = Files.newOutputStream(outputPath)) {
            marshaller.marshal(toMarshal, output);
        }
    }

    private static Object wrapWithObjectFactory(Object payload) {
        if (payload == null) {
            return null;
        }
        ObjectFactory factory = new ObjectFactory();
        Method[] methods = ObjectFactory.class.getMethods();
        for (Method method : methods) {
            if (!method.getName().startsWith("create")) {
                continue;
            }
            Class<?>[] params = method.getParameterTypes();
            if (params.length != 1) {
                continue;
            }
            if (!params[0].isAssignableFrom(payload.getClass())) {
                continue;
            }
            try {
                return method.invoke(factory, payload);
            } catch (Exception ignore) {
                // keep looking for another applicable factory method
            }
        }
        return payload;
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

    private static String sha1ThumbprintFromPfx(String pfxPath, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(pfxPath)) {
            ks.load(fis, password);
        }

        Enumeration<String> aliases = ks.aliases();
        String chosen = null;
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                chosen = alias;
                break;
            }
            if (chosen == null) {
                chosen = alias;
            }
        }
        if (chosen == null) {
            throw new Exception("No aliases found in PFX");
        }

        X509Certificate cert = (X509Certificate) ks.getCertificate(chosen);
        if (cert == null) {
            throw new Exception("No certificate found in PFX alias: " + chosen);
        }

        byte[] enc = cert.getEncoded();
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(enc);

        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
