import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

public class SoapTraceHandler implements SOAPHandler<SOAPMessageContext> {
    private final String outDir;
    private final String operation;
    private final String timestamp;
    private String requestPath;
    private String responsePath;

    public SoapTraceHandler(String outDir, String operation, String timestamp) {
        this.outDir = outDir;
        this.operation = operation;
        this.timestamp = timestamp;
    }

    @Override
    public boolean handleMessage(SOAPMessageContext context) {
        Boolean outbound = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
        if (outbound == null) {
            return true;
        }
        String suffix = outbound ? "soap_request.xml" : "soap_response.xml";
        String name = operation + "_" + timestamp + "_" + suffix;
        Path outPath = Path.of(outDir, name);
        try {
            SOAPMessage message = context.getMessage();
            if (message != null) {
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                message.writeTo(output);
                Files.write(outPath, output.toByteArray());
            }
        } catch (Exception exc) {
            return true;
        }
        if (outbound) {
            requestPath = outPath.toString();
        } else {
            responsePath = outPath.toString();
        }
        return true;
    }

    @Override
    public boolean handleFault(SOAPMessageContext context) {
        return handleMessage(context);
    }

    @Override
    public void close(MessageContext context) {
        // no-op
    }

    @Override
    public Set<QName> getHeaders() {
        return null;
    }

    public String getRequestPath() {
        return requestPath;
    }

    public String getResponsePath() {
        return responsePath;
    }
}
