VraaDivClient.jar - Klienta API

            serializer-2.7.1.jar        |
            webservices-api.jar         |
            webservices-extra.jar       |
            webservices-extra-api.jar   |>   treðâs puses bibliotçkas 
            webservices-rt.jar          |
            webservices-tools.jar       |
            xalan-2.7.1.jar             |
            
Visiem ðiem JAR jâbût CLASSPATH, lai varçtu lietot klienta API
    
webservices-api.jar turklât jâbût definçtai kâ "endorsed" bibliotçkai (skat. http://docs.oracle.com/javase/1.5.0/docs/guide/standards/index.html)

SVARÎGI: Ja sertifikâta .pfx ìenerçðanai tiek izmantota OpenSSL jaunâka versija, nepiecieðams nodroðinât atbilstîbu Java 8: 
>openssl pkcs12 -export -in c:\temp\sertifikats_test.cer -inkey c:\temp\sertifikats_test.key -out c:\temp\sertifikats_test_for_JAVA8.pfx -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1
