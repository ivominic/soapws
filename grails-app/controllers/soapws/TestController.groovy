package soapws

import wslite.soap.SOAPClient
import wslite.soap.SOAPResponse

import java.security.Key
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

class TestController {

    String servis1 = "https://10.61.4.10/servicev2/dokumenta-lks.php"
    String servis2 = "https://10.61.4.10/servicev2/dokumenta-lk.php"
    String servis3 = "https://10.61.4.10/servicev2/kodovi-servis.php?wsdl"
    String KEYSTORE_TYPE = "PKCS12"
    String KEYSTORE_PASS = "123456789"
    String KEY_STORE = "JKS"
    String X509 = "X.509"

    def index() {
        FileInputStream fileInputStreamPublic = new FileInputStream(new File(request.getSession().getServletContext().getRealPath('/sertifikati/Epeticije.cer')))
        CertificateFactory certificateFactory = CertificateFactory.getInstance(X509)
        Certificate publicSertifikat = certificateFactory.generateCertificate(fileInputStreamPublic)
        fileInputStreamPublic.close()

        //println publicSertifikat


        //try {
        FileInputStream fileInputStream = new FileInputStream(new File(request.getSession().getServletContext().getRealPath('/sertifikati/EpeticijePK.cer.pfx')))

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
        keyStore.load(fileInputStream, KEYSTORE_PASS.toCharArray())
        PrivateKey privateKey
        //println keyStore.aliases().getProperties()
        String alijas = ""
        keyStore.aliases().each {a->
            alijas = a
            println "alijas aa " + a
            privateKey = (PrivateKey) keyStore.getKey(a, KEYSTORE_PASS.toCharArray())
        }
        X509Certificate certificate = (X509Certificate)keyStore.getCertificate(alijas)
        //println "certificate Subject " + certificate.getSubjectDN()
        println "certificate" + certificate
        println "private key " + privateKey

        Signature privateSignature = Signature.getInstance("SHA1withRSA")
        //Signature privateSignature = Signature.getInstance("SHA1")
        privateSignature.initSign(privateKey)

        String user = "epeticija"
        String password = "epet0812"
        String pravni_osnov = "24"
        String osnov = "24"
        String mbr = "1703982210261"
        String broj_dokumenta = "821049285"
        String organ_izdavanja = "" //Ovdje kod za organ izdavanja, vraća ga servis
        String datum_izdavanja = "2010" //Godina izdavanja dokumenta
        String datum_zastite = "" //šalje se prazan string

        String stringZaPotpis = user + " , " + password + " , " + pravni_osnov + " , " + osnov + " , " + mbr + " , " + broj_dokumenta + " , " + organ_izdavanja + " , " + datum_izdavanja + " , " + datum_zastite
        privateSignature.update(stringZaPotpis.getBytes())

        byte[] signature = privateSignature.sign()
        String potpis = Base64.getEncoder().encodeToString(signature)

        println "potpis    " + potpis

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = [ new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null
            }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }
        ]

// Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL")
        sc.init(null, trustAllCerts, new java.security.SecureRandom())
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())

// Create all-trusting host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true
            }
        }

        // Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

        SOAPClient client = new SOAPClient("${servis1}?wsdl")
        //SOAPClient client = new SOAPClient()
        client.httpClient.sslTrustStoreFile = certificate
        client.httpClient.sslTrustStorePassword ="123456789"
        client.httpClient.sslTrustAllCerts = true
        SOAPResponse response = client.send(
                """<?xml version='1.0' encoding='UTF-8'?>
       <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:do="https://10.61.4.10/servicev2/dokumenta-lk.php">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
        <do:vratiDokumentLK SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <DokumentIN>
                <user>${user}</user>
                <password>${password}</password>
                <pravni_osnov>${pravni_osnov}</pravni_osnov>
                <osnov>${osnov}</osnov>
                <mbr>${mbr}</mbr>
                <broj_dokumenta>${broj_dokumenta}</broj_dokumenta>
                <organ_izdavanja>${organ_izdavanja}</organ_izdavanja>
                <datum_izdavanja>${datum_izdavanja}</datum_izdavanja>
                <datum_zastite>${datum_zastite}</datum_zastite>
                <potpis>${potpis}</potpis>
            </DokumentIN>
        </do:vratiDokumentLK>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
        )


        /*SOAPResponse response = client.send(SOAPAction: servis1) {
            body('xmlns': 'http://schemas.xmlsoap.org/wsdl/soap/') {
                vratiDokumentLK {
                    user(user1)
                    password(password1)
                    pravni_osnov(pravni_osnov1)
                    osnov(osnov1)
                    mbr(mbr1)
                    broj_dokumenta(broj_dokumenta1)
                    organ_izdavanja(organ_izdavanja1)
                    datum_izdavanja(datum_izdavanja1)
                    datum_zastite(datum_zastite1)
                    potpis(signature)
                }
            }
        }*/


        render response

        //render Base64.getEncoder().encodeToString(signature)
        /*}
        catch (Exception ex){
            println "Greška    " + ex.message
            render "Greška    " + ex.message
        }*/
    }


    def prvi() {

        FileInputStream fileInputStreamPublic = new FileInputStream(new File(request.getSession().getServletContext().getRealPath('/sertifikati/Epeticije.cer')))
        CertificateFactory certificateFactory = CertificateFactory.getInstance(X509)
        Certificate publicSertifikat = certificateFactory.generateCertificate(fileInputStreamPublic)
        fileInputStreamPublic.close()

        FileInputStream fileInputStream = new FileInputStream(new File(request.getSession().getServletContext().getRealPath('/sertifikati/EpeticijePK.cer.pfx')))

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
        keyStore.load(fileInputStream, KEYSTORE_PASS.toCharArray())
        PrivateKey privateKey
        //println keyStore.aliases().getProperties()
        String alijas = ""
        keyStore.aliases().each {a->
            alijas = a
            privateKey = (PrivateKey) keyStore.getKey(a, KEYSTORE_PASS.toCharArray())
        }
        X509Certificate certificate = (X509Certificate)keyStore.getCertificate(alijas)

        Signature privateSignature = Signature.getInstance("SHA1withRSA")

        privateSignature.initSign(privateKey)

        String user = "epeticija"
        String password = "epet0812"
        String pravni_osnov = "24"
        String osnov = "24"
        String mbr = "1703982210261"
        String broj_dokumenta = "821049285"
        String organ_izdavanja = "" //Ovdje kod za organ izdavanja, vraća ga servis
        String datum_izdavanja = "2010" //Godina izdavanja dokumenta
        String datum_zastite = "" //šalje se prazan string

        String stringZaPotpis = user + " , " + password + " , " + pravni_osnov + " , " + osnov + " , " + mbr + " , " + broj_dokumenta + " , " + organ_izdavanja + " , " + datum_izdavanja + " , " + datum_zastite
        privateSignature.update(stringZaPotpis.getBytes())

        byte[] signature = privateSignature.sign()
        String potpis = Base64.getEncoder().encodeToString(signature)

        println "potpis    " + potpis

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = [ new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null
            }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }
        ]

// Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL")
        sc.init(null, trustAllCerts, new java.security.SecureRandom())
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())

// Create all-trusting host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true
            }
        }

        // Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

        SOAPClient client = new SOAPClient("${servis1}?wsdl")
        //SOAPClient client = new SOAPClient()
        //client.httpClient.sslTrustStoreFile = publicSertifikat
        client.httpClient.sslTrustStoreFile = privateKey
        client.httpClient.sslTrustStorePassword ="123456789"
        client.httpClient.sslTrustAllCerts = true
        SOAPResponse response = client.send(
                """<?xml version='1.0' encoding='UTF-8'?>
       <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:do="https://10.61.4.10/servicev2/dokumenta-lk.php">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
        <do:vratiDokumentLK SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <DokumentIN>
                <user>epeticija</user>
                <password>epet0812</password>
                <pravni_osnov>24</pravni_osnov>
                <osnov>24</osnov>
                <mbr>1703982210261</mbr>
                <broj_dokumenta>821049285</broj_dokumenta>
                <organ_izdavanja></organ_izdavanja>
                <datum_izdavanja>2010</datum_izdavanja>
                <datum_zastite></datum_zastite>
                <potpis>lrBsu4qFR2MVGjw9FAzSw7AGHzRQWX+cFmYhXxsiry9YyyflzIzkvCUJMJaga0aZsg3Qjqz5g0LPHkoy6BcV4gioFYVcMQiJBf+w0v6XligUAkqrbyquA2JKKTUaNLmp3OEpqbf9RQHY0zXCglczOjABv17GukMeBuKYMHrSOv24kToYfGDjlONk5CLYkWUvoHbodMV+alTS2elnF1iTFpR+8waZHhU/4gIGm/+BVdkY3iq+Cx2PsDVInYvonk/16GYOYbRdsa0uTtuDAmYpgFXZLYBVMlGFxKhA3ERDIcoqQ3tLLc4J42RVnE8HAmTe16lP7kUdxBmrvOrFoI7alg==</potpis>
            </DokumentIN>
        </do:vratiDokumentLK>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
        )

        render response

    }


    def drugi() {
        FileInputStream fileInputStreamPublic = new FileInputStream(new File(request.getSession().getServletContext().getRealPath('/sertifikati/Epeticije.cer')))
        CertificateFactory certificateFactory = CertificateFactory.getInstance(X509)
        Certificate publicSertifikat = certificateFactory.generateCertificate(fileInputStreamPublic)
        fileInputStreamPublic.close()

        FileInputStream fileInputStream = new FileInputStream(new File(request.getSession().getServletContext().getRealPath('/sertifikati/EpeticijePK.cer.pfx')))

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
        keyStore.load(fileInputStream, KEYSTORE_PASS.toCharArray())
        PrivateKey privateKey
        //println keyStore.aliases().getProperties()
        String alijas = ""
        keyStore.aliases().each {a->
            alijas = a
            privateKey = (PrivateKey) keyStore.getKey(a, KEYSTORE_PASS.toCharArray())
        }
        X509Certificate certificate = (X509Certificate)keyStore.getCertificate(alijas)

        Signature privateSignature = Signature.getInstance("SHA1withRSA")

        privateSignature.initSign(privateKey)

        String user = "epeticija"
        String password = "epet0812"
        String pravni_osnov = "24"
        String osnov = "24"
        String mbr = "1703982210261"
        String broj_dokumenta = "821049285"
        String organ_izdavanja = "" //Ovdje kod za organ izdavanja, vraća ga servis
        String datum_izdavanja = "2010" //Godina izdavanja dokumenta
        String datum_zastite = "" //šalje se prazan string

        String stringZaPotpis = user + " , " + password + " , " + pravni_osnov + " , " + osnov + " , " + mbr + " , " + broj_dokumenta + " , " + organ_izdavanja + " , " + datum_izdavanja + " , " + datum_zastite
        privateSignature.update(stringZaPotpis.getBytes())

        byte[] signature = privateSignature.sign()
        String potpis = Base64.getEncoder().encodeToString(signature)

        println "potpis    " + potpis

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = [ new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null
            }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }
        ]

// Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL")
        sc.init(null, trustAllCerts, new java.security.SecureRandom())
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())

// Create all-trusting host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true
            }
        }

        // Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

        SOAPClient client = new SOAPClient("${servis1}?wsdl")
        //SOAPClient client = new SOAPClient()
        //client.httpClient.sslTrustStoreFile = publicSertifikat
        //client.httpClient.sslTrustStoreFile = privateKey
        //client.httpClient.sslTrustStorePassword ="123456789"
        //client.httpClient.sslTrustAllCerts = true
        SOAPResponse response = client.send(
                """<?xml version='1.0' encoding='UTF-8'?>
       <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:do="https://10.61.4.10/servicev2/dokumenta-lk.php">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
        <do:vratiDokumentLK SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <DokumentIN>
                <user>epeticija</user>
                <password>epet0812</password>
                <pravni_osnov>24</pravni_osnov>
                <osnov>24</osnov>
                <mbr>1703982210261</mbr>
                <broj_dokumenta>821049285</broj_dokumenta>
                <organ_izdavanja></organ_izdavanja>
                <datum_izdavanja>2010</datum_izdavanja>
                <datum_zastite></datum_zastite>
                <potpis>lrBsu4qFR2MVGjw9FAzSw7AGHzRQWX+cFmYhXxsiry9YyyflzIzkvCUJMJaga0aZsg3Qjqz5g0LPHkoy6BcV4gioFYVcMQiJBf+w0v6XligUAkqrbyquA2JKKTUaNLmp3OEpqbf9RQHY0zXCglczOjABv17GukMeBuKYMHrSOv24kToYfGDjlONk5CLYkWUvoHbodMV+alTS2elnF1iTFpR+8waZHhU/4gIGm/+BVdkY3iq+Cx2PsDVInYvonk/16GYOYbRdsa0uTtuDAmYpgFXZLYBVMlGFxKhA3ERDIcoqQ3tLLc4J42RVnE8HAmTe16lP7kUdxBmrvOrFoI7alg==</potpis>
            </DokumentIN>
        </do:vratiDokumentLK>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
        )

        render response

    }

    def treci() {
        FileInputStream fileInputStreamPublic = new FileInputStream(new File(request.getSession().getServletContext().getRealPath('/sertifikati/Epeticije.cer')))
        CertificateFactory certificateFactory = CertificateFactory.getInstance(X509)
        Certificate publicSertifikat = certificateFactory.generateCertificate(fileInputStreamPublic)
        fileInputStreamPublic.close()

        FileInputStream fileInputStream = new FileInputStream(new File(request.getSession().getServletContext().getRealPath('/sertifikati/EpeticijePK.cer.pfx')))

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
        keyStore.load(fileInputStream, KEYSTORE_PASS.toCharArray())
        PrivateKey privateKey
        //println keyStore.aliases().getProperties()
        String alijas = ""
        keyStore.aliases().each {a->
            alijas = a
            privateKey = (PrivateKey) keyStore.getKey(a, KEYSTORE_PASS.toCharArray())
        }
        X509Certificate certificate = (X509Certificate)keyStore.getCertificate(alijas)

        Signature privateSignature = Signature.getInstance("SHA1withRSA")

        privateSignature.initSign(privateKey)

        String user = "epeticija"
        String password = "epet0812"
        String pravni_osnov = "24"
        String osnov = "24"
        String mbr = "1703982210261"
        String broj_dokumenta = "821049285"
        String organ_izdavanja = "" //Ovdje kod za organ izdavanja, vraća ga servis
        String datum_izdavanja = "2010" //Godina izdavanja dokumenta
        String datum_zastite = "" //šalje se prazan string

        String stringZaPotpis = user + " , " + password + " , " + pravni_osnov + " , " + osnov + " , " + mbr + " , " + broj_dokumenta + " , " + organ_izdavanja + " , " + datum_izdavanja + " , " + datum_zastite
        privateSignature.update(stringZaPotpis.getBytes())

        byte[] signature = privateSignature.sign()
        String potpis = Base64.getEncoder().encodeToString(signature)

        println "potpis    " + potpis

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = [ new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null
            }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }
        ]

// Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL")
        sc.init(null, trustAllCerts, new java.security.SecureRandom())
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())

// Create all-trusting host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true
            }
        }

        // Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

        SOAPClient client = new SOAPClient("${servis1}?wsdl")
        //SOAPClient client = new SOAPClient()
        //client.httpClient.sslTrustStoreFile = publicSertifikat
        //client.httpClient.sslTrustStoreFile = privateKey
        //client.httpClient.sslTrustStorePassword ="123456789"
        //client.httpClient.sslTrustAllCerts = true
        SOAPResponse response = client.send(
                """<?xml version='1.0' encoding='UTF-8'?>
       <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:do="https://10.61.4.10/servicev2/dokumenta-lk.php">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
        <do:vratiDokumentLK SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <DokumentIN>
                <user>epeticija</user>
                <password>epet0812</password>
                <pravni_osnov>24</pravni_osnov>
                <osnov>24</osnov>
                <mbr>1703982210261</mbr>
                <broj_dokumenta>821049285</broj_dokumenta>
                <organ_izdavanja></organ_izdavanja>
                <datum_izdavanja>2010</datum_izdavanja>
                <datum_zastite></datum_zastite>
                <potpis>lrBsu4qFR2MVGjw9FAzSw7AGHzRQWX+cFmYhXxsiry9YyyflzIzkvCUJMJaga0aZsg3Qjqz5g0LPHkoy6BcV4gioFYVcMQiJBf+w0v6XligUAkqrbyquA2JKKTUaNLmp3OEpqbf9RQHY0zXCglczOjABv17GukMeBuKYMHrSOv24kToYfGDjlONk5CLYkWUvoHbodMV+alTS2elnF1iTFpR+8waZHhU/4gIGm/+BVdkY3iq+Cx2PsDVInYvonk/16GYOYbRdsa0uTtuDAmYpgFXZLYBVMlGFxKhA3ERDIcoqQ3tLLc4J42RVnE8HAmTe16lP7kUdxBmrvOrFoI7alg==</potpis>
            </DokumentIN>
        </do:vratiDokumentLK>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
        )

        render response

    }

    def cetvrti() {
        FileInputStream fileInputStreamPublic = new FileInputStream(new File(request.getSession().getServletContext().getRealPath('/sertifikati/Epeticije.cer')))
        CertificateFactory certificateFactory = CertificateFactory.getInstance(X509)
        Certificate publicSertifikat = certificateFactory.generateCertificate(fileInputStreamPublic)
        fileInputStreamPublic.close()

        FileInputStream fileInputStream = new FileInputStream(new File(request.getSession().getServletContext().getRealPath('/sertifikati/EpeticijePK.cer.pfx')))

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE)
        keyStore.load(fileInputStream, KEYSTORE_PASS.toCharArray())
        PrivateKey privateKey
        //println keyStore.aliases().getProperties()
        String alijas = ""
        keyStore.aliases().each {a->
            alijas = a
            privateKey = (PrivateKey) keyStore.getKey(a, KEYSTORE_PASS.toCharArray())
        }
        X509Certificate certificate = (X509Certificate)keyStore.getCertificate(alijas)

        Signature privateSignature = Signature.getInstance("SHA1withRSA")

        privateSignature.initSign(privateKey)

        String user = "epeticija"
        String password = "epet0812"
        String pravni_osnov = "24"
        String osnov = "24"
        String mbr = "1703982210261"
        String broj_dokumenta = "821049285"
        String organ_izdavanja = "" //Ovdje kod za organ izdavanja, vraća ga servis
        String datum_izdavanja = "2010" //Godina izdavanja dokumenta
        String datum_zastite = "" //šalje se prazan string

        String stringZaPotpis = user + " , " + password + " , " + pravni_osnov + " , " + osnov + " , " + mbr + " , " + broj_dokumenta + " , " + organ_izdavanja + " , " + datum_izdavanja + " , " + datum_zastite
        privateSignature.update(stringZaPotpis.getBytes())

        byte[] signature = privateSignature.sign()
        String potpis = Base64.getEncoder().encodeToString(signature)

        println "potpis    " + potpis

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = [ new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null
            }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }
        ]

// Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL")
        sc.init(null, trustAllCerts, new java.security.SecureRandom())
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())

// Create all-trusting host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true
            }
        }

        // Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

        SOAPClient client = new SOAPClient("https://mupservis/servicev2/dokumenta-lk.php")
        //SOAPClient client = new SOAPClient()
        //client.httpClient.sslTrustStoreFile = publicSertifikat
        //client.httpClient.sslTrustStoreFile = privateKey
        //client.httpClient.sslTrustStorePassword ="123456789"
        //client.httpClient.sslTrustAllCerts = true
        SOAPResponse response = client.send(
                """<?xml version='1.0' encoding='UTF-8'?>
       <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:do="https://10.61.4.10/servicev2/dokumenta-lk.php">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
        <do:vratiDokumentLK SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <DokumentIN>
                <user>epeticija</user>
                <password>epet0812</password>
                <pravni_osnov>24</pravni_osnov>
                <osnov>24</osnov>
                <mbr>1703982210261</mbr>
                <broj_dokumenta>821049285</broj_dokumenta>
                <organ_izdavanja></organ_izdavanja>
                <datum_izdavanja>2010</datum_izdavanja>
                <datum_zastite></datum_zastite>
                <potpis>lrBsu4qFR2MVGjw9FAzSw7AGHzRQWX+cFmYhXxsiry9YyyflzIzkvCUJMJaga0aZsg3Qjqz5g0LPHkoy6BcV4gioFYVcMQiJBf+w0v6XligUAkqrbyquA2JKKTUaNLmp3OEpqbf9RQHY0zXCglczOjABv17GukMeBuKYMHrSOv24kToYfGDjlONk5CLYkWUvoHbodMV+alTS2elnF1iTFpR+8waZHhU/4gIGm/+BVdkY3iq+Cx2PsDVInYvonk/16GYOYbRdsa0uTtuDAmYpgFXZLYBVMlGFxKhA3ERDIcoqQ3tLLc4J42RVnE8HAmTe16lP7kUdxBmrvOrFoI7alg==</potpis>
            </DokumentIN>
        </do:vratiDokumentLK>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
        )

        render response

    }
}
