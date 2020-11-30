package soapws

import wslite.soap.SOAPClient
import wslite.soap.SOAPResponse

class HttppozivController {

    String servis1 = "http://www.dneonline.com/calculator.asmx"
    String servis1wsdl = "http://www.dneonline.com/calculator.asmx?wsdl"
    String servis1akcija = "http://www.dneonline.com/calculator.asmx?op=Add"
    String servis2wsdl = "http://localhost/dokumenta.asmx?wsdl"

    def index() {
        SOAPClient client = new SOAPClient(servis2wsdl)
        SOAPResponse response = client.send(
                """<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
    xmlns:ns0="http://tempuri.org/">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
        <ns0:licnakarta>
            <ns0:ime>Ivo</ns0:ime>
            <ns0:prezime>Minić</ns0:prezime>
            <ns0:jmb>1703982210261</ns0:jmb>
            <ns0:brDoc>821049285</ns0:brDoc>
        </ns0:licnakarta>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
        )
        println " response body 1   " + response.getBody()
        render response.getBody().toString()

    }

    def index2() {
        SOAPClient client = new SOAPClient(servis2wsdl)
        SOAPResponse response = client.send(
                """<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
    xmlns:ns0="http://tempuri.org/">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
        <ns0:LK>
        </ns0:LK>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
        )

        println " response body 2   " + response.getBody()
        render response.getBody().toString()

    }


    ///OVAJ RADI!!!!!
    def soap() {
        SOAPClient client = new SOAPClient(servis1wsdl)

        SOAPResponse response = client.send(
                """<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
    xmlns:ns0="http://tempuri.org/">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
        <ns0:Add>
            <ns0:intA>2</ns0:intA>
            <ns0:intB>3</ns0:intB>
        </ns0:Add>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
        )

        println response.getBody()

        render response.getBody()

    }

    def postovanje(){
        SOAPClient client = new SOAPClient(servis1wsdl)

        SOAPResponse response = client.send(
                """<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
    xmlns:ns0="http://tempuri.org/">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
        <ns0:licnakarta>
            <ns0:intA>2</ns0:intA>
            <ns0:intB>3</ns0:intB>
        </ns0:licnakarta>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
        )

        println response.getBody()

        render response.getBody()
    }


    def poziv() {
        String memberStateCode = "0"
        String vatNumberCode = "0"
        SOAPClient client = new SOAPClient(servis1wsdl)

        SOAPResponse response = client.send() {
            body('xmlns': "http://www.dneonline.com/calculator.asmx/Add") {
                Add {
                    intA(11)
                    intB(11)
                }
            }
        }
        render response
    }


//    def poziv() {
//        String memberStateCode = "0"
//        String vatNumberCode = "0"
//        String url = 'http://ec.europa.eu/taxation_customs/vies/services/checkVatService'
//        SOAPClient client = new SOAPClient("${url}.wsdl")
//
//        SOAPResponse response = client.send(SOAPAction: url) {
//            body('xmlns': 'urn:ec.europa.eu:taxud:vies:services:checkVat:types') {
//                checkVat {
//                    countryCode(memberStateCode)
//                    vatNumber(vatNumberCode)
//                }
//            }
//        }
//        response.checkVatResponse.valid.text() == 'true'
//    }
}
