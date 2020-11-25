package soapws

import wslite.soap.SOAPClient
import wslite.soap.SOAPResponse

class NetservisController {

    String servis1 = "http://localhost/dokumenta.asmx"
    String servis1akcija = "http://localhost/dokumenta.asmx/LK"
    String servis2 = "http://localhost/dokumenta.asmx"
    String servis2akcija = "http://localhost/dokumenta.asmx/licnakarta"

    def index() {
        SOAPClient client = new SOAPClient("${servis1}?wsdl")
        SOAPResponse response = client.send(SOAPAction: servis1akcija) {
            body('xmlns': 'http://schemas.xmlsoap.org/wsdl/soap/') {
                LK {

                }
            }
        }
        render response
    }

    def index2() {
        SOAPClient client = new SOAPClient("${servis2}?wsdl")
        SOAPResponse response = client.send(SOAPAction: servis2akcija) {
            body('xmlns': 'http://schemas.xmlsoap.org/wsdl/soap/') {
                licnakarta {
                    ime("Ivo")
                    prezime("Minic")
                    jmb("1703982210261")
                    brDoc("821049285")
                }
            }
        }
        render response
    }


    def envelop() {
        SOAPClient client = new SOAPClient(servis1akcija)
        SOAPResponse response = client.send(
                """<?xml version='1.0' encoding='UTF-8'?>
       <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:do="http://localhost/dokumenta.asmx">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
        <do:LK SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
        </do:LK>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
        )
        render response
    }

    def envelop2() {
        SOAPClient client = new SOAPClient(servis1)
        SOAPResponse response = client.send(SOAPAction: "LK",
                """<?xml version='1.0' encoding='UTF-8'?>
       <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:do="http://localhost/dokumenta.asmx/LK">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
        <do:LK SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
        </do:LK>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
        )
        render response
    }

    def envelop3() {
        SOAPClient client = new SOAPClient(servis1akcija)
        SOAPResponse response = client.send(
                """<?xml version='1.0' encoding='UTF-8'?>
       <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:do="http://localhost/dokumenta.asmx/LK">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
        <do:LK SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
        </do:LK>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""
        )
        render response
    }


    def treci() {
        SOAPClient client = new SOAPClient("${servis1}?wsdl")
        def members = LK(client).results
        render members.toString()
    }



    def cetvrti() {
        SOAPClient client = new SOAPClient("${servis1}?wsdl")
        SOAPResponse response = client.send(SOAPAction: servis1akcija) {
            body('xmlns': 'http://schemas.xmlsoap.org/wsdl/soap/') {
                LK {
                }
            }
        }
    }

    def peto() {
        SOAPClient client = new SOAPClient("${servis1}?wsdl")
        SOAPResponse response = client.send(SOAPAction: servis1akcija) {
            body('xmlns': 'http://schemas.xmlsoap.org/wsdl/soap/') {
                licnakarta {
                }
            }
        }
    }
}
