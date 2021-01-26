package es.upm.dit.pruebas;
import java.io.IOException;
import java.security.KeyStore;
import java.util.List;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;


public class SignXmlXadesB {

	public static void main(final String[] args) throws DSSException, IOException {
		// Preparing parameters for the XAdES signature
		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		// We choose the level of the signature (-B, -T, -LT, -LTA).
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		// We choose the type of the signature packaging (ENVELOPED, ENVELOPING, DETACHED).
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		// We set the digest algorithm to use with the signature algorithm. You must use the
		// same parameter when you invoke the method sign on the token. The default value is SHA256
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		
		Pkcs12SignatureToken signingToken= new Pkcs12SignatureToken("src/main/resources/identity.p12", new KeyStore.PasswordProtection("123456".toCharArray()));
		
		List<DSSPrivateKeyEntry> keys = signingToken.getKeys();
		DSSPrivateKeyEntry privateKey = null;
		for (DSSPrivateKeyEntry entry : keys) {
		    privateKey = entry;
		    break;
		}
		// We set the signing certificate
		parameters.setSigningCertificate(privateKey.getCertificate());
		// We set the certificate chain
		parameters.setCertificateChain(privateKey.getCertificateChain());

		// Create common certificate verifier
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

		// Create XAdES service for signature
		XAdESService service = new XAdESService(commonCertificateVerifier);
		
		
		DSSDocument toSignDocument = new FileDocument("src/main/resources/xml_example.xml");
		// Get the SignedInfo XML segment that need to be signed.
		ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

		// This function obtains the signature value for signed information using the
		// private key and specified algorithm
		SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);

		// We invoke the service to sign the document with the signature value obtained in
		// the previous step.
		DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
		
        signedDocument.save("target/xml_example_signed.xml");
		String same = signedDocument.getName();
		System.out.println(same);
	}
}
