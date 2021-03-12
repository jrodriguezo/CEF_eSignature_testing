package es.upm.dit.pruebas;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.util.Base64;
import java.util.List;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.MSCAPISignatureToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;


public class SignXmlXadesB {

	public static void main(String[] args) throws DSSException, IOException {

		try (MSCAPISignatureToken token = new MSCAPISignatureToken()) {

			List<DSSPrivateKeyEntry> keys = token.getKeys();
			for (DSSPrivateKeyEntry entry : keys) {
				System.out.println(entry.getCertificate().getCertificate());
			}

			ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes());
			SignatureValue signatureValue = token.sign(toBeSigned, DigestAlgorithm.SHA256, keys.get(0));

			System.out.println("Signature value : " + Utils.toBase64(signatureValue.getValue()));
		}
	}

}
