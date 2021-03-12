package es.upm.dit.pruebas;

import java.io.File;
import java.io.IOException;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class Validation {
	
	public static void main(String[] args) throws DSSException, IOException {
		
		//CertificateSource keystoreCertSource = new KeyStoreCertificateSource(new File("D:/TFM/PrivateKeys/identity.p12"), "PKCS12", "123456");
		//CertificateSource adjunctCertSource = new KeyStoreCertificateSource(new File("D:/TFM/PrivateKeys/identity.p12"), "PKCS12", "123456");
		
		
		// First, we need a Certificate verifier
		CertificateVerifier cv = new CommonCertificateVerifier();

		// We can inject several sources. eg: OCSP, CRL, AIA, trusted lists

		// Capability to download resources from AIA
		cv.setDataLoader(new CommonsDataLoader());

		// Capability to request OCSP Responders
		cv.setOcspSource(new OnlineOCSPSource());

		// Capability to download CRL
		cv.setCrlSource(new OnlineCRLSource());
		
		


		// Create an instance of a trusted certificate source
		//CommonTrustedCertificateSource certSource = new CommonTrustedCertificateSource();
		//certSource.addCertificate(DSSUtils.loadCertificate(new File("D:/TFM/root-ca.cer")));
		//cv.setTrustedCertSources(certSource);
		
		// import the keystore as trusted
		//trustedCertSource.importAsTrusted(keystoreCertSource);

		// Add trust anchors (trusted list, keystore,...) to a list of trusted certificate sources
		// Hint : use method {@code CertificateVerifier.setTrustedCertSources(certSources)} in order to overwrite the existing list
		//cv.addTrustedCertSources(trustedCertSource);

		// Additionally add missing certificates to a list of adjunct certificate sources
		//cv.addAdjunctCertSources(adjunctCertSource);

		// Here is the document to be validated (any kind of signature file)
		DSSDocument document = new FileDocument("D:/TFM/signedFileDNI");

		// We create an instance of DocumentValidator
		// It will automatically select the supported validator from the classpath
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);

		// We add the certificate verifier (which allows to verify and trust certificates)
		documentValidator.setCertificateVerifier(cv);

		// Here, everything is ready. We can execute the validation (for the example, we use the default and embedded
		// validation policy)
		Reports reports = documentValidator.validateDocument();

		// We have 3 reports
		// The diagnostic data which contains all used and static data
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		// The detailed report which is the result of the process of the diagnostic data and the validation policy
		DetailedReport detailedReport = reports.getDetailedReport();

		// The simple report is a summary of the detailed report (more user-friendly)
		SimpleReport simpleReport = reports.getSimpleReport();
		
		reports.print();
	}

}
