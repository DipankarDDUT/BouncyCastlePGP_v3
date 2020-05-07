import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

public class Verify {

	private static final BouncyCastleProvider provider = new BouncyCastleProvider();
	static {
		Security.addProvider(provider);
	}

	public static boolean verify(byte[] signedMessage, PGPPublicKey publicKey) throws PGPException {
		try {
			InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(signedMessage));

			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);

			PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();

			pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

			PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();

			PGPOnePassSignature ops = p1.get(0);

			PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

			InputStream dIn = p2.getInputStream();
			int ch;
//System.out.print("dadsdsad"); used for testing

			ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider(provider), publicKey);

			while ((ch = dIn.read()) >= 0) {
				ops.update((byte) ch);
			}

			PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

			if (ops.verify(p3.get(0))) {
				return true;
			} else {
				return false;
			}
		} catch (Exception e) {
			throw new PGPException("Error in verify", e);
		}
	}

}
