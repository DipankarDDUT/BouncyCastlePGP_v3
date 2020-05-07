import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

public class Decrypt {
	private static final BouncyCastleProvider provider = new BouncyCastleProvider();
	static {
		Security.addProvider(provider);
	}
	protected static byte[] decrypt(byte[] encrypted, InputStream keyIn, char[] password)
			throws IOException, PGPException, NoSuchProviderException {

		InputStream decodeIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(encrypted));
		BcPGPObjectFactory pgpF = new BcPGPObjectFactory(decodeIn);
		decodeIn.close();

		PGPEncryptedDataList enc = null;
		Object o = pgpF.nextObject();

		if (o instanceof PGPEncryptedDataList) {
			enc = (PGPEncryptedDataList) o;
		} else {
			enc = (PGPEncryptedDataList) pgpF.nextObject();
		}

		PGPPrivateKey sKey = null;

		PGPPublicKeyEncryptedData pbe = null;
		PGPSecretKeyRingCollection pgpSec = new BcPGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));

		for (int i = 0; i < enc.size() && sKey == null; i++) {
			Object encryptedData = enc.get(i);

			pbe = (PGPPublicKeyEncryptedData) encryptedData;
			sKey = findSecretKey(pgpSec, pbe.getKeyID(), password);

		}

		if (sKey == null) {
			throw new IllegalArgumentException("secret key for message not found.");
		}

		BcPublicKeyDataDecryptorFactory pkdf = new BcPublicKeyDataDecryptorFactory(sKey);

		InputStream clear = pbe.getDataStream(pkdf);
		PGPObjectFactory pgpFact = new BcPGPObjectFactory(clear);

		PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();

		pgpFact = new BcPGPObjectFactory(cData.getDataStream());

		PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

		InputStream unc = ld.getInputStream();

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int ch;

		while ((ch = unc.read()) >= 0) {
			out.write(ch);

		}

		byte[] returnBytes = out.toByteArray();
		clear.close();
		out.close();
		unc.close();

		return returnBytes;

	}

	protected static byte[] decryptByte(String passphrase, String keyFile, byte[] encryptedBytes) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		FileInputStream secKey = new FileInputStream(keyFile);
		byte[] decrypted = decrypt(encryptedBytes, secKey, passphrase.toCharArray());

		return decrypted;
	}

	protected static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
			throws PGPException, NoSuchProviderException {
		PGPPrivateKey privateKey = null;
		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

		if (pgpSecKey == null) {
			return null;
		}
		privateKey = extractPrivateKey(pgpSecKey, pass);

		return privateKey;
	}
	private static PGPPrivateKey extractPrivateKey(PGPSecretKey pgpSecKey, char[] passPhrase) throws PGPException {
		PGPPrivateKey privateKey = null;
		BcPGPDigestCalculatorProvider calculatorProvider = new BcPGPDigestCalculatorProvider();
		BcPBESecretKeyDecryptorBuilder secretKeyDecryptorBuilder = new BcPBESecretKeyDecryptorBuilder(
				calculatorProvider);
		PBESecretKeyDecryptor pBESecretKeyDecryptor = secretKeyDecryptorBuilder.build(passPhrase);

		try {
			privateKey = pgpSecKey.extractPrivateKey(pBESecretKeyDecryptor);
		} catch (PGPException e) {
			throw new PGPException("invalid privateKey passPhrase: " + String.valueOf(passPhrase), e);
		}

		return privateKey;
	}

}
