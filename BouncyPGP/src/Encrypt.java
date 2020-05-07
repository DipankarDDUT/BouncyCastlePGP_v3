import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

public class Encrypt {
	private static final BouncyCastleProvider provider = new BouncyCastleProvider();
	static {
		Security.addProvider(provider);
	}
	
	public static byte[] encrypt(final byte[] message, final PGPPublicKey publicKey, boolean armored)
			throws PGPException {
		try {
			final ByteArrayInputStream in = new ByteArrayInputStream(message);
			final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			final PGPLiteralDataGenerator literal = new PGPLiteralDataGenerator();
			final PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
			final OutputStream pOut = literal.open(comData.open(bOut), PGPLiteralData.BINARY, "filename",
					in.available(), new Date());
			Streams.pipeAll(in, pOut);
			comData.close();
			final byte[] bytes = bOut.toByteArray();
			final PGPEncryptedDataGenerator generator = new PGPEncryptedDataGenerator(
					new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true)
							.setSecureRandom(new SecureRandom())

							.setProvider(provider));
			generator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider(provider));
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			OutputStream theOut = armored ? new ArmoredOutputStream(out) : out;
			OutputStream cOut = generator.open(theOut, bytes.length);
			cOut.write(bytes);
			cOut.close();
			theOut.close();
			return out.toByteArray();
		} catch (Exception e) {
			throw new PGPException("Error in encrypt", e);
		}
	}

}
