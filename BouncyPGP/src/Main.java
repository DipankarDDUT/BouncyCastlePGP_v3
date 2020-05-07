import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import java.util.Scanner;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

public class Main {
	static final String passphrase = "passphrase";
	static Scanner sc = new Scanner(System.in);
	private static final BouncyCastleProvider provider = new BouncyCastleProvider();
	static {
		Security.addProvider(provider);
	}

	public static void main(String[] args) {

		try {
			ByteArrayInputStream in = new ByteArrayInputStream(
					"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: Keybase OpenPGP v1.0.0\nComment: https://keybase.io/crypto\n\nxo0EXqmUlAEEANDZakx/45HGTb083ITuK6lFJxbJ+oSqpUI8MsLkFJ8xa3k5d38Y\n5K7GhzPkRq7nKqWgtozHnYRICU7uthgYH7Ub7PDtICaPLlhZl0UgfefdjtqtiOy5\nzcT9iV6fYtdGggsxkKHuMYGkMEO3d7Pn1+eailhTR0nNqfzQwV6O9BXfABEBAAHN\nI2Fuc2h1bWFuIDxhbnNodXNhaWtpYTU1NUBnbWFpbC5jb20+wq0EEwEKABcFAl6p\nlJQCGy8DCwkHAxUKCAIeAQIXgAAKCRBSGbsSdOUnQ3hpBACd/yE4ROebqDvyt//H\nTvXosViYBOUAUdnpaPkmAGJd+uAuixN0uxoVamVfxclnFr7nTp9dZUkrPBqrclQu\nNw4zLeWwmGuO8DmdqE/vOL+g0k5OYV6hJPjsUBYTxZnjLvfxLEPNYRZl0M2cvdkN\njYTl6xTQDsN1f2e7G22LSo3rYM6NBF6plJQBBADd6sGHfIcAdSUm7SVLOW6A5LuK\n2s0Xm28EKktiqKWiIIhh9qDnpq/k2KV9oI6JjwMDmknYpxvLUYUtUZKCQu94T/C0\nwbXDwIL9nbBNvctL1BOgkQ1uwa13g/ZABTrE8LIRTj1Inm6GHSozGwCfthMcvV2+\nk4BEWou5gzd3XvKXDwARAQABwsCDBBgBCgAPBQJeqZSUBQkPCZwAAhsuAKgJEFIZ\nuxJ05SdDnSAEGQEKAAYFAl6plJQACgkQjIjDc1W7DoN7IQP/bQX9ANDro8YqKk2g\ndEpTJ2QEJjNaP4L7NWK28vVSS7fZKGjAeeW2K+djAM6/uT4gswfKxb4CeIstNHOb\nkuepp0X6gsjHf6l1yUS8AR1+Gg//mQBBTxPop9L47uZB7z3T3Zb3iKK5P1wzGBoI\nqlamvliWRvmjbK4kaRXEJmtb9nCMXwP+OEQppUAwF+iDkJII7eqzisbJkn1yNEF1\nMIOANVj46iDuBXs7LWQ/+ynwNJ9M3e+pY+O08YADxKsJiKgieELn8k7/Paa2CJq1\nj/63UGwTeMogZ5RP6M68+sKUupIYkPpbuZIxu7v7NEPNyUVRB1Wtlay1OBE3XTyR\nb/46LrymUZnOjQReqZSUAQQA93mMeM+utNgJZCoo1Qv0wpys8ZTtKCthdyKO79ko\nJM+B7YDPDErJqyKPrTCSfkmqB36qZQ8BnrA2EdLi0DCS1mu4QKcSjfZMWAbOGgNs\nBzsREWTF0pcXS8rm4dUGzLZjKxXJmVozBYzkoDSRugFzyM30VZUhfRU7Vv947I25\nGfcAEQEAAcLAgwQYAQoADwUCXqmUlAUJDwmcAAIbLgCoCRBSGbsSdOUnQ50gBBkB\nCgAGBQJeqZSUAAoJEBc4xQjQ4FgFpCAD/1Tsy/HBLteXGHSEF8KElYP1iDSgMoFO\ngtXbbQQ/5CSAld4GVrbaJ7S1LbFAux4OY6wsPNgzUyK7FxhCuJ46dLlIoXg7QGQj\nJ66pikUyPG9mkRJQc2Bu4VOpkyQp7YpTNjlwtJKmZwSyDzCEVikSKvUB/syqvqtf\nD+bMFWIsA3RvWL4EALtXT/o9RpWp7WzoVz6MFUT1b1T1jr5CWGhOuFrNgbtKAU62\nC4d2nGoajdtr/eWoDXQy5IKbB/GLAOSzff2LiATTOzjxcNlA/7qn1HJH6csfrL/o\nYK/8AAmvDp/n4N4L1TFIgAkc8hv8eHAhFQrPGNHVd0+t4ypYkfyLdLIpt6XZ\n=AC7c\n-----END PGP PUBLIC KEY BLOCK-----"
							.getBytes());
			PGPPublicKey publicKey = readPublicKey(in);
			System.out.println("Enter the message");
			String str = sc.nextLine();
			byte[] byteArr = str.getBytes();

			String s = new String(byteArr);
			// Encryption
			Encrypt e = new Encrypt();
			System.out.println("-----------------------------------\noriginal message: " + s);
			byte[] byteArr1 = e.encrypt(byteArr, publicKey, true);
			String s1 = new String(byteArr1);
			System.out.println("-----------------------------\nencrypted message\n" + s1);

			ByteArrayInputStream secKey = new ByteArrayInputStream(
					"-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: Keybase OpenPGP v1.0.0\nComment: https://keybase.io/crypto\n\n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\n8hv8eHAhFQrPGNHVd0+t4ypYkfyLdLIpt6XZ\n=wVgO\n-----END PGP PRIVATE KEY BLOCK-----"
							.getBytes());
			String sec = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: Keybase OpenPGP v1.0.0\nComment: https://keybase.io/crypto\n\n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\n8hv8eHAhFQrPGNHVd0+t4ypYkfyLdLIpt6XZ\n=wVgO\n-----END PGP PRIVATE KEY BLOCK-----";
			// Decryption
			Decrypt d = new Decrypt();
			byte[] decrypted = d.decrypt(byteArr1, secKey, "passphrase".toCharArray());

			System.out.println("---------------------------\ndecrypted data = '" + new String(decrypted) + "'");
			InputStream result = new ByteArrayInputStream(sec.getBytes(StandardCharsets.UTF_8));
			PGPSecretKey privatekey = readSecretKey(result);

			PGPPrivateKey k = extractPrivateKey(privatekey, "passphrase".toCharArray());

			// Sign
			Sign a = new Sign();

			byte[] signed_message = a.sign(byteArr, privatekey, passphrase, false);
			System.out.println("SignedMessage\n" + signed_message);
			
			
			String decoded = new String(signed_message, "ISO-8859-1");
		    System.out.println("decoded:" + decoded);

		    byte[] encoded = decoded.getBytes("ISO-8859-1"); 
		   // System.out.println("encoded:" + java.util.Arrays.toString(encoded));

		   // String decryptedText = encrypter.decrypt(encoded);
			
			
			
			
			
			String sig=new String(signed_message);
			//byte[] bbb=sig.getBytes();
			//System.out.println(sig);
//			String p="[B@e01a26b£xœ›ÀËÌÀÄ$¹[¨ä©º3ãiÁ$Ž´ÌœÔ¼ÄÜÔ¸ÍkL‹S;²0021h³2?TdóŠ3JsólÀ¬âÄÌìÌDSSS‡ôÜÄÌ½äü\\.N˜‘mÚÌÿÓ&ßâhqˆ÷²?Wý$0lù}§?—Df|·»ÿÞ·%TÒâmäåhÞçÂ¯æ½»mkôaföËÕ¦“Ož™õ4lž»p÷S¶?+IªVZ÷+½]}M Îd«î¬NËÞ?ûœNj¯É®ž½Ôáý*é‡½ÝßýZ#ìÒMÝ4°†{±\–Õž¿ë‡";
			// verify
			Verify b = new Verify();
			boolean x = b.verify(encoded, publicKey);
			System.out.println("Verification\n" + x);
		} catch (PGPException e) {
			System.out.println(e.toString());
			System.out.println(e.getUnderlyingException().toString());

		} catch (Exception e) {
			System.out.println(e.toString());
		}
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

	static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException {
		InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
		PGPPublicKey pubKey = readPublicKey(keyIn);
		keyIn.close();
		return pubKey;
	}

	static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input),
				new JcaKeyFingerprintCalculator());
		Iterator keyRingIter = pgpPub.getKeyRings();
		while (keyRingIter.hasNext()) {
			PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();

			Iterator keyIter = keyRing.getPublicKeys();
			while (keyIter.hasNext()) {
				PGPPublicKey key = (PGPPublicKey) keyIter.next();

				if (key.isEncryptionKey()) {
					return key;
				}
			}
		}

		throw new IllegalArgumentException("Can't find encryption key in key ring.");
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

	static PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input),
				new JcaKeyFingerprintCalculator());

		Iterator keyRingIter = pgpSec.getKeyRings();
		while (keyRingIter.hasNext()) {
			PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

			Iterator keyIter = keyRing.getSecretKeys();
			while (keyIter.hasNext()) {
				PGPSecretKey key = (PGPSecretKey) keyIter.next();

				if (key.isSigningKey()) {
					return key;
				}
			}
		}

		throw new IllegalArgumentException("Can't find signing key in key ring.");
	}

}
