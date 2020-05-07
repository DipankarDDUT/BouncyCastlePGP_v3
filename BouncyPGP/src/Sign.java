import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class Sign {
	private static final BouncyCastleProvider provider = new BouncyCastleProvider();
	static {
		Security.addProvider(provider);
	}
	 public static byte[] sign( byte[] message, PGPSecretKey secretKey, String secretPwd, boolean armor )
	            throws PGPException
	    {
	        try
	        {
	            ByteArrayOutputStream out = new ByteArrayOutputStream();
	            OutputStream theOut = armor ? new ArmoredOutputStream( out ) : out;

	            PGPPrivateKey pgpPrivKey = secretKey.extractPrivateKey(
	                    new JcePBESecretKeyDecryptorBuilder().setProvider( provider ).build( secretPwd.toCharArray() ) );
	            PGPSignatureGenerator sGen = new PGPSignatureGenerator(
	                    new JcaPGPContentSignerBuilder( secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1 )
	                            .setProvider( provider ) );

	            sGen.init( PGPSignature.BINARY_DOCUMENT, pgpPrivKey );

	            Iterator it = secretKey.getPublicKey().getUserIDs();
	            if ( it.hasNext() )
	            {
	                PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

	                spGen.setSignerUserID( false, ( String ) it.next() );
	                sGen.setHashedSubpackets( spGen.generate() );
	            }

	            PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator( PGPCompressedData.ZLIB );

	            BCPGOutputStream bOut = new BCPGOutputStream( cGen.open( theOut ) );

	            sGen.generateOnePassVersion( false ).encode( bOut );

	            PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
	            OutputStream lOut =
	                    lGen.open( bOut, PGPLiteralData.BINARY, "filename", new Date(), new byte[4096] );         //
	            InputStream fIn = new ByteArrayInputStream( message );
	            int ch;

	            while ( ( ch = fIn.read() ) >= 0 )
	            {
	                lOut.write( ch );
	                sGen.update( ( byte ) ch );
	            }

	            lGen.close();

	            sGen.generate().encode( bOut );

	            cGen.close();

	            theOut.close();

	            return out.toByteArray();
	        }
	        catch ( Exception e )
	        {
	            throw new PGPException( "Error in sign", e );
	        }
	    }



}
