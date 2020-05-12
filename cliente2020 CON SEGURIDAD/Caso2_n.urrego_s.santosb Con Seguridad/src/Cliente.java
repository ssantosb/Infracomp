import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Cliente extends Thread{

	public final static String SERVIDOR="172.24.99.58";
	public final static int PUERTO=3400;
	private X509Certificate certificado;
	private X509Certificate certificadoServidor;
	private byte[] mybyte;
	private SecretKey llave;
	private KeyPair par;
	private static Scanner sc =  new Scanner(System.in);;
	public static final String HOLA = "HOLA";
	public static final String OK = "OK";
	public static final String ERROR = "ERROR";
	public static final String ALGORITMOS = "ALGORITMOS";
	public static final String AES = "AES";
	public static final String RSA = "RSA";
	public static final String HMACSHA512 = "HMACSHA512";

	public void run(){

		System.out.println("CLIENTE: Inici� su ejecuci�n");
		PrintWriter pw=null;
		BufferedReader br=null;
		Socket socket=null;

		try{

			Security.addProvider((Provider)new BouncyCastleProvider());
			
			System.out.println("CLIENTE: Conectando al servidor "+SERVIDOR+" en el puerto "+PUERTO);
			socket = new Socket(SERVIDOR,PUERTO);
			pw=new PrintWriter(socket.getOutputStream(),true);
			br=new BufferedReader(new InputStreamReader(socket.getInputStream()));

			pw.println(HOLA);

			String linea = null;

			linea = br.readLine();

			if(linea.equals(OK)){

				pw.println(ALGORITMOS + ":" + AES + ":" + RSA + ":" + HMACSHA512);
				System.out.println("CLIENTE: Se enviaron los algoritmos al servidor");

				linea = br.readLine();

				System.out.println("CLIENTE: Recibi�  del servidor: " + linea);

				if(linea.equals("OK")){

					KeyPairGenerator kpGen = KeyPairGenerator.getInstance(RSA);
					kpGen.initialize(1024, new SecureRandom());
					par = kpGen.generateKeyPair();
					certificado = gc(par);

					this.mybyte = new byte[520];

					this.mybyte = certificado.getEncoded();

					String strCerCli = toHexString(this.mybyte);
					pw.println(strCerCli);

					linea = br.readLine();
					System.out.println("CLIENTE: Recibi� del servidor: " + linea);

					if(linea.equals("OK")){
						
						linea = br.readLine();

						String strCerServidor = linea;
						byte[] certServidor = new byte[520];
						certServidor = toByteArray(strCerServidor);

						CertificateFactory creador = CertificateFactory.getInstance("X.509");					
						InputStream in = new ByteArrayInputStream(certServidor);
						certificadoServidor = (X509Certificate)creador.generateCertificate(in);

						System.out.println("CLIENTE: Recibi� certificado servidor");
						pw.println("OK");	
						linea = br.readLine();

						byte[] ciphertext1 = toByteArray(linea);
						byte[] llaveSimetrica = ad(ciphertext1,par.getPrivate(),RSA);			       
						llave = new SecretKeySpec(llaveSimetrica, 0, llaveSimetrica.length, AES); 

						byte[] ba;
						//Leo el reto
						linea=br.readLine();
						byte[] reto = toByteArray(linea);
						byte[] retoD = sd(reto, llave, AES);
						byte[] retoEncrip = ae(retoD, certificadoServidor.getPublicKey(), RSA);
						pw.println(toHexString(retoEncrip));

						Cipher cifradorAES=Cipher.getInstance(AES);
						cifradorAES.init(Cipher.DECRYPT_MODE, llave);
						System.out.println("CLIENTE: Envi� el reto-" + toHexString(retoEncrip) + "-continuando.");
						
						linea = br.readLine();

						System.out.println("CLIENTE: Recibi� del servidor: " + linea);
						if(linea.equals(OK)){
							//Etapa 3
							//Env�o el idUsuario
							System.out.println("Por favor ingrese el idUsuario a enviar:");
							String id = DatatypeConverter.printBase64Binary(se(leerConsola().getBytes(), llave, AES));
							pw.println(id);
							System.out.println("CLIENTE: Envi� idUsuario-" + id + "-continuando.");
							//Leo el valor que me envi� el servidor (hhmm)
							String hhmm=br.readLine();
							cifradorAES=Cipher.getInstance(AES);
							cifradorAES.init(Cipher.DECRYPT_MODE, llave);
							ba=cifradorAES.doFinal(DatatypeConverter.parseBase64Binary(hhmm));
							String valorFinalHhmm =DatatypeConverter.printBase64Binary(ba);
							System.out.println("CLIENTE: Recibi� hhmm-" + valorFinalHhmm + "-continuando.");
							pw.println(OK);
							System.out.println("CLIENTE: Envi� confirmaci�n");
						}
					}
				}
			}

			pw.close();
			br.close();
			socket.close();


		}
		catch(Exception e){
			System.out.println("CLIENTE: Se ha producido un error, interrumpiendo conexi�n");
			pw.close();
			try {
				br.close();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			try {
				socket.close();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

			e.printStackTrace();
		}
		System.out.println("CLIENTE: Termin� su ejecuci�n");
	}

	public static byte[] se(byte[] msg, Key key, String algo) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		algo = algo + (!algo.equals("DES") && !algo.equals("AES") ? "" : "/ECB/PKCS5Padding");
		Cipher decifrador = Cipher.getInstance(algo);
		decifrador.init(1, key);
		return decifrador.doFinal(msg);
	}

	public static byte[] sd(byte[] msg, Key key, String algo) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		algo = algo + (!algo.equals("DES") && !algo.equals("AES") ? "" : "/ECB/PKCS5Padding");
		Cipher decifrador = Cipher.getInstance(algo);
		decifrador.init(2, key);
		return decifrador.doFinal(msg);
	}

	public static byte[] ae(byte[] msg, Key key, String algo) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher decifrador = Cipher.getInstance(algo);
		decifrador.init(1, key);
		return decifrador.doFinal(msg);
	}

	public static byte[] ad(byte[] msg, Key key, String algo) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher decifrador = Cipher.getInstance(algo);
		decifrador.init(2, key);
		return decifrador.doFinal(msg);
	}

	public static X509Certificate gc(KeyPair keyPair) throws OperatorCreationException, CertificateException {

		Calendar endCalendar = Calendar.getInstance();
		endCalendar.add(1, 10);
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(new X500Name("CN=localhost"), BigInteger.valueOf(1L), Calendar.getInstance().getTime(), endCalendar.getTime(), new X500Name("CN=localhost"), SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
		ContentSigner contentSigner = (new JcaContentSignerBuilder("SHA1withRSA")).build(keyPair.getPrivate());
		X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);

		return (new JcaX509CertificateConverter()).setProvider("BC").getCertificate(x509CertificateHolder);

	}

	public static String toHexString(byte[] array) {
		return DatatypeConverter.printBase64Binary(array);
	}

	public static byte[] toByteArray(String s) {
		return DatatypeConverter.parseBase64Binary(s);
	}

	public static String leerConsola() throws IOException
	{
		return ""+Math.random()*1000;
	}




}
