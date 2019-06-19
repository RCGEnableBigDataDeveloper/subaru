package com.subaru.udf;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

/**
 * @author rcggs
 *
 *
 */
public class EncryptDecryptUtil {
	final static Logger logger = LoggerFactory.getLogger(EncryptDecryptUtil.class);

	private static final String TMP_SUFFIX = "secret";
	private static final String TMP_PREFIX_SECRETKEY = "key";
	private static final String EMPTY_STRING = "";
	private static final String DES = "DES";
	private static final String DES_ECB_PKCS5_PADDING = "DES/ECB/PKCS5Padding";
	private static final String UTF_8 = "UTF-8";
	
	private static SecretKey key;

	/**
	 * Constructor
	 */
	static {
		
		try {
			key = readKeyFromStream(EncryptDecryptUtil.class.getResourceAsStream("/datalake.key"));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Method to encrypt the plain text password.
	 * 
	 * @param key      the {@link SecretKey}.
	 * @param password the plan text password to encode.
	 * @return String the encrypted password.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static String encrypt(final String password)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance(DES_ECB_PKCS5_PADDING);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] stringBytes = password.getBytes(UTF_8);
		byte[] raw = cipher.doFinal(stringBytes);
		Base64 encoder = new Base64();
		String base64 = encoder.encodeToString(raw).trim();

		return base64;

	};

	/**
	 * @param filename
	 * @param plainTextPassword
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 */
	public static String encrypt(final String filename, final String plainTextPassword)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, IOException {
		return encrypt(plainTextPassword);
	}

	/**
	 * Method to decrypt the encrypted password.
	 * 
	 * @param key               the {@link SecretKey}.
	 * @param encryptedPassword the encrypted password.
	 * @return String the decrypted password.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	public static String decrypt(SecretKey key, final String encryptedPassword)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {
		Cipher cipher = Cipher.getInstance(DES_ECB_PKCS5_PADDING);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] raw = Base64.decodeBase64(encryptedPassword);
		byte[] stringBytes = cipher.doFinal(raw);
		String decryptedPassword = new String(stringBytes, UTF_8);
		return decryptedPassword;
	}

	/**
	 * Method to decrypt password from password key file and password file.
	 *
	 * @param secretKeyFileName
	 * @param encryptedPassword
	 * @return
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 */
	public static String decrypt(String encryptedPassword)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, ParserConfigurationException, SAXException {
		//SecretKey key = readKeyFromFile(secretKeyFileName);

		if (encryptedPassword != null && !EMPTY_STRING.equals(encryptedPassword)) {
			return decrypt(key, encryptedPassword);
		}
		return encryptedPassword;
	}

	public static String decrypt(InputStream is, String encryptedPassword)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, ParserConfigurationException, SAXException {
		//SecretKey key = readKeyFromStream(is);

		if (encryptedPassword != null && !EMPTY_STRING.equals(encryptedPassword)) {
			return decrypt(key, encryptedPassword);
		}
		return encryptedPassword;
	}

	/**
	 * Method to validate supplied password with the stored password.
	 * 
	 * @param suppliedPassword  the input password
	 * @param secretKeyFileName the secret key file name.
	 * @param passwordFileName  the password file name
	 * @return boolean true if password matches otherwise false.
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 */
	public static boolean isPasswordValid(String suppliedPassword, String secretKeyFileName, String passwordFileName)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, IOException, ParserConfigurationException, SAXException {
		String decryptedPassword = decrypt( passwordFileName);
		if (suppliedPassword != null && decryptedPassword != null) {
			return suppliedPassword.equals(decryptedPassword);
		} else {
			return false;
		}
	}

	/**
	 * Method to generate the secret key using Data Encryption Standard (DES)
	 * 
	 * @return {@link SecretKey} key.
	 * @throws NoSuchAlgorithmException
	 */
	public static SecretKey generateKey() throws NoSuchAlgorithmException {
		KeyGenerator generator;
		generator = KeyGenerator.getInstance(DES);
		generator.init(new SecureRandom());
		return generator.generateKey();
	}

	/**
	 * Method to generate {@link SecretKey} and put in a given file.
	 * 
	 * @param key  the {@link SecretKey}
	 * @param file the file to write the secret key into.
	 * @throws IOException.
	 * @throws NoSuchAlgorithmException
	 */
	public static void generatePasswordKeyFile(SecretKey key, File file) throws IOException, NoSuchAlgorithmException {
		if (key == null) {
			key = generateKey();
		}
		byte[] keyBytes = key.getEncoded();
		char[] hex = Hex.encodeHex(keyBytes);
		String data = String.valueOf(hex);
		FileUtils.writeStringToFile(file, data);
	}

	/**
	 * @param fileName
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static void generatePasswordKeyFile(String fileName) throws NoSuchAlgorithmException, IOException {
		File file = new File(fileName);
		SecretKey key = generateKey();
		generatePasswordKeyFile(key, file);
	}

	/**
	 * Method to read the {@link SecretKey} from a given file.
	 * 
	 * @param file the file to read the secret key from.
	 * @return {@link SecretKey} the key.
	 * @throws IOException
	 */
	public static SecretKey readKeyFromFile(File file) throws IOException {
		String stringKey = new String(FileUtils.readFileToByteArray(file));
		char[] hex = stringKey.toCharArray();
		byte[] encoded;
		try {
			encoded = Hex.decodeHex(hex);
		} catch (DecoderException e) {
			e.printStackTrace();
			return null;
		}
		SecretKey secretKey = new SecretKeySpec(encoded, DES);
		return secretKey;
	}

	/**
	 * Method to read the {@link SecretKey} from a given file.
	 * 
	 * @param file the String file name.
	 * @return {@link SecretKey} the key.
	 * @throws IOException
	 */
	public static SecretKey readKeyFromFile(String file) throws IOException {
// Read the file
		InputStream fis = new FileInputStream(file);
		return getKey(fis);
	}

	public static SecretKey readKeyFromStream(final InputStream fis) throws IOException {
		return getKey(fis);
	}

	private static SecretKey getKey(final InputStream fis) throws IOException {
		final File tempFile = File.createTempFile(TMP_PREFIX_SECRETKEY, TMP_SUFFIX);
// Delete temp file on exit
		tempFile.deleteOnExit();
		OutputStream fos = new FileOutputStream(tempFile);
		IOUtils.copy(fis, fos);
		String stringKey = new String(FileUtils.readFileToByteArray(tempFile));
		char[] hex = stringKey.toCharArray();
		byte[] encoded;
		try {
			encoded = Hex.decodeHex(hex);
		} catch (DecoderException e) {
			e.printStackTrace();
			return null;
		}
		SecretKey secretKey = new SecretKeySpec(encoded, DES);
		return secretKey;
	}

	public static void main(String[] args)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, IOException, ParserConfigurationException, SAXException {
//		String pwd = encrypt("D:\\Users\\vxeperle\\eclipse-workspace\\subaru-hive\\src\\datalake.key", "adminuser");
//		String decryptedPwd = decrypt("D:\\Users\\vxeperle\\eclipse-workspace\\subaru-hive\\src\\datalake.key",
//				"rGd3bl/dGQe64CRnzKwXcw==");
//		logger.info(pwd);
//		System.err.println(pwd);
//		System.err.println(decryptedPwd);
		
		String pwd = EncryptDecryptUtil.encrypt(String.valueOf("JF2SJADC9GH490774"));
		System.err.println(pwd);
		
		String dpwd =EncryptDecryptUtil.decrypt("nOljFapPvwFRq8HTSw2L+wGnG0Dcc3Y5");
		System.err.println(dpwd);

	}
}
