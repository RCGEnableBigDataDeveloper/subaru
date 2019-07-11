/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.soa.processors.sample;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.io.IOUtils;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.io.InputStreamCallback;
import org.apache.nifi.processor.io.OutputStreamCallback;
import org.apache.nifi.processor.util.StandardValidators;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;

import org.apache.commons.lang3.StringUtils;
@Tags({ "soa encryptor with json input" })
@CapabilityDescription("Provide a description")
@SeeAlso({})
@ReadsAttributes({ @ReadsAttribute(attribute = "", description = "") })
@WritesAttributes({ @WritesAttribute(attribute = "", description = "") })
public class MyProcessor extends AbstractProcessor {

	public static final PropertyDescriptor MY_PROPERTY = new PropertyDescriptor.Builder().name("MY_PROPERTY")
			.displayName("My property2").description("Example2 Property").required(false)
			.addValidator(StandardValidators.NON_EMPTY_VALIDATOR).build();

	private List<PropertyDescriptor> descriptors;// properties

	private Set<Relationship> relationships;

	public static final String MATCH_ATTR = "match";

	public static final PropertyDescriptor JSON_PATH = new PropertyDescriptor.Builder().name("Json Path").required(true)
			.defaultValue("VIN").addValidator(StandardValidators.NON_EMPTY_VALIDATOR).build();

	public static final Relationship SUCCESS = new Relationship.Builder().name("SUCCESS")
			.description("Succes relationship").build();

	public static final String PLAINTEXT_KEY_PATH = "/var/tmp/plaintextKey_data.txt";
	public static final String CIPHERTEXT_KEY_PATH = "/var/tmp/cipherTextBlob_data.txt";
	final AtomicReference<Key> plaintextKeyRef = new AtomicReference<>();

	@Override
	protected void init(final ProcessorInitializationContext context) {
		final List<PropertyDescriptor> descriptors = new ArrayList<PropertyDescriptor>();
		// descriptors.add(MY_PROPERTY);
		descriptors.add(JSON_PATH);
		this.descriptors = Collections.unmodifiableList(descriptors);

		final Set<Relationship> relationships = new HashSet<Relationship>();
		// relationships.add(MY_RELATIONSHIP);
		relationships.add(SUCCESS);
		this.relationships = Collections.unmodifiableSet(relationships);

		generateKey();

		// final ByteBuffer plaintextKey = null;
		File f = new File(PLAINTEXT_KEY_PATH);
		if (f.exists()) {
			RandomAccessFile aFile;
			try {
				//System.out.println("READING FILE START");
				aFile = new RandomAccessFile(PLAINTEXT_KEY_PATH, "r");
				FileChannel inChannel = aFile.getChannel();
				long fileSize = inChannel.size();
				ByteBuffer plaintextKey = ByteBuffer.allocate((int) fileSize);
				inChannel.read(plaintextKey);
				// buffer.rewind();
				plaintextKey.flip();

				Key key = makeKey(plaintextKey);
				plaintextKeyRef.set(key);

				inChannel.close();
				aFile.close();
				//System.out.println("READING FILE END");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
	}

	public void generateKey() {

		File f = new File(PLAINTEXT_KEY_PATH);
		if (f.exists()) {
			return;
		}

		String keyArn = "arn:aws:kms:us-east-1:792904047691:key/fbe73092-70c4-4ad5-8fd9-95e77df24a67";
		GenerateDataKeyRequest dataKeyRequest = new GenerateDataKeyRequest();
		dataKeyRequest.setKeyId(keyArn);
		dataKeyRequest.setKeySpec("AES_256");
		AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
		GenerateDataKeyResult dataKeyResult = kmsClient.generateDataKey(dataKeyRequest);
		ByteBuffer plaintextKey = dataKeyResult.getPlaintext();
		ByteBuffer cipherTextBlob = dataKeyResult.getCiphertextBlob();

		try {
			FileChannel plaintextKeyFc = new FileOutputStream(PLAINTEXT_KEY_PATH).getChannel();
			plaintextKeyFc.write(plaintextKey);
			plaintextKeyFc.close();

			FileChannel fc = new FileOutputStream(CIPHERTEXT_KEY_PATH).getChannel();
			fc.write(cipherTextBlob);
			fc.close();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	@Override
	public Set<Relationship> getRelationships() {
		return this.relationships;
	}

	@Override
	public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
		return descriptors;
	}

	@OnScheduled
	public void onScheduled(final ProcessContext context) {

	}

	@Override
	public void onTrigger(ProcessContext context, ProcessSession session) throws ProcessException {
		// getLogger().trace("GOING ON to onTrigger...1");

		final AtomicReference<String> value = new AtomicReference<>();
		final AtomicReference<String> value2 = new AtomicReference<>();

		FlowFile flowfile = session.get();

		// System.out.println("***********************GOING ON to
		// onTrigger...2");
		if (flowfile != null) {
			// getLogger().trace("GOING ON to onTrigger...3");
			// 		.out.println("***********************GOING ON to
			// onTrigger...3");

			// final ByteBuffer plaintextKey = null;

			session.read(flowfile, new InputStreamCallback() {
				/* (non-Javadoc)
				 * @see org.apache.nifi.processor.io.InputStreamCallback#process(java.io.InputStream)
				 */
				@SuppressWarnings("unused")
				@Override
				public void process(InputStream in) throws IOException {
					try {
						String inputJsonNonFormatted = IOUtils.toString(in);
						StringBuffer sb = new StringBuffer();
						sb.append("{\"model\":");
						sb.append(inputJsonNonFormatted);
						sb.append("}");

						String inputJson = sb.toString();
						//System.out.print("inputJson:::::::" + inputJson);

						String jsonPathStr = context.getProperty(JSON_PATH).getValue();

						DocumentContext jsonDocObj = null;
						// String encryptStr = "";

						try {

							Integer jsonLength = JsonPath.read(inputJson, "$.model.length()");
							//System.out.println("jsonLength:" + jsonLength);
							jsonDocObj = JsonPath.parse(inputJson);
							for (int i = 0; i < jsonLength; i++) {

								String jsonPath = "$.model[" + i + "]." + jsonPathStr;
								// System.out.println("jsonPath:::::::" +
								// jsonPath);
								String VIN = JsonPath.read(inputJson, jsonPath);

								//System.out.println("VIN:::::::" + VIN);
								// System.out.println("plaintextKey:" +
								// plaintextKeyRef.get().toString());
								//if (plaintextKeyRef.get() == null) {
								//	System.out.print("Key is NULLLLLLLLL");
								//}
								// String encryptStr = encrypt(VIN,
								// makeKey(plaintextKeyRef.get()));
								String encryptStr = encrypt(VIN, plaintextKeyRef.get());

								jsonDocObj.set(jsonPath, encryptStr);
								//System.out.println("encrypt[" + encryptStr + "]" + encryptStr.length());

							}

						} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
								| IllegalBlockSizeException | BadPaddingException
								| InvalidAlgorithmParameterException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

						// DocumentContext json = JsonPath.parse(inputJson);
						// String jayPath = "$.VIN";
						// String tagValue = "ReplacedText";
						// json.set(jayPath, encryptStr);

						// value.set(result);

						String jsonFinal = jsonDocObj.json().toString();
						//System.out.println(jsonFinal);
						//String jsonFinal2 = jsonFinal.replaceFirst("model=", "\"model\":");
						String jsonFinalTemp = jsonFinal.replaceFirst("\\{model=", "");
						String jsonFinal2 = StringUtils.chop(jsonFinalTemp);

						
					
						//System.out.println("jsonFinal2:::::::" + jsonFinal2);
						value.set(jsonFinal2);
						// value2.set(jsonPath + ":" + result + " encryptStr:" +
						// encryptStr + " cipherTextBlobStr:"+
						// cipherTextBlobStr);
					} catch (Exception ex) {
						ex.printStackTrace();
						getLogger().error("Failed to read json string." + ex.getMessage());
					}
				}
			});

			// Write the results to an attribute
			String results = value2.get();
			if (results != null && !results.isEmpty()) {
				flowfile = session.putAttribute(flowfile, "match", results);
			}

			// To write the results back out ot flow file
			flowfile = session.write(flowfile, new OutputStreamCallback() {
				@Override
				public void process(OutputStream out) throws IOException {
					out.write(value.get().getBytes());

				}
			});

			/*
			 * def text = IOUtils.toString(inputStream, StandardCharsets.UTF_8)
			 * def obj = new JsonSlurper().parseText(text)
			 * 
			 * // Update ingestionDate field with today's date obj.ingestionDate
			 * = new Date().format( 'dd-MM-yyyy' )
			 * 
			 * // Output updated JSON def json = JsonOutput.toJson(obj)
			 * outputStream.write(JsonOutput.prettyPrint(json).getBytes(
			 * StandardCharsets.UTF_8))
			 */

			session.transfer(flowfile, SUCCESS);

		} else {
			getLogger().error("Flow file is empty");
		}
	}

	public static String encrypt(String src, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

		// Cipher cipher = Cipher.getInstance("AES");
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

		cipher.init(Cipher.ENCRYPT_MODE, key);

		// byte[] enc = cipher.doFinal(src.getBytes());
		byte[] enc = cipher.doFinal(src.getBytes());

		return Base64.getEncoder().encodeToString(enc);

	}

	public static String decrypt(String src, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

		byte[] decodeBase64src = Base64.getDecoder().decode(src);
		//System.out.println(new String(decodeBase64src));

		Cipher cipher = Cipher.getInstance("AES");

		cipher.init(Cipher.DECRYPT_MODE, key);
		//System.out.println(new String(cipher.doFinal(decodeBase64src)));
		return new String(cipher.doFinal(decodeBase64src));
	}

	public static Key makeKey(ByteBuffer key) {
		return new SecretKeySpec(getByteArray(key), "AES");
	}

	public static String getString(ByteBuffer b) {

		return new String(getByteArray(b));
	}

	public static byte[] getByteArray(ByteBuffer b) {
		byte[] byteArray = new byte[b.remaining()];
		b.get(byteArray);
		return byteArray;
	}

}
