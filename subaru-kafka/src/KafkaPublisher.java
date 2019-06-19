
import java.util.Properties;

import org.apache.commons.io.IOUtils;
import org.apache.kafka.clients.producer.Callback;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.log4j.Logger;

public class KafkaPublisher {

	final static Logger logger = Logger.getLogger(KafkaPublisher.class);

	public static void main(String[] args) throws Exception {
		KafkaPublisher kp = new KafkaPublisher();
		kp.publish(args[0]);
	}

	public void publish(String topic) throws Exception {

		System.out.println(topic);

		String json = IOUtils.toString(KafkaPublisher.class.getResourceAsStream("/data.json"));

		Properties kafkaProperties = new Properties();

		kafkaProperties.put("bootstrap.servers", "ip-10-8-64-196.pvt.su150.cazena.com:9093");
		kafkaProperties.put("zookeeper.connect", "ip-10-8-64-198.pvt.su150.cazena.com:2181");
		kafkaProperties.put("group.id", "local");
		kafkaProperties.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
		kafkaProperties.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
		kafkaProperties.put("security.protocol", "SASL_SSL");
		kafkaProperties.put("sasl.kerberos.service.name", "kafka");

		System.out.println(kafkaProperties);

		Producer<String, String> producer = new KafkaProducer<String, String>(kafkaProperties);

		for (int i = 0; i < 10; i++) {
			long time = System.currentTimeMillis();

			json = String.format(json, i);

			System.out.println("sending new record " + json);

//			producer.send(new ProducerRecord<String, String>("test3", Integer.toString(i), Integer.toString(i)));

			producer.send(new ProducerRecord<String, String>(topic, Integer.toString(i), json), new ProducerCallback());

			System.out.println("record " + i + " sent successfully in " + (System.currentTimeMillis() - time) + " ms");
		}

		producer.close();

	}

	private class ProducerCallback implements Callback {

		@Override
		public void onCompletion(RecordMetadata recordMetadata, Exception ex) {

			if (ex != null) {
				ex.printStackTrace();
			}
		}
	}
}
