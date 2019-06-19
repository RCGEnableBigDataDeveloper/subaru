package com.subaru.udf;

import org.apache.hadoop.hive.ql.exec.UDF;
import org.apache.hadoop.io.Text;
import org.apache.log4j.Logger;

import com.google.common.base.Throwables;

public class UnMask extends UDF {

	private final static Logger logger = Logger.getLogger(Mask.class);

	public Text evaluate(Text input) {
		
		logger.fatal("starting udf...");
		try {
			logger.fatal("calling eval...");
			return new Text(EncryptDecryptUtil.decrypt(String.valueOf(input.toString())));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			logger.fatal(Throwables.getStackTraceAsString(e));
			e.printStackTrace();
			return new Text(e.getMessage());
		}
	}
}
