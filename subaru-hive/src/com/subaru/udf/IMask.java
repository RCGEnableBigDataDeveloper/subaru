package com.subaru.udf;

import java.util.Arrays;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hive.ql.exec.UDF;

public class IMask extends UDF {
	public IMask() {

	}

	public String evaluate(String str) {
		if (StringUtils.isBlank(str)) {
			return null;
		} else {
			try {
					return EncryptDecryptUtil.encrypt(str);
			} catch (Exception e) {
				return null;
			}
		}
	}
}