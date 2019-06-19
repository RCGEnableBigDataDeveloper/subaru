package com.subaru.udf;

import java.util.Arrays;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hive.ql.exec.UDF;

public class TestUDF extends UDF {
	public TestUDF() {

	}

	public String evaluate(String str, String delim, String idx) {
		if (StringUtils.isBlank(str)) {
			return null;
		} else {
			try {
				List<String> splitStr = Arrays.asList(StringUtils.splitPreserveAllTokens(str, delim, -1));
				return splitStr.get(Integer.valueOf(idx));
			} catch (Exception e) {
				return null;
			}
		}
	}
}