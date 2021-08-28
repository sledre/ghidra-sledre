package re.sled.ghidra;

import com.google.gson.annotations.SerializedName;

class SledreAPIJobRequest {
	@SerializedName(value = "job_type")
	private String jobType;

	@SerializedName(value = "job_time")
	private Integer jobTime;

	private String malware;

	public SledreAPIJobRequest(String jobType, Integer jobTime, String malware) {
		super();
		this.jobType = jobType;
		this.jobTime = jobTime;
		this.malware = malware;
	}
}