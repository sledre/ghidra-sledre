package re.sled.ghidra;

import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;

import re.sled.ghidra.TracesParser.HexaJsonAdapter;

class TracesHook {

	private Long timestamp;
	private int thread;

	@SerializedName(value = "fnc_name")
	private String fncName;

	@SerializedName(value = "fnc_args")
	private String[] fncArgs;

	@SerializedName(value = "fnc_ret")
	private String fncRet;

	@SerializedName(value = "ret_addr")
	@JsonAdapter(HexaJsonAdapter.class)
	private Integer retAddr;

	public TracesHook() {
	}

	public TracesHook(Long timestamp, int thread, String fncName, String[] fncArgs, String fncRet, Integer retAddr) {
		super();
		this.timestamp = timestamp;
		this.thread = thread;
		this.fncName = fncName;
		this.fncArgs = fncArgs;
		this.fncRet = fncRet;
		this.retAddr = retAddr;
	}

	public Long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(Long timestamp) {
		this.timestamp = timestamp;
	}

	public int getThread() {
		return thread;
	}

	public void setThread(int thread) {
		this.thread = thread;
	}

	public String getFncName() {
		return fncName;
	}

	public void setFncName(String fncName) {
		this.fncName = fncName;
	}

	public String[] getFncArgs() {
		return fncArgs;
	}

	public void setFncArgs(String[] fncArgs) {
		this.fncArgs = fncArgs;
	}

	public String getFncRet() {
		return fncRet;
	}

	public void setFncRet(String fncRet) {
		this.fncRet = fncRet;
	}

	public Integer getRetAddr() {
		return retAddr;
	}

	public void setRetAddr(Integer retAddr) {
		this.retAddr = retAddr;
	}
}