package re.sled.ghidra;

import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;

import re.sled.ghidra.TracesParser.HexaJsonAdapter;

class TracesMemorySpace {
	
	private String filename;

	@SerializedName(value = "begin_addr")
	@JsonAdapter(HexaJsonAdapter.class)
	private Integer beginAddr;

	@SerializedName(value = "end_addr")
	@JsonAdapter(HexaJsonAdapter.class)
	private Integer endAddr;

	@JsonAdapter(HexaJsonAdapter.class)
	private Integer state;

	@JsonAdapter(HexaJsonAdapter.class)
	private Integer protect;

	public TracesMemorySpace() {
	}

	public TracesMemorySpace(String filename, Integer beginAddr, Integer endAddr, Integer state, Integer protect) {
		super();
		this.filename = filename;
		this.beginAddr = beginAddr;
		this.endAddr = endAddr;
		this.state = state;
		this.protect = protect;
	}

	public String getFilename() {
		return filename;
	}

	public void setFilename(String filename) {
		this.filename = filename;
	}

	public Integer getBeginAddr() {
		return beginAddr;
	}

	public void setBeginAddr(Integer beginAddr) {
		this.beginAddr = beginAddr;
	}

	public Integer getEndAddr() {
		return endAddr;
	}

	public void setEndAddr(Integer endAddr) {
		this.endAddr = endAddr;
	}

	public Integer getState() {
		return state;
	}

	public void setState(Integer state) {
		this.state = state;
	}

	public Integer getProtect() {
		return protect;
	}

	public void setProtect(Integer protect) {
		this.protect = protect;
	}
}