package re.sled.ghidra;

import java.sql.Timestamp;

import com.google.gson.annotations.SerializedName;

class SledreAPIJob {
	private String id;

	@SerializedName(value = "job_type")
	private String jobType;

	@SerializedName(value = "job_time")
	private Integer jobTime;
	private String state;
	// TODO : extra results not useful at the moment

	@SerializedName(value = "creation_time")
	private Timestamp creationTime;

	@SerializedName(value = "start_time")
	private Timestamp startTime;

	@SerializedName(value = "end_time")
	private Timestamp endTime;

	public SledreAPIJob(String id, String jobType, Integer jobTime, String state, Timestamp creationTime,
			Timestamp startTime, Timestamp endTime) {
		super();
		this.id = id;
		this.jobType = jobType;
		this.jobTime = jobTime;
		this.state = state;
		this.creationTime = creationTime;
		this.startTime = startTime;
		this.endTime = endTime;
	}

	public Boolean isFinished() {
		return state.equals("DONE") || state.equals("TIMED_OUT");
	}

	public Boolean isSuccess() {
		return state.equals("DONE");
	}

	public Boolean isDetours() {
		return jobType.equals("Detours");
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getJobType() {
		return jobType;
	}

	public void setJobType(String jobType) {
		this.jobType = jobType;
	}

	public Integer getJobTime() {
		return jobTime;
	}

	public void setJobTime(Integer jobTime) {
		this.jobTime = jobTime;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}

	public Timestamp getCreationTime() {
		return creationTime;
	}

	public void setCreationTime(Timestamp creationTime) {
		this.creationTime = creationTime;
	}

	public Timestamp getStartTime() {
		return startTime;
	}

	public void setStartTime(Timestamp startTime) {
		this.startTime = startTime;
	}

	public Timestamp getEndTime() {
		return endTime;
	}

	public void setEndTime(Timestamp endTime) {
		this.endTime = endTime;
	}
}