package ghidraautodetours;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.NoSuchElementException;
import java.util.stream.Stream;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

import ghidra.program.model.listing.Program;
import ghidraautodetours.GhidraAutoDetoursParser.AutoDetoursTraces;

public class AutoDetoursAPI {

	private URL url;

	public AutoDetoursAPI(URL url) {
		super();
		this.url = url;
	}
	// https://github.com/dragonGR/Ghidra/blob/decb362234d3ddfead76394b521e5669d2afac05/Ghidra/Features/Base/src/main/java/ghidra/app/util/exporter/BinaryExporter.java#L41
	// https://github.com/dragonGR/Ghidra/blob/decb362234d3ddfead76394b521e5669d2afac05/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/exporter/ExporterDialog.java

	// TODO : Provide a list to choose which detours jobs

	public AutoDetoursTraces getTraces(Program program) throws IOException, InterruptedException {
		// URL result URL = new URL(url, "/api/jobs/5cc9590f-360f-4480-b434-00714a96934a/download_results/");
		AutoDetoursAPIRequest.connectivityCheck(url);
		String sha256 = program.getExecutableSHA256();

		AutoDetoursTraces traces = null;
		AutoDetoursAPIJob job = null;
		// TODO : also upload the binary when not present
		try {
			job = getLastDetoursJob(sha256);
		} catch (NoSuchElementException e) {
			job = createDetoursJob(sha256);
			while (!job.isFinished()) {
				Thread.sleep(10);
				job = getJob(job.getId());
			}
		}

		if (job != null && job.isDetours() && job.isSuccess()) {
			String results = getJobResults(job.getId());
			traces = GhidraAutoDetoursParser.parseJson(results);
		}

		return traces;
	}

	private AutoDetoursAPIMalware getMalware(String sha256) throws IOException {
		URL malwareURL = new URL(url, String.format("/api/malwares/%s/", sha256));
		AutoDetoursAPIMalware malware = AutoDetoursAPIRequest.get(malwareURL, AutoDetoursAPIMalware.class);

		return malware;
	}

	private AutoDetoursAPIJob getJob(String jobId) throws IOException {
		URL jobURL = new URL(url, String.format("/api/jobs/%s/", jobId));
		AutoDetoursAPIJob job = AutoDetoursAPIRequest.get(jobURL, AutoDetoursAPIJob.class);

		return job;
	}

	private String getJobResults(String jobId) throws IOException {
		URL jobResultURL = new URL(url, String.format("/api/jobs/%s/download_results/", jobId));
		return AutoDetoursAPIRequest.rawGet(jobResultURL);
	}

	// TODO : Add Analysis time option
	// TODO : finish this
	private AutoDetoursAPIJob createDetoursJob(String sha256) throws IOException {
		AutoDetoursJobRequest jobReq = new AutoDetoursJobRequest("Detours", 30, sha256);
		URL jobURL = new URL(url, String.format("/api/jobs/"));
		AutoDetoursAPIJob job = AutoDetoursAPIRequest.post(jobURL, jobReq, AutoDetoursAPIJob.class);
		return job;
	}

	private AutoDetoursAPIJob getLastDetoursJob(String sha256) throws NoSuchElementException, IOException {
		AutoDetoursAPIMalware malware = getMalware(sha256);

		return malware.getJobs().stream().filter(j -> j.isSuccess()).filter(j -> j.isDetours())
				.sorted((m1, m2) -> m2.getEndTime().compareTo(m1.getEndTime())).findFirst().get();
	}

	static class AutoDetoursJobRequest {
		@SerializedName(value = "job_type")
		private String jobType;

		@SerializedName(value = "job_time")
		private Integer jobTime;

		private String malware;

		public AutoDetoursJobRequest(String jobType, Integer jobTime, String malware) {
			super();
			this.jobType = jobType;
			this.jobTime = jobTime;
			this.malware = malware;
		}
	}

	static class AutoDetoursAPIJob {
		// TODO : add isfinished etc..
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

		public AutoDetoursAPIJob(String id, String jobType, Integer jobTime, String state, Timestamp creationTime,
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

	static class AutoDetoursAPIMalware {

		private String sha256;
		private ArrayList<AutoDetoursAPIJob> jobs;
		private String state;
		private String name;
		private Timestamp uploadTime;
		private String md5;
		private String sha512;
		private String format;
		private String exportDLL;

		public AutoDetoursAPIMalware(String sha256, ArrayList<AutoDetoursAPIJob> jobs, String state, String name,
				Timestamp uploadTime, String md5, String sha512, String format, String exportDLL) {
			super();
			this.sha256 = sha256;
			this.jobs = jobs;
			this.state = state;
			this.name = name;
			this.uploadTime = uploadTime;
			this.md5 = md5;
			this.sha512 = sha512;
			this.format = format;
			this.exportDLL = exportDLL;
		}

		public String getSha256() {
			return sha256;
		}

		public void setSha256(String sha256) {
			this.sha256 = sha256;
		}

		public ArrayList<AutoDetoursAPIJob> getJobs() {
			return jobs;
		}

		public void setJobs(ArrayList<AutoDetoursAPIJob> jobs) {
			this.jobs = jobs;
		}

		public String getState() {
			return state;
		}

		public void setState(String state) {
			this.state = state;
		}

		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}

		public Timestamp getUploadTime() {
			return uploadTime;
		}

		public void setUploadTime(Timestamp uploadTime) {
			this.uploadTime = uploadTime;
		}

		public String getMd5() {
			return md5;
		}

		public void setMd5(String md5) {
			this.md5 = md5;
		}

		public String getSha512() {
			return sha512;
		}

		public void setSha512(String sha512) {
			this.sha512 = sha512;
		}

		public String getFormat() {
			return format;
		}

		public void setFormat(String format) {
			this.format = format;
		}

		public String getExportDLL() {
			return exportDLL;
		}

		public void setExportDLL(String exportDLL) {
			this.exportDLL = exportDLL;
		}
	}
}
