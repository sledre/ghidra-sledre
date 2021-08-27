package ghidrasledre;

import java.io.IOException;
import java.net.URL;
import java.util.NoSuchElementException;
import ghidra.program.model.listing.Program;

public class SledreAPI {

	private URL url;

	public SledreAPI(URL url) {
		super();
		this.url = url;
	}
	// https://github.com/dragonGR/Ghidra/blob/decb362234d3ddfead76394b521e5669d2afac05/Ghidra/Features/Base/src/main/java/ghidra/app/util/exporter/BinaryExporter.java#L41
	// https://github.com/dragonGR/Ghidra/blob/decb362234d3ddfead76394b521e5669d2afac05/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/exporter/ExporterDialog.java

	// TODO : Provide a list to choose which detours jobs
	public Traces getTraces(Program program) throws IOException, InterruptedException {
		// URL result URL = new URL(url, "/api/jobs/5cc9590f-360f-4480-b434-00714a96934a/download_results/");
		Requests.connectivityCheck(url);
		String sha256 = program.getExecutableSHA256();

		Traces traces = null;
		SledreAPIJob job = null;
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
			traces = TracesParser.parseJson(results);
		}

		return traces;
	}

	private SledreAPIMalware getMalware(String sha256) throws IOException {
		URL malwareURL = new URL(url, String.format("/api/malwares/%s/", sha256));
		SledreAPIMalware malware = Requests.get(malwareURL, SledreAPIMalware.class);

		return malware;
	}

	private SledreAPIJob getJob(String jobId) throws IOException {
		URL jobURL = new URL(url, String.format("/api/jobs/%s/", jobId));
		SledreAPIJob job = Requests.get(jobURL, SledreAPIJob.class);

		return job;
	}

	private String getJobResults(String jobId) throws IOException {
		URL jobResultURL = new URL(url, String.format("/api/jobs/%s/download_results/", jobId));
		return Requests.rawGet(jobResultURL);
	}

	// TODO : Add Analysis time option
	// TODO : finish this
	private SledreAPIJob createDetoursJob(String sha256) throws IOException {
		SledreAPIJobRequest jobReq = new SledreAPIJobRequest("Detours", 30, sha256);
		URL jobURL = new URL(url, String.format("/api/jobs/"));
		SledreAPIJob job = Requests.post(jobURL, jobReq, SledreAPIJob.class);
		return job;
	}

	private SledreAPIJob getLastDetoursJob(String sha256) throws NoSuchElementException, IOException {
		SledreAPIMalware malware = getMalware(sha256);

		return malware.getJobs().stream().filter(j -> j.isSuccess()).filter(j -> j.isDetours())
				.sorted((m1, m2) -> m2.getEndTime().compareTo(m1.getEndTime())).findFirst().get();
	}
}
