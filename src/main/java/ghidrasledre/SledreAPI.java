package ghidrasledre;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

public class SledreAPI {

	private URL url;
	private Program program;
	
	String sha256;

	public SledreAPI(URL url, Program program) {
		super();
		this.url = url;
		setProgram(program);
	}
	
	public void setProgram(Program program) {
		this.program = program;
		this.sha256 = program.getExecutableSHA256();
	}
	// https://github.com/dragonGR/Ghidra/blob/decb362234d3ddfead76394b521e5669d2afac05/Ghidra/Features/Base/src/main/java/ghidra/app/util/exporter/BinaryExporter.java#L41
	// https://github.com/dragonGR/Ghidra/blob/decb362234d3ddfead76394b521e5669d2afac05/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/exporter/ExporterDialog.java

	// TODO : Provide a list to choose which detours jobs
	public Traces getTraces() throws IOException, InterruptedException, MemoryAccessException {
		// URL result URL = new URL(url, "/api/jobs/5cc9590f-360f-4480-b434-00714a96934a/download_results/");
		Requests.connectivityCheck(url);

		Traces traces = null;
		SledreAPIJob job = null;
		
		if (getMalware() == null && !postMalware()) {
			throw new IOException("Can't submit the sample to sledre!");
		}
		
		try {
			job = getLastDetoursJob();
		} catch (NoSuchElementException e) {
			job = createDetoursJob();
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
	
	private Boolean postMalware() throws IOException, MemoryAccessException {
		URL malwareURL = new URL(url, "/api/malwares/");
		Map<String, String> headers = new HashMap<>();
	    headers.put("Accept", "application/json");
		HttpPostMultipart multipart = new HttpPostMultipart(malwareURL, "utf-8", headers);
		System.out.println("toto");
		Memory memory = program.getMemory();
		AddressSet set = new AddressSet(memory);
		MemoryBlock[] blocks = memory.getBlocks();
		for (int i = 0; i < blocks.length; ++i) {
			if (!blocks[i].isInitialized()) {
				set.delete(new AddressRangeImpl(blocks[i].getStart(), blocks[i].getEnd()));
			}
		}

		PipedInputStream pis = new PipedInputStream(Math.toIntExact(memory.getSize()));
		PipedOutputStream pos = new PipedOutputStream(pis);
		System.out.println("toto2");
		AddressRangeIterator iter = set.getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			byte[] mem = new byte[(int) range.getLength()];
			int numBytes = memory.getBytes(range.getMinAddress(), mem);
			pos.write(mem, 0, numBytes);
		}

	    multipart.addFormField("name", program.getName());
	    multipart.addFormField("format", "exe");

	    pos.flush();
	    pos.close();
	    multipart.addFilePart("file", program.getName(), pis);

	    String response = multipart.finish();
		return response != null;
	}

	private SledreAPIMalware getMalware() throws IOException {
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
	private SledreAPIJob createDetoursJob() throws IOException {
		SledreAPIJobRequest jobReq = new SledreAPIJobRequest("Detours", 30, sha256);
		URL jobURL = new URL(url, String.format("/api/jobs/"));
		SledreAPIJob job = Requests.post(jobURL, jobReq, SledreAPIJob.class);
		return job;
	}

	private SledreAPIJob getLastDetoursJob() throws NoSuchElementException, IOException {
		SledreAPIMalware malware = getMalware();

		return malware.getJobs().stream().filter(j -> j.isSuccess()).filter(j -> j.isDetours())
				.sorted((m1, m2) -> m2.getEndTime().compareTo(m1.getEndTime())).findFirst().get();
	}
}
