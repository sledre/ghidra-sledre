package ghidraautodetours;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.ArrayList;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

public class GhidraAutoDetoursParser {

	public static AutoDetoursTraces parseJson(String results) throws IOException {
		Reader in = new StringReader(results);
		AutoDetoursTraces traces = new AutoDetoursTraces();
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		
		ArrayList<MemorySpace> memoryMap = new ArrayList<MemorySpace>();
		ArrayList<Hook> hookResults = new ArrayList<Hook>();

		try (BufferedReader br = new BufferedReader(in)) {
			String line;
			while ((line = br.readLine()) != null) {
				JsonLineType type = gson.fromJson(line, JsonLineType.class);
				if (type.type.equals("memory_map")) {
					MemorySpace memorySpace = gson.fromJson(line, MemorySpace.class);
					memoryMap.add(memorySpace);
				} else if (type.type.equals("hook")) {
					Hook hook = gson.fromJson(line, Hook.class);
					hookResults.add(hook);
				} else {
					System.err.println("Could parse line: " + line);
				}
			}
		}
		traces.setHookResults(hookResults);
		traces.setMemoryMap(memoryMap);
		
		return traces;
	}

	private static class HexaJsonAdapter extends TypeAdapter<Integer> {

		@Override
		public void write(JsonWriter out, Integer value) throws IOException {
			out.value(Integer.toHexString(value));
		}

		@Override
		public Integer read(JsonReader in) throws IOException {
			return Integer.parseInt(in.nextString(), 16);
		}
	}

	private static class JsonLineType {
		
		private String type;
		
	}

	static class AutoDetoursTraces {

		private ArrayList<MemorySpace> memoryMap;
		private ArrayList<Hook> hookResults;
		
		public AutoDetoursTraces() {
			super();
		}

		public AutoDetoursTraces(ArrayList<MemorySpace> memoryMap, ArrayList<Hook> hookResults) {
			super();
			this.memoryMap = memoryMap;
			this.hookResults = hookResults;
		}

		public ArrayList<MemorySpace> getMemoryMap() {
			return memoryMap;
		}

		public void setMemoryMap(ArrayList<MemorySpace> memoryMap) {
			this.memoryMap = memoryMap;
		}

		public ArrayList<Hook> getHookResults() {
			return hookResults;
		}

		public void setHookResults(ArrayList<Hook> hookResults) {
			this.hookResults = hookResults;
		}
		
		public void resetState() {
			memoryMap.clear();
			hookResults.clear();
		}
	}

	static class MemorySpace {
		
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

		public MemorySpace() {
		}

		public MemorySpace(String filename, Integer beginAddr, Integer endAddr, Integer state, Integer protect) {
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

	static class Hook {

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

		public Hook() {
		}

		public Hook(Long timestamp, int thread, String fncName, String[] fncArgs, String fncRet, Integer retAddr) {
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
}
