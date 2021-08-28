package re.sled.ghidra;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.ArrayList;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

public class TracesParser {

	public static Traces parseJson(String results) throws IOException {
		Reader in = new StringReader(results);
		Traces traces = new Traces();
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		
		ArrayList<TracesMemorySpace> memoryMap = new ArrayList<TracesMemorySpace>();
		ArrayList<TracesHook> hookResults = new ArrayList<TracesHook>();

		try (BufferedReader br = new BufferedReader(in)) {
			String line;
			while ((line = br.readLine()) != null) {
				JsonLineType type = gson.fromJson(line, JsonLineType.class);
				if (type.type.equals("memory_map")) {
					TracesMemorySpace memorySpace = gson.fromJson(line, TracesMemorySpace.class);
					memoryMap.add(memorySpace);
				} else if (type.type.equals("hook")) {
					TracesHook hook = gson.fromJson(line, TracesHook.class);
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

	static class HexaJsonAdapter extends TypeAdapter<Integer> {

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
}
