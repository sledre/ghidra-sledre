package re.sled.ghidra;

import java.util.ArrayList;

class Traces {

	private ArrayList<TracesMemorySpace> memoryMap;
	private ArrayList<TracesHook> hookResults;
	
	public Traces() {
		super();
	}

	public Traces(ArrayList<TracesMemorySpace> memoryMap, ArrayList<TracesHook> hookResults) {
		super();
		this.memoryMap = memoryMap;
		this.hookResults = hookResults;
	}

	public ArrayList<TracesMemorySpace> getMemoryMap() {
		return memoryMap;
	}

	public void setMemoryMap(ArrayList<TracesMemorySpace> memoryMap) {
		this.memoryMap = memoryMap;
	}

	public ArrayList<TracesHook> getHookResults() {
		return hookResults;
	}

	public void setHookResults(ArrayList<TracesHook> hookResults) {
		this.hookResults = hookResults;
	}
	
	public void resetState() {
		memoryMap.clear();
		hookResults.clear();
	}
}