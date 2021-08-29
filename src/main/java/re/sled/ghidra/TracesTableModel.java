package re.sled.ghidra;

import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.table.field.AbstractProgramLocationTableColumn;
import ghidra.util.table.field.AddressBasedLocation;
import ghidra.util.task.TaskMonitor;

public class TracesTableModel extends AddressBasedTableModel<TracesHook> {

	private Traces traces;
	
	protected TracesTableModel(ServiceProvider serviceProvider, Program program, TaskMonitor monitor) {
		super("AutoDetours Hook Table Model", serviceProvider, program, monitor);
		// TODO Auto-generated constructor stub
		traces = null;
	}

	private static Address getAddressFromHook(Program program, TracesHook hook) {
		Address hookAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(hook.getRetAddr());
		Instruction inst = program.getListing().getInstructionBefore(hookAddr);
		return inst.getAddress();
	}

	@Override
	public Address getAddress(int row) {
		TracesHook hook = filteredData.get(row);
		return getAddressFromHook(program, hook);
	}

	@Override
	protected void doLoad(Accumulator<TracesHook> accumulator, TaskMonitor monitor) throws CancelledException {
		if (getProgram() == null || traces == null) {
			return;
		}

		for (TracesHook h : traces.getHookResults()) {
			accumulator.add(h);
		}
	}

	@Override
	protected TableColumnDescriptor<TracesHook> createTableColumnDescriptor() {
		TableColumnDescriptor<TracesHook> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new HookLocationColumn(), 1, true);
		descriptor.addVisibleColumn(new HookNameColumn());
		descriptor.addVisibleColumn(new HookArgsColumn());
		descriptor.addVisibleColumn(new HookRetColumn());

		return descriptor;
	}

	public void reload(Program newProgram, Traces newTraces) {
		setProgram(newProgram);
		setTraces(newTraces);
		reload();
	}
	
	public void setTraces(Traces newTraces) {
		traces = newTraces;
	}

	// ==================================================================================================
	// Inner Classes
	// ==================================================================================================

	private static class HookLocationColumn extends AbstractProgramLocationTableColumn<TracesHook, AddressBasedLocation> {

		@Override
		public String getColumnName() {
			return "Location";
		}

		@Override
		public AddressBasedLocation getValue(TracesHook hook, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			AddressBasedLocation addr = new AddressBasedLocation(program,
					TracesTableModel.getAddressFromHook(program, hook));
			return addr;

		}

		@Override
		public ProgramLocation getProgramLocation(TracesHook hook, Settings settings, Program program,
				ServiceProvider serviceProvider) {
			return new ProgramLocation(program,
					TracesTableModel.getAddressFromHook(program, hook));
		}

	}

	private static class HookNameColumn extends AbstractProgramBasedDynamicTableColumn<TracesHook, String> {

		@Override
		public String getColumnName() {
			return "Function Name";
		}

		@Override
		public String getValue(TracesHook hook, Settings settings, Program data, ServiceProvider serviceProvider)
				throws IllegalArgumentException {
			// TODO Auto-generated method stub
			return hook.getFncName();
		}
	}

	private static class HookArgsColumn extends AbstractProgramBasedDynamicTableColumn<TracesHook, String> {

		@Override
		public String getColumnName() {
			return "Function Args";
		}

		@Override
		public String getValue(TracesHook hook, Settings settings, Program data, ServiceProvider serviceProvider)
				throws IllegalArgumentException {
			// TODO Auto-generated method stub
			return String.join(", ", hook.getFncArgs());
		}
	}

	private static class HookRetColumn extends AbstractProgramBasedDynamicTableColumn<TracesHook, String> {

		@Override
		public String getColumnName() {
			return "Function Return Value";
		}

		@Override
		public String getValue(TracesHook hook, Settings settings, Program data, ServiceProvider serviceProvider)
				throws IllegalArgumentException {
			// TODO Auto-generated method stub
			return hook.getFncRet();
		}
	}
}
