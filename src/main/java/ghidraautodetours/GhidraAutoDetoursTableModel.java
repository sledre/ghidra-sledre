package ghidraautodetours;

import java.io.IOException;

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
import ghidraautodetours.GhidraAutoDetoursParser.Hook;

public class GhidraAutoDetoursTableModel extends AddressBasedTableModel<Hook> {

	protected GhidraAutoDetoursTableModel(ServiceProvider serviceProvider, Program program, TaskMonitor monitor) {
		super("AutoDetours Hook Table Model", serviceProvider, program, monitor);
		// TODO Auto-generated constructor stub
	}

	private static Address getAddressFromHook(Program program, Hook hook) {
		Address hookAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(hook.getRetAddr());
		Instruction inst = program.getListing().getInstructionBefore(hookAddr);
		return inst.getAddress();
	}

	@Override
	public Address getAddress(int row) {
		Hook hook = filteredData.get(row);
		return getAddressFromHook(program, hook);
	}

	@Override
	protected void doLoad(Accumulator<Hook> accumulator, TaskMonitor monitor) throws CancelledException {
		if (getProgram() == null) {
			return;
		}

		String path = "/Users/baptistin/ghidra_scripts/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa_Detours.jsonl";
		GhidraAutoDetoursParser parser = new GhidraAutoDetoursParser(path);

		try {
			parser.parseJson();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		for (Hook h : parser.getHookResults()) {
			accumulator.add(h);
		}
	}

	@Override
	protected TableColumnDescriptor<Hook> createTableColumnDescriptor() {
		TableColumnDescriptor<Hook> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new HookLocationColumn(), 1, true);
		descriptor.addVisibleColumn(new HookNameColumn());
		descriptor.addVisibleColumn(new HookArgsColumn());
		descriptor.addVisibleColumn(new HookRetColumn());

		return descriptor;
	}

	public void reload(Program newProgram) {
		setProgram(newProgram);
		reload();
	}

	// ==================================================================================================
	// Inner Classes
	// ==================================================================================================

	private static class HookLocationColumn extends AbstractProgramLocationTableColumn<Hook, AddressBasedLocation> {

		@Override
		public String getColumnName() {
			return "Location";
		}

		@Override
		public AddressBasedLocation getValue(Hook hook, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			AddressBasedLocation addr = new AddressBasedLocation(program,
					GhidraAutoDetoursTableModel.getAddressFromHook(program, hook));
			return addr;

		}

		@Override
		public ProgramLocation getProgramLocation(Hook hook, Settings settings, Program program,
				ServiceProvider serviceProvider) {
			return new ProgramLocation(program,
					GhidraAutoDetoursTableModel.getAddressFromHook(program, hook));
		}

	}

	private static class HookNameColumn extends AbstractProgramBasedDynamicTableColumn<Hook, String> {

		@Override
		public String getColumnName() {
			return "Function Name";
		}

		@Override
		public String getValue(Hook hook, Settings settings, Program data, ServiceProvider serviceProvider)
				throws IllegalArgumentException {
			// TODO Auto-generated method stub
			return hook.getFncName();
		}
	}

	private static class HookArgsColumn extends AbstractProgramBasedDynamicTableColumn<Hook, String> {

		@Override
		public String getColumnName() {
			return "Function Args";
		}

		@Override
		public String getValue(Hook hook, Settings settings, Program data, ServiceProvider serviceProvider)
				throws IllegalArgumentException {
			// TODO Auto-generated method stub
			return null;
		}
	}

	private static class HookRetColumn extends AbstractProgramBasedDynamicTableColumn<Hook, String> {

		@Override
		public String getColumnName() {
			return "Function Return Value";
		}

		@Override
		public String getValue(Hook hook, Settings settings, Program data, ServiceProvider serviceProvider)
				throws IllegalArgumentException {
			// TODO Auto-generated method stub
			return hook.getFncRet();
		}
	}
}
