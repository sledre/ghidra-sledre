/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package re.sled.ghidra;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.app.util.bin.format.pe.Constants;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = SledrePlugin.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Ghidrasledre is an integration of sledre project to Ghidra.",
	description = "Ghidrasledre allow you to query sledre to recover samples analyzed or submit samples open in Ghidra. The traces provided by sledre are directly integrated to Ghidra.",
	servicesRequired = {
		ProgramManager.class,
		GoToService.class
	}
)
//@formatter:on
public class SledrePlugin extends ProgramPlugin {
	public static final String NAME = "ghidrasledreplugin";
	public static final String GUI_NAME = "Sledre";

	TracesTableProvider uiProvider;

	private ProgramManager pm;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public SledrePlugin(PluginTool tool) {
		super(tool, true, true);

		// TODO: Customize provider (or remove if a provider is not desired)

	}

	@Override
	public void init() {
		super.init();

		pm = tool.getService(ProgramManager.class);

		uiProvider = new TracesTableProvider(this, GUI_NAME, NAME);

		// TODO: Acquire services if necessary
	}

	@Override
	public void dispose() {
		uiProvider.dispose();
		super.dispose();
	}

	// Triggered when program is changed
	@Override
	protected void programActivated(Program program) {
		uiProvider.setProgram(program);
	}

	private boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();
		if (format.equals(PeLoader.PE_NAME)) {
			return true;
		}
		if (format.equals(BinaryLoader.BINARY_NAME)) {
			MemoryByteProvider mbp = new MemoryByteProvider(program.getMemory(),
					program.getAddressFactory().getDefaultAddressSpace());
			try {
				FactoryBundledWithBinaryReader reader = new FactoryBundledWithBinaryReader(
						RethrowContinuesFactory.INSTANCE, mbp, true/* LittleEndian */);
				DOSHeader dosHeader = DOSHeader.createDOSHeader(reader);
				if (dosHeader.e_magic() == DOSHeader.IMAGE_DOS_SIGNATURE) {
					int peHeaderStartIndex = dosHeader.e_lfanew();
					int peMagicNumber = reader.readInt(peHeaderStartIndex);
					if (peMagicNumber == Constants.IMAGE_NT_SIGNATURE) {
						return true;
					}
				}
			} catch (IOException e) {
			}
		}
		return false;
	}

	public void startAutoDetoursAnalysis() {
		Program program = pm.getCurrentProgram();

		if (!canAnalyze(program))
			return;

		/*String path = "/Users/baptistin/ghidra_scripts/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa_Detours.jsonl";

		try {
			tracesParser.parseJson();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		for (MemorySpace m : tracesParser.getMemoryMap()) {
			if (m.getFilename().equals("C:\\Temp\\sample.exe")) {
				Address baseAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(m.getBeginAddr());
				try {
					program.setImageBase(baseAddr, true); // TODO : Add an option to the plugin
				} catch (AddressOverflowException | LockException | IllegalStateException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}

		for (Hook h : tracesParser.getHookResults()) {
			Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(h.getRetAddr());
			Instruction inst = program.getListing().getInstructionBefore(addr);

			String comment = String.format("%s(%s) -> %s", h.getFncName(), String.join(", ", h.getFncArgs()),
					h.getFncRet());
			SetCommentCmd cmd = new SetCommentCmd(inst.getAddress(), CodeUnit.PRE_COMMENT, comment);
			cmd.applyTo(program);
		}*/
	}
}