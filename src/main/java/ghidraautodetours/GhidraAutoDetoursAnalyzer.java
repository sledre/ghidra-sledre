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
package ghidraautodetours;

import java.io.IOException;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.app.util.bin.format.pe.Constants;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidraautodetours.GhidraAutoDetoursParser.Hook;
import ghidraautodetours.GhidraAutoDetoursParser.MemorySpace;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class GhidraAutoDetoursAnalyzer extends AbstractAnalyzer {

	public GhidraAutoDetoursAnalyzer() {

		// TODO: Name the analyzer and give it a description.

		super("AutoDetours", "Run the sample through AutoDetours and add the traces to the project.", AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// TODO: Return true if analyzer should be enabled by default

		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();
		if (format.equals(PeLoader.PE_NAME)) {
			return true;
		}
		if (format.equals(BinaryLoader.BINARY_NAME)) {
			MemoryByteProvider mbp = new MemoryByteProvider(program.getMemory(),
				program.getAddressFactory().getDefaultAddressSpace());
			try {
				FactoryBundledWithBinaryReader reader = new FactoryBundledWithBinaryReader(
					RethrowContinuesFactory.INSTANCE, mbp, true/*LittleEndian*/);
				DOSHeader dosHeader = DOSHeader.createDOSHeader(reader);
				if (dosHeader.e_magic() == DOSHeader.IMAGE_DOS_SIGNATURE) {
					int peHeaderStartIndex = dosHeader.e_lfanew();
					int peMagicNumber = reader.readInt(peHeaderStartIndex);
					if (peMagicNumber == Constants.IMAGE_NT_SIGNATURE) {
						return true;
					}
				}
			}
			catch (IOException e) {
			}
		}
		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// TODO: If this analyzer has custom options, register them here

		/*options.registerOption("Option name goes here", false, null,
			"Option description goes here");*/
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// TODO: Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.
		
		String path = "/Users/baptistin/ghidra_scripts/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa_Detours.jsonl";
		GhidraAutoDetoursParser parser = new GhidraAutoDetoursParser(path);
		try {
			parser.parseJson();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
				
		for (MemorySpace m : parser.getMemoryMap()) {
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
		
		for (Hook h : parser.getHookResults()) {
			Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(h.getRetAddr());
			Instruction inst = program.getListing().getInstructionBefore(addr);
			
			String comment = String.format("%s(%s) -> %s", h.getFncName(), String.join(", ", h.getFncArgs()), h.getFncRet());
			SetCommentCmd cmd = new SetCommentCmd(inst.getAddress(), CodeUnit.EOL_COMMENT, comment);
			cmd.applyTo(program);
		}

		return false;
	}
}
