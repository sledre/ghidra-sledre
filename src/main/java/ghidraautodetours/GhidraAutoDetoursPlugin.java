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

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = GhidraAutoDetoursPlugin.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "GhidraAutoDetours is an integration of AutoDetours project to Ghidra.",
	description = "GhidraAutoDetours allow you to query AutoDetours to recover samples analyzed or submit samples open in Ghidra. The traces provided by AutoDetours are directly integrated to Ghidra.",
	servicesRequired = {
		ProgramManager.class
	}
)
//@formatter:on
public class GhidraAutoDetoursPlugin extends ProgramPlugin {
	public static final String NAME = "GhidraAutoDetours";

	GhidraAutoDetoursComponent ui;

	private ProgramManager pm;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhidraAutoDetoursPlugin(PluginTool tool) {
		super(tool, true, true);

		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		ui = new GhidraAutoDetoursComponent(this, pluginName);
	}

	@Override
	public void init() {
		super.init();

		pm = tool.getService(ProgramManager.class);

		// TODO: Acquire services if necessary
	}

	public void startAutoDetoursAnalysis() {
		Program program = pm.getCurrentProgram();
		AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
		GhidraAutoDetoursAnalyzer gadAnalyzer = new GhidraAutoDetoursAnalyzer();
		analysisManager.scheduleOneTimeAnalysis(gadAnalyzer, new AddressSet());
	}

}
