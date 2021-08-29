package re.sled.ghidra;

import java.awt.BorderLayout;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.dialogs.InputDialogListener;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import resources.ResourceManager;

public class TracesTableProvider extends ComponentProviderAdapter {

	private JPanel panel;
	private DockingAction addCommentsAction;
	private DockingAction startAnalysisAction;
	private DockingAction configureAPIAction;

	private SledrePlugin sledrePlugin;
	private Program currentProgram;

	private GhidraThreadedTablePanel<TracesHook> tablePanel;
	private GhidraTableFilterPanel<TracesHook> tableFilterPanel;
	private GhidraTable table;
	private TracesTableModel hookTableModel;
	
	private SledreAPI api;
	private Traces traces;

	public TracesTableProvider(Plugin plugin, String guiName, String name) {
		super(plugin.getTool(), guiName, name);
		sledrePlugin = (SledrePlugin) plugin;
		api = null;
		traces = null;

		setIcon(ResourceManager.loadImage("images/logo.png"));
		setDefaultWindowPosition(WindowPosition.BOTTOM);

		buildTable();
		setVisible(true);
		createActions();
	}

	// GUI creation
	private void buildTable() {
		panel = new JPanel(new BorderLayout());

		hookTableModel = new TracesTableModel(sledrePlugin.getTool(), currentProgram, null);
		tablePanel = new GhidraThreadedTablePanel<>(hookTableModel);

		table = tablePanel.getTable();

		table.setName("AutoDetours Results Table");

		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			table.installNavigation(goToService, goToService.getDefaultNavigatable());
		}

		tableFilterPanel = new GhidraTableFilterPanel<>(table, hookTableModel);

		panel.add(tablePanel, BorderLayout.CENTER);
		panel.add(tableFilterPanel, BorderLayout.SOUTH);
	}

	private void createActions() {
		// Comments
		addCommentsAction = new DockingAction("Add traces comments", sledrePlugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				addTracesComments();
			}
		};
		addCommentsAction.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/table_go.png"), null));
		addCommentsAction.setEnabled(true);
		addCommentsAction.markHelpUnnecessary();
		
		// Analysis
		startAnalysisAction = new DockingAction("Start SledRE analysis", sledrePlugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Task t = new Task("SledRE analysis", true, false, false) {
					@Override
					public void run(TaskMonitor monitor) {
						startSledreAnalysis();
					}
				};
				new TaskLauncher(t, tool.getToolFrame(), 0);
			}
		};
		startAnalysisAction.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		startAnalysisAction.setEnabled(true);
		startAnalysisAction.markHelpUnnecessary();
		
		// API config
		configureAPIAction = new DockingAction("Add traces comments", sledrePlugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				InputDialog userURL = new InputDialog("SledRE API URL", "URL", "http://<ip>:<port>", new InputDialogListener() {
					@Override
					public boolean inputIsValid(InputDialog dialog) {
						try {
							new URL(dialog.getValue());
						}
						catch (MalformedURLException e) {
							return false;
						}
						return true;
					}
				});
				
				tool.showDialog(userURL);
				if (!userURL.isCanceled()) {
					try {
						api = new SledreAPI(new URL(userURL.getValue()), currentProgram);
					} catch (MalformedURLException e) {
						Msg.showError(userURL, panel, "SledRE Error", "You entered an invalid URL, please try again.");
					}
				}
			}
		};
		configureAPIAction.setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON, null));
		configureAPIAction.setEnabled(true);
		configureAPIAction.markHelpUnnecessary();
		
		dockingTool.addLocalAction(this, configureAPIAction);
		dockingTool.addLocalAction(this, startAnalysisAction);
		dockingTool.addLocalAction(this, addCommentsAction);
	}
	
	// Core
	public void setAPIUrl(URL url) {
		api = new SledreAPI(url, currentProgram);
	}
	
	public void startSledreAnalysis() {
		if (api != null) {
			try {
				traces = api.getTraces();
			} catch (MemoryAccessException e) {
				Msg.showError(panel, panel, "SledRE Error", "Could not submit the sample to SledRE API.");
			} catch (IOException e) {
				Msg.showError(panel, panel, "SledRE Error", "Could not correctly communicate with the SledRE API.");
			} catch (InterruptedException e) {
				Msg.showError(panel, panel, "SledRE Error", "Task got interrupted, please try again.");
			}
			hookTableModel.reload(currentProgram, traces);
		} else {
			Msg.showError(panel, panel, "SledRE Error", "Please configure SledRE URL before starting an analysis.");
		}
	}
	
	public void addTracesComments() {
		if (traces != null) {
			int transId = currentProgram.startTransaction("sledreAddComment");
			String comment;
			for (TracesHook h : traces.getHookResults()) {
				Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(h.getRetAddr());
				Instruction inst = currentProgram.getListing().getInstructionBefore(addr);
	
				comment = String.format("%s(%s) -> %s", h.getFncName(), String.join(", ", h.getFncArgs()),
						h.getFncRet());
				SetCommentCmd cmd = new SetCommentCmd(inst.getAddress(), CodeUnit.PRE_COMMENT, comment); // TODO : add option to choose
				cmd.applyTo(currentProgram);
			}
			currentProgram.endTransaction(transId, true);
		} else {
			Msg.showError(panel, panel, "SledRE Error", "No traces available, please run a SledRE analysis.");
		}
	}

	// Updating
	@Override
	public JComponent getComponent() {
		return panel;
	}

	void dispose() {
		currentProgram = null;
		removeFromTool();
		tablePanel.dispose();
		tableFilterPanel.dispose();
	}

	void setProgram(Program program) {
		if (program == currentProgram) {
			return;
		}
		currentProgram = program;
		traces = null;
		hookTableModel.reload(program, traces);
		if (api != null) {
			api.setProgram(program);
		}
	}
}
