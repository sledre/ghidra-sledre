package ghidrasledre;

import java.awt.BorderLayout;
import java.io.IOException;

import javax.swing.JComponent;
import javax.swing.JPanel;
import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;
import resources.ResourceManager;

public class TracesTableProvider extends ComponentProviderAdapter {

	private JPanel panel;
	private DockingAction addCommentsAction;

	private SledrePlugin gadplugin;
	private Program currentProgram;

	private GhidraThreadedTablePanel<TracesHook> tablePanel;
	private GhidraTableFilterPanel<TracesHook> tableFilterPanel;
	private GhidraTable table;
	TracesTableModel hookTableModel;

	public TracesTableProvider(Plugin plugin, String guiName, String name) {
		super(plugin.getTool(), guiName, name);
		gadplugin = (SledrePlugin) plugin;

		setIcon(ResourceManager.loadImage("images/logo.png"));
		setDefaultWindowPosition(WindowPosition.BOTTOM);

		buildTable();
		setVisible(true);
		createActions();
	}

	// Customize GUI
	private void buildTable() {
		panel = new JPanel(new BorderLayout());

		hookTableModel = new TracesTableModel(gadplugin.getTool(), currentProgram, null);
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

	// TODO: Customize actions
	private void createActions() {
		addCommentsAction = new DockingAction("Add traces comments", gadplugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				try {
					gadplugin.addTracesComments();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				Msg.showInfo(getClass(), panel, SledrePlugin.GUI_NAME,
						"Traces comments successfully added !");
			}
		};
		addCommentsAction.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/table_go.png"), null));
		addCommentsAction.setEnabled(true);
		addCommentsAction.markHelpUnnecessary();
		dockingTool.addLocalAction(this, addCommentsAction);
	}

	/**
	 * @see ghidra.framework.plugintool.ComponentProviderAdapter#getComponent()
	 */
	@Override
	public JComponent getComponent() {
		return panel;
	}

	@Override
	public void componentShown() {
		hookTableModel.reload(currentProgram);
	}

	@Override
	public void componentHidden() {
		hookTableModel.reload(null);
	}

	GhidraTable getTable() {
		return table;
	}

	void dispose() {
		currentProgram = null;
		removeFromTool();
		tablePanel.dispose();
		// tableFilterPanel.dispose();
	}

	public Program getProgram() {
		return currentProgram;
	}

	void setProgram(Program program) {
		if (program == currentProgram) {
			return;
		}
		currentProgram = program;
		if (isVisible()) {
			hookTableModel.reload(program);
		}
	}
}
