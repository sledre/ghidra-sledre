package ghidraautodetours;

import java.awt.BorderLayout;
import javax.swing.JComponent;
import javax.swing.JPanel;
import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;
import ghidraautodetours.GhidraAutoDetoursParser.Hook;
import resources.Icons;
import resources.ResourceManager;

public class GhidraAutoDetoursComponent extends ComponentProviderAdapter {
	
	private JPanel panel;
	private DockingAction action;
	
	private GhidraAutoDetoursPlugin gadplugin;
	private Program currentProgram;
	
	private GhidraThreadedTablePanel<Hook> tablePanel;
	private GhidraTableFilterPanel<Hook> tableFilterPanel;
	private GhidraTable table;
	GhidraAutoDetoursTableModel hookTableModel;

	public GhidraAutoDetoursComponent(Plugin plugin, String guiName, String name) {
		super(plugin.getTool(), guiName, name);
		gadplugin = (GhidraAutoDetoursPlugin) plugin;
		
		setIcon(ResourceManager.loadImage("images/logo.png"));
		setDefaultWindowPosition(WindowPosition.BOTTOM);

		buildTable();
		createActions();
		setVisible(true);
	}

	// Customize GUI
	private void buildTable() {
		panel = new JPanel(new BorderLayout());
		
		hookTableModel = new GhidraAutoDetoursTableModel(gadplugin.getTool(), currentProgram, null);
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
		action = new DockingAction("My Action", GhidraAutoDetoursPlugin.NAME) {
			@Override
			public void actionPerformed(ActionContext context) {
				gadplugin.startAutoDetoursAnalysis();
				Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
			}
		};
		action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		//dockingTool.addLocalAction(this, action);
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
		//tableFilterPanel.dispose();
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
