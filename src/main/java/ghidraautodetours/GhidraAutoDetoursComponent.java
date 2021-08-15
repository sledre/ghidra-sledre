package ghidraautodetours;

import java.awt.BorderLayout;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.Msg;
import resources.Icons;
import resources.ResourceManager;

public class GhidraAutoDetoursComponent extends ComponentProvider {

	private JPanel panel;
	private DockingAction action;
	
	private GhidraAutoDetoursPlugin gadplugin;

	public GhidraAutoDetoursComponent(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		gadplugin = (GhidraAutoDetoursPlugin) plugin;
		
		setIcon(ResourceManager.loadImage("images/logo.png"));
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setVisible(true);
		
		buildPanel();
		createActions();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new JPanel(new BorderLayout());
		JTextArea textArea = new JTextArea(5, 25);
		textArea.setEditable(false);
		panel.add(new JScrollPane(textArea));
		setVisible(true);
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
		dockingTool.addLocalAction(this, action);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}