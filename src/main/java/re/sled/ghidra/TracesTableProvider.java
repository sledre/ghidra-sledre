package re.sled.ghidra;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Image;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;


import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.dialogs.InputDialogListener;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.services.GoToService;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.app.util.bin.format.pe.Constants;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.feature.vt.gui.filters.StatusLabel;
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
	
	private JLabel statusLabel;
	private JLabel apiURLLabel;
	
	private JButton configureSledreButton;
	private JButton startButton;
	private JButton addTracesCommentsButton;

	private SledrePlugin sledrePlugin;
	private Program currentProgram;

	private GhidraThreadedTablePanel<TracesHook> tablePanel;
	private GhidraTableFilterPanel<TracesHook> tableFilterPanel;
	private GhidraTable table;
	private TracesTableModel hookTableModel;
	
	private SledreAPI api;
	private Traces traces;
	
	private class Status {
		public static final String CONNECTED = "<html><b>Status:</b> connected to SledRE</html>";
		public static final String ERROR = "<html><b>Status:</b> an error occured</html>";
		public static final String RUNNING = "<html><b>Status:</b> running SledRE analysis</html>";
		public static final String DISCONNECTED = "<html><b>Status:</b> disconnected</html>";
	}

	public TracesTableProvider(Plugin plugin, String guiName, String name) {
		super(plugin.getTool(), guiName, name);
		sledrePlugin = (SledrePlugin) plugin;
		api = null;
		traces = null;

		setIcon(ResourceManager.loadImage("images/logo.png"));
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		
		setVisible(true);
		
		createActions();
		buildTable();
	}
	
	private boolean canAnalyzeProgram() {
		String format = currentProgram.getExecutableFormat();
		if (format.equals(PeLoader.PE_NAME)) {
			return true;
		}
		if (format.equals(BinaryLoader.BINARY_NAME)) {
			MemoryByteProvider mbp = new MemoryByteProvider(currentProgram.getMemory(),
					currentProgram.getAddressFactory().getDefaultAddressSpace());
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

	// GUI creation
	private void buildTable() {
		JPanel tracesPanel = new JPanel(new BorderLayout());
		JPanel statusPanel = new JPanel(new GridBagLayout());
		panel = new JPanel(new BorderLayout());
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.insets = new Insets(4, 8, 4, 8);
		gbc.gridx = 0;
		gbc.anchor = GridBagConstraints.SOUTHEAST;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.weightx = 1.0;
		gbc.gridwidth = gbc.gridheight = 1;
		

		hookTableModel = new TracesTableModel(sledrePlugin.getTool(), currentProgram, null);
		tablePanel = new GhidraThreadedTablePanel<>(hookTableModel);

		table = tablePanel.getTable();

		table.setName("SledRE Results Table");

		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			table.installNavigation(goToService, goToService.getDefaultNavigatable());
		}

		tableFilterPanel = new GhidraTableFilterPanel<>(table, hookTableModel);

		tracesPanel.add(tablePanel, BorderLayout.CENTER);
		tracesPanel.add(tableFilterPanel, BorderLayout.SOUTH);
		tracesPanel.setBorder(BorderFactory.createTitledBorder("Traces"));
		
		ImageIcon sledreIcon = new ImageIcon(ResourceManager.loadImage("images/logo.png").getImage().getScaledInstance(60, 60, Image.SCALE_DEFAULT));
		JLabel iconLabel = new JLabel(sledreIcon, SwingConstants.CENTER);
        statusLabel = new JLabel("", SwingConstants.LEFT);
        statusLabel.setText(Status.DISCONNECTED);
        apiURLLabel = new JLabel("", SwingConstants.LEFT);
        apiURLLabel.setText("<html><b>URL:</b> not configured");
        
        
        statusPanel.add(iconLabel);
        
        gbc.insets = new Insets(20, 16, 4, 8);
        statusPanel.add(statusLabel, gbc);
        gbc.insets = new Insets(4, 16, 20, 8);
        statusPanel.add(apiURLLabel, gbc);
        
        gbc.insets = new Insets(4, 8, 4, 8);
        statusPanel.add(configureSledreButton, gbc);
        statusPanel.add(startButton, gbc);
        statusPanel.add(addTracesCommentsButton, gbc);
        statusPanel.setBorder(BorderFactory.createTitledBorder("SledRE"));
        
        panel.add(statusPanel, BorderLayout.WEST);
        panel.add(tracesPanel, BorderLayout.CENTER);
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
		addCommentsAction.setEnabled(false);
		addCommentsAction.markHelpUnnecessary();
		
		// Analysis
		startAnalysisAction = new DockingAction("Start SledRE analysis", sledrePlugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (canAnalyzeProgram()) {
					configureAPIAction.setEnabled(false);
					addCommentsAction.setEnabled(false);
					startAnalysisAction.setEnabled(false);
					
					configureSledreButton.setEnabled(false);
					addTracesCommentsButton.setEnabled(false);
					startButton.setEnabled(false);
					Task t = new Task("SledRE analysis", true, false, false) {
						@Override
						public void run(TaskMonitor monitor) {
							statusLabel.setText(Status.RUNNING);
							startSledreAnalysis();
							configureAPIAction.setEnabled(true);
							addCommentsAction.setEnabled(true);
							startAnalysisAction.setEnabled(true);
							
							configureSledreButton.setEnabled(true);
							addTracesCommentsButton.setEnabled(true);
							startButton.setEnabled(true);
							statusLabel.setText(Status.CONNECTED);
						}
					};
					new TaskLauncher(t, tool.getToolFrame(), 0);
				}
				else {
					Msg.showError(panel, panel, "SledRE Error", "SledRE only supports Windows PE binary format.");
				}
			}
		};
		startAnalysisAction.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		startAnalysisAction.setEnabled(false);
		startAnalysisAction.markHelpUnnecessary();
		
		// API config
		configureAPIAction = new DockingAction("Configure SledRE URL", sledrePlugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				InputDialog userURL = new InputDialog("SledRE URL", "URL", "http://<ip>:<port>", new InputDialogListener() {
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
						URL url = new URL(userURL.getValue());
						api = new SledreAPI(url, currentProgram);
						if (api.isConnected()) {
							statusLabel.setText(Status.CONNECTED);
							apiURLLabel.setText("<html><b>URL:</b> " + url.toString());
							startAnalysisAction.setEnabled(true);
							startButton.setEnabled(true);
						}
						else {
							Msg.showError(panel, panel, "SledRE Error", "SledRE API is not available, please try again.");
						}
					} catch (MalformedURLException e) {
						Msg.showError(userURL, panel, "SledRE Error", "You entered an invalid URL, please try again.");
					}
				}
			}
		};
		configureAPIAction.setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON, null));
		configureAPIAction.setEnabled(true);
		configureAPIAction.markHelpUnnecessary();
		
        configureSledreButton = configureAPIAction.createButton();
        configureSledreButton.setText("Configure SledRE URL");
        configureSledreButton.addActionListener(new ActionListener() {
        	@Override
        	public void actionPerformed(ActionEvent e) {
        		configureAPIAction.actionPerformed(null);
        	}
        });
        startButton = startAnalysisAction.createButton();
        startButton.setText("Start SledRE analysis");
        startButton.addActionListener(new ActionListener() {
        	@Override
        	public void actionPerformed(ActionEvent e) {
        		startAnalysisAction.actionPerformed(null);
        	}
        });
        addTracesCommentsButton = addCommentsAction.createButton();
        addTracesCommentsButton.setText("Add traces comments");
        addTracesCommentsButton.addActionListener(new ActionListener() {
        	@Override
        	public void actionPerformed(ActionEvent e) {
        		addCommentsAction.actionPerformed(null);
        	}
        });
		
		dockingTool.addLocalAction(this, configureAPIAction);
		dockingTool.addLocalAction(this, startAnalysisAction);
		dockingTool.addLocalAction(this, addCommentsAction);
	}
	
	// Core
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
