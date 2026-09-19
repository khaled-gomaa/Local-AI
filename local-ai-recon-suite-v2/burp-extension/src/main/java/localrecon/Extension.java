package localrecon;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponseReceived;

import javax.swing.*;
import java.awt.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.ArrayList;
import java.util.List;

public class Extension implements BurpExtension {
    private MontoyaApi api;
    private final HttpClient client = HttpClient.newHttpClient();
    private final JTextField backend = new JTextField("http://127.0.0.1:5000", 30);
    private final JTextArea output = new JTextArea();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Local Recon AI");

        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                JMenuItem item = new JMenuItem("Local Recon AI - Analyze request");
                item.addActionListener(e -> analyze(event));
                return List.of(item);
            }
        });

        JPanel panel = new JPanel(new BorderLayout(8, 8));
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton health = new JButton("Health");
        JButton analyze = new JButton("Analyze selected request");
        top.add(new JLabel("Backend:"));
        top.add(backend);
        top.add(health);
        top.add(analyze);

        output.setEditable(false);
        output.setLineWrap(true);
        output.setWrapStyleWord(true);

        health.addActionListener(e -> requestBackend("/health", null));
        analyze.addActionListener(e -> {
            var selected = api.userInterface().currentEditorTab();
            JOptionPane.showMessageDialog(panel,
                    "Use the request context menu to analyze a selected request.",
                    "Local Recon AI", JOptionPane.INFORMATION_MESSAGE);
        });

        panel.add(top, BorderLayout.NORTH);
        panel.add(new JScrollPane(output), BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("Recon AI", panel);
    }

    private void analyze(ContextMenuEvent event) {
        var selected = event.selectedRequestResponses();
        if (selected == null || selected.isEmpty()) {
            output.setText("No request selected.");
            return;
        }
        HttpRequest req = selected.get(0).request();
        String raw = req.toString();
        String json = "{\"request\":" + quoteJson(raw) + "}";
        requestBackend("/burp_analyze", json);
    }

    private void requestBackend(String path, String json) {
        String base = backend.getText().replaceAll("/$", "");
        new Thread(() -> {
            try {
                var builder = java.net.http.HttpRequest.newBuilder()
                        .uri(URI.create(base + path))
                        .header("Content-Type", "application/json");
                if (json == null) {
                    builder.GET();
                } else {
                    builder.POST(BodyPublishers.ofString(json));
                }
                var response = client.send(builder.build(), BodyHandlers.ofString());
                SwingUtilities.invokeLater(() -> output.setText(response.body()));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> output.setText("Backend error: " + ex.getMessage()));
            }
        }, "local-recon-ai-http").start();
    }

    private static String quoteJson(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> b.append("\\\\");
                case '"' -> b.append("\\\"");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20) b.append(String.format("\\u%04x", (int)c));
                    else b.append(c);
                }
            }
        }
        return b.append("\"").toString();
    }
}
