package localrecon;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponseReceived;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

import javax.swing.*;
import java.awt.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Extension implements BurpExtension {
    private MontoyaApi api;
    private final HttpClient client = HttpClient.newHttpClient();
    private final JTextField backend = new JTextField("http://127.0.0.1:5000", 30);
    private final JTextArea output = new JTextArea();
    private final ExecutorService events = Executors.newFixedThreadPool(2);

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Local Recon AI");

        // Passive observer: never modifies traffic and only forwards Burp in-scope
        // request/response pairs to the local analysis service.
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                if (request.isInScope()) {
                    events.submit(() -> sendEvent(request.url(), request.toString(), null, request.messageId()));
                }
                return continueWith(request);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                if (response.initiatingRequest().isInScope()) {
                    events.submit(() -> sendEvent(
                            response.initiatingRequest().url(),
                            response.initiatingRequest().toString(),
                            response.toString(),
                            response.messageId()
                    ));
                }
                return continueWith(response);
            }
        });

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


    private void sendEvent(String url, String req, String resp, long messageId) {
        String json = "{"
                + "\"message_id\":" + quoteJson(Long.toString(messageId))
                + ",\"url\":" + quoteJson(url)
                + ",\"request\":" + quoteJson(req)
                + ",\"response\":" + quoteJson(resp == null ? "" : resp)
                + "}";
        postBackend("/burp_event", json);
    }

    private void postBackend(String path, String json) {
        String base = backend.getText().replaceAll("/$", "");
        try {
            var builder = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(base + path))
                    .header("Content-Type", "application/json")
                    .POST(BodyPublishers.ofString(json));
            client.send(builder.build(), BodyHandlers.ofString());
        } catch (Exception ex) {
            api.logging().logToError("Local Recon AI event error: " + ex.getMessage());
        }
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
