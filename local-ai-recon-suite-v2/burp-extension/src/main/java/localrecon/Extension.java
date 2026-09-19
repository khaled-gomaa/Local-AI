package localrecon;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.ContextMenuItemsProvider;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

public class Extension implements BurpExtension {
    private MontoyaApi api;

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private final ExecutorService events = Executors.newFixedThreadPool(3);

    private final JTextField backend = new JTextField("http://127.0.0.1:5000", 24);
    private final JTextField hostInput = new JTextField(22);
    private final JComboBox<String> hosts = new JComboBox<>();
    private final JTextArea output = new JTextArea();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Local Recon AI");

        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                if (request.isInScope()) {
                    events.submit(() ->
                            sendEvent(
                                    request.url(),
                                    request.toString(),
                                    "",
                                    request.messageId()
                            )
                    );
                }
                return continueWith(request);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                if (response.initiatingRequest().isInScope()) {
                    events.submit(() ->
                            sendEvent(
                                    response.initiatingRequest().url(),
                                    response.initiatingRequest().toString(),
                                    response.toString(),
                                    response.messageId()
                            )
                    );
                }
                return continueWith(response);
            }
        });

        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                JMenuItem item = new JMenuItem("Local Recon AI - Analyze selected request");
                item.addActionListener(e -> analyze(event));
                return List.of(item);
            }
        });

        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton health = new JButton("Health");
        JButton refresh = new JButton("Refresh");
        JButton analyzeHost = new JButton("Analyze Host");

        top.add(new JLabel("Backend:"));
        top.add(backend);
        top.add(health);
        top.add(refresh);
        top.add(new JLabel("Host:"));
        top.add(hostInput);
        top.add(analyzeHost);

        hosts.setPrototypeDisplayValue("host.example.com");
        hosts.addActionListener(e -> {
            Object selected = hosts.getSelectedItem();
            if (selected != null) {
                hostInput.setText(selected.toString());
                loadInsight(selected.toString());
            }
        });

        JPanel second = new JPanel(new FlowLayout(FlowLayout.LEFT));
        second.add(new JLabel("Observed hosts:"));
        second.add(hosts);

        output.setEditable(false);
        output.setLineWrap(true);
        output.setWrapStyleWord(true);
        output.setText(
                "Local Recon AI\n\n"
                + "Passive observation is enabled for Burp in-scope traffic.\n"
                + "The extension will build an application graph in the background."
        );

        health.addActionListener(e -> requestBackend("/health", null));
        refresh.addActionListener(e -> refreshHosts());
        analyzeHost.addActionListener(e -> {
            String host = hostInput.getText().trim();
            if (!host.isEmpty()) {
                requestBackend("/recon/" + host + "/analyze", "{}");
            }
        });

        panel.add(top, BorderLayout.NORTH);
        panel.add(second, BorderLayout.CENTER);
        panel.add(new JScrollPane(output), BorderLayout.SOUTH);

        // Give the output most of the screen.
        JPanel body = new JPanel(new BorderLayout(8, 8));
        body.add(second, BorderLayout.NORTH);
        body.add(new JScrollPane(output), BorderLayout.CENTER);

        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(panel.getBorder());
        root.add(top, BorderLayout.NORTH);
        root.add(body, BorderLayout.CENTER);

        api.userInterface().registerSuiteTab("Recon AI", root);

        Timer timer = new Timer(5000, e -> refreshHosts());
        timer.setRepeats(true);
        timer.start();
        SwingUtilities.invokeLater(this::refreshHosts);
        events.submit(this::syncProxyHistory);
    }

    
    private void syncProxyHistory() {
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int scanned = 0;
            int forwarded = 0;

            int start = Math.max(0, history.size() - 5000);
            for (int i = start; i < history.size(); i++) {
                ProxyHttpRequestResponse item = history.get(i);
                HttpRequest request = item.request();

                if (!request.isInScope()) {
                    continue;
                }

                String req = request.toString();
                String resp = item.hasResponse() ? item.response().toString() : "";
                long syntheticId = Integer.toUnsignedLong((req + "\n" + resp).hashCode());

                sendEvent(request.url(), req, resp, syntheticId);
                forwarded++;
                scanned++;
            }

            api.logging().logToOutput(
                    "Local Recon AI: history bootstrap scanned=" + scanned
                            + " forwarded=" + forwarded
                            + " of " + history.size()
            );
        } catch (Exception ex) {
            api.logging().logToError(
                    "Local Recon AI history bootstrap failed: " + ex.getMessage()
            );
        }
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

    private void refreshHosts() {
        requestBackend("/recon/hosts", null, true);
    }

    private void loadInsight(String host) {
        if (!host.isBlank()) {
            requestBackend("/recon/" + host + "/insight.txt", null, false);
        }
    }

    private void sendEvent(String url, String req, String resp, long messageId) {
        String json = "{"
                + "\"message_id\":" + quoteJson(Long.toString(messageId))
                + ",\"url\":" + quoteJson(url)
                + ",\"request\":" + quoteJson(req)
                + ",\"response\":" + quoteJson(resp)
                + "}";
        postBackend("/burp_event", json);
    }

    private void postBackend(String path, String json) {
        String base = backend.getText().replaceAll("/$", "");
        try {
            var builder = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(base + path))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(15));
            if (json == null) {
                builder.GET();
            } else {
                builder.POST(BodyPublishers.ofString(json));
            }
            client.send(builder.build(), BodyHandlers.ofString());
        } catch (Exception ex) {
            api.logging().logToError("Local Recon AI event error: " + ex.getMessage());
        }
    }

    private void requestBackend(String path, String json) {
        requestBackend(path, json, false);
    }

    private void requestBackend(String path, String json, boolean hostList) {
        String base = backend.getText().replaceAll("/$", "");
        events.submit(() -> {
            try {
                var builder = java.net.http.HttpRequest.newBuilder()
                        .uri(URI.create(base + path))
                        .header("Content-Type", "application/json")
                        .timeout(Duration.ofSeconds(20));
                if (json == null) {
                    builder.GET();
                } else {
                    builder.POST(BodyPublishers.ofString(json));
                }

                var response = client.send(builder.build(), BodyHandlers.ofString());
                SwingUtilities.invokeLater(() -> {
                    if (hostList && response.statusCode() >= 200 && response.statusCode() < 300) {
                        updateHostsFromJson(response.body());
                    } else {
                        output.setText(response.body());
                    }
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() ->
                        output.setText("Backend error: " + ex.getMessage())
                );
            }
        });
    }

    private void updateHostsFromJson(String body) {
        try {
            String hostField = "\"host\"";
            int cursor = 0;
            java.util.ArrayList<String> found = new java.util.ArrayList<>();

            while (true) {
                int idx = body.indexOf(hostField, cursor);
                if (idx < 0) {
                    break;
                }
                int colon = body.indexOf(':', idx);
                int start = body.indexOf('\"', colon + 1);
                int end = body.indexOf('\"', start + 1);
                if (colon < 0 || start < 0 || end < 0) {
                    break;
                }
                String host = body.substring(start + 1, end);
                if (!found.contains(host)) {
                    found.add(host);
                }
                cursor = end + 1;
            }

            Object selected = hosts.getSelectedItem();
            hosts.removeAllItems();
            found.forEach(hosts::addItem);

            if (selected != null && found.contains(selected.toString())) {
                hosts.setSelectedItem(selected);
            } else if (!found.isEmpty()) {
                hosts.setSelectedIndex(0);
            }

            if (!found.isEmpty()) {
                hostInput.setText(found.get(0));
                loadInsight(found.get(0));
            }
        } catch (Exception ex) {
            output.setText("Host parsing error: " + ex.getMessage());
        }
    }

    private static String quoteJson(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> b.append("\\\\");
                case '\"' -> b.append("\\\"");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                }
            }
        }
        return b.append("\"").toString();
    }
}
