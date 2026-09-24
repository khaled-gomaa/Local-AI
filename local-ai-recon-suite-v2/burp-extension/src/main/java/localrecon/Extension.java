package localrecon;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
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
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
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

    private final ExecutorService workers =
            Executors.newFixedThreadPool(3);

    private final JTextField backend =
            new JTextField("http://127.0.0.1:5000", 24);

    private final JTextField programField =
            new JTextField("program-name", 18);

    private final JComboBox<String> hosts =
            new JComboBox<>();

    private final JTextArea output =
            new JTextArea();

    private volatile String activeProgram = "";
    private volatile String activeHost = "";

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Local Recon AI");

        registerPassiveObserver();
        registerContextMenu();

        JPanel root = buildUi();
        api.userInterface().registerSuiteTab("Recon AI", root);

        Timer timer = new Timer(5000, e -> refreshHosts());
        timer.setRepeats(true);
        timer.start();

        SwingUtilities.invokeLater(() -> {
            activeProgram = programField.getText().trim();
            refreshHosts();
        });

        workers.submit(this::syncProxyHistory);
    }

    private void registerPassiveObserver() {
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(
                    HttpRequestToBeSent request) {

                if (request.isInScope() && hasActiveProgram()) {
                    workers.submit(() -> sendEvent(
                            request.url(),
                            request.toString(),
                            "",
                            request.messageId()
                    ));
                }

                return continueWith(request);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(
                    HttpResponseReceived response) {

                if (response.initiatingRequest().isInScope()
                        && hasActiveProgram()) {
                    workers.submit(() -> sendEvent(
                            response.initiatingRequest().url(),
                            response.initiatingRequest().toString(),
                            response.toString(),
                            response.messageId()
                    ));
                }

                return continueWith(response);
            }
        });
    }

    private void registerContextMenu() {
        api.userInterface().registerContextMenuItemsProvider(
                new ContextMenuItemsProvider() {
                    @Override
                    public List<Component> provideMenuItems(
                            ContextMenuEvent event) {

                        JMenuItem item = new JMenuItem(
                                "Local Recon AI - Analyze selected request"
                        );
                        item.addActionListener(e -> analyze(event));
                        return List.of(item);
                    }
                }
        );
    }

    private JPanel buildUi() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton health = new JButton("Health");
        JButton startSession = new JButton("Start / Resume Today");
        JButton refresh = new JButton("Refresh");
        JButton analyzeHost = new JButton("Review Host");

        top.add(new JLabel("Backend:"));
        top.add(backend);

        top.add(new JLabel("Program:"));
        top.add(programField);

        top.add(health);
        top.add(startSession);
        top.add(refresh);
        top.add(analyzeHost);

        JPanel hostBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        hostBar.add(new JLabel("Observed hosts:"));
        hosts.setPrototypeDisplayValue("api.example.com");
        hosts.addActionListener(e -> {
            Object value = hosts.getSelectedItem();
            if (value != null) {
                activeHost = value.toString();
                loadReport(activeHost);
            }
        });
        hostBar.add(hosts);

        output.setEditable(false);
        output.setLineWrap(true);
        output.setWrapStyleWord(true);
        output.setText(
                "Local Recon AI\n\n"
                        + "Manual-first workflow.\n"
                        + "Enter a program name and click Start / Resume Today.\n"
                        + "The extension will passively review in-scope traffic in the background."
        );

        health.addActionListener(e ->
                requestBackend("/health", null, false, null)
        );

        startSession.addActionListener(e -> {
            String program = programField.getText().trim();

            if (program.isBlank() || program.equalsIgnoreCase("program-name")) {
                output.setText(
                        "Enter the assessment program name first."
                );
                return;
            }

            activeProgram = program;
            requestBackend(
                    "/projects/" + pathPart(program) + "/start",
                    "{}",
                    false,
                    "briefing"
            );
            workers.submit(this::syncProxyHistory);
            refreshHosts();
        });

        refresh.addActionListener(e -> refreshHosts());

        analyzeHost.addActionListener(e -> {
            String program = activeProgram;
            String host = activeHost;

            if (!hasActiveProgram() || host.isBlank()) {
                output.setText(
                        "Start/resume a program and select an observed host first."
                );
                return;
            }

            requestBackend(
                    "/projects/" + pathPart(program)
                            + "/shadow/" + pathPart(host) + "/review",
                    "{}",
                    false,
                    null
            );
        });

        root.add(top, BorderLayout.NORTH);

        JPanel body = new JPanel(new BorderLayout(8, 8));
        body.add(hostBar, BorderLayout.NORTH);
        body.add(new JScrollPane(output), BorderLayout.CENTER);

        root.add(body, BorderLayout.CENTER);
        return root;
    }

    private boolean hasActiveProgram() {
        return activeProgram != null
                && !activeProgram.isBlank()
                && !activeProgram.equalsIgnoreCase("program-name");
    }

    private String pathPart(String value) {
        return URLEncoder.encode(
                value,
                StandardCharsets.UTF_8
        ).replace("+", "%20");
    }

    private void analyze(ContextMenuEvent event) {
        var selected = event.selectedRequestResponses();

        if (selected == null || selected.isEmpty()) {
            output.setText("No request selected.");
            return;
        }

        HttpRequest request = selected.get(0).request();
        String raw = request.toString();
        String json = "{\"request\":" + quoteJson(raw) + "}";

        requestBackend("/burp_analyze", json, false, "analysis");
    }

    private void refreshHosts() {
        if (!hasActiveProgram()) {
            return;
        }

        requestBackend(
                "/projects/" + pathPart(activeProgram) + "/hosts",
                null,
                true,
                null
        );
    }

    private void loadReport(String host) {
        if (!hasActiveProgram() || host == null || host.isBlank()) {
            return;
        }

        requestBackend(
                "/projects/" + pathPart(activeProgram)
                        + "/report/" + pathPart(host),
                null,
                false,
                null
        );
    }

    private void syncProxyHistory() {
        try {
            String program = programField.getText().trim();

            if (program.isBlank() || program.equalsIgnoreCase("program-name")) {
                api.logging().logToOutput(
                        "Local Recon AI: enter a program name to enable passive history review."
                );
                return;
            }

            activeProgram = program;

            List<ProxyHttpRequestResponse> history =
                    api.proxy().history();

            int forwarded = 0;

            int start = Math.max(0, history.size() - 5000);

            for (int i = start; i < history.size(); i++) {
                ProxyHttpRequestResponse item = history.get(i);

                HttpRequest request = item.request();

                if (!request.isInScope()) {
                    continue;
                }

                String req = request.toString();
                String resp = item.hasResponse()
                        ? item.response().toString()
                        : "";

                long syntheticId = Integer.toUnsignedLong(
                        (req + "\n" + resp).hashCode()
                );

                sendEvent(
                        request.url(),
                        req,
                        resp,
                        syntheticId
                );

                forwarded++;
            }

            api.logging().logToOutput(
                    "Local Recon AI history bootstrap: forwarded "
                            + forwarded
                            + " in-scope items from "
                            + history.size()
                            + " history entries."
            );

        } catch (Exception ex) {
            api.logging().logToError(
                    "Local Recon AI history bootstrap failed: "
                            + ex.getMessage()
            );
        }
    }

    private void sendEvent(
            String url,
            String request,
            String response,
            long messageId) {

        if (!hasActiveProgram()) {
            return;
        }

        String json = "{"
                + "\"message_id\":"
                + quoteJson(Long.toString(messageId))
                + ",\"program\":"
                + quoteJson(activeProgram)
                + ",\"url\":"
                + quoteJson(url)
                + ",\"request\":"
                + quoteJson(request)
                + ",\"response\":"
                + quoteJson(response == null ? "" : response)
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

            client.send(
                    builder.build(),
                    BodyHandlers.ofString()
            );

        } catch (Exception ex) {
            api.logging().logToError(
                    "Local Recon AI event error: "
                            + ex.getMessage()
            );
        }
    }

    private void requestBackend(
            String path,
            String json,
            boolean hostList,
            String textField) {

        String base = backend.getText().replaceAll("/$", "");

        workers.submit(() -> {
            try {
                var builder = java.net.http.HttpRequest.newBuilder()
                        .uri(URI.create(base + path))
                        .header("Content-Type", "application/json")
                        .timeout(Duration.ofSeconds(30));

                if (json == null) {
                    builder.GET();
                } else {
                    builder.POST(BodyPublishers.ofString(json));
                }

                var response = client.send(
                        builder.build(),
                        BodyHandlers.ofString()
                );

                SwingUtilities.invokeLater(() -> {
                    if (hostList
                            && response.statusCode() >= 200
                            && response.statusCode() < 300) {
                        updateHostsFromJson(response.body());
                    } else if (textField != null
                            && response.statusCode() >= 200
                            && response.statusCode() < 300) {
                        output.setText(extractJsonStringField(
                                response.body(),
                                textField
                        ));
                    } else {
                        output.setText(response.body());
                    }
                });

            } catch (Exception ex) {
                SwingUtilities.invokeLater(() ->
                        output.setText(
                                "Backend error: "
                                        + ex.getMessage()
                        )
                );
            }
        });
    }

    private String extractJsonStringField(
            String body,
            String field) {
        String marker = "\"" + field + "\":\"";
        int start = body.indexOf(marker);

        if (start < 0) {
            return body;
        }

        start += marker.length();

        StringBuilder value = new StringBuilder();
        boolean escaped = false;

        for (int i = start; i < body.length(); i++) {
            char ch = body.charAt(i);

            if (escaped) {
                switch (ch) {
                    case 'n' -> value.append('\n');
                    case 'r' -> value.append('\r');
                    case 't' -> value.append('\t');
                    case '\\' -> value.append('\\');
                    case '"' -> value.append('"');
                    default -> value.append(ch);
                }
                escaped = false;
                continue;
            }

            if (ch == '\\') {
                escaped = true;
                continue;
            }

            if (ch == '"') {
                break;
            }

            value.append(ch);
        }

        return value.toString();
    }

    private void updateHostsFromJson(String body) {
        try {
            String hostField = "\"host\"";
            int cursor = 0;

            ArrayList<String> found = new ArrayList<>();

            while (true) {
                int idx = body.indexOf(
                        hostField,
                        cursor
                );

                if (idx < 0) {
                    break;
                }

                int colon = body.indexOf(
                        ':',
                        idx
                );

                int start = body.indexOf(
                        '"',
                        colon + 1
                );

                int end = body.indexOf(
                        '"',
                        start + 1
                );

                if (colon < 0
                        || start < 0
                        || end < 0) {
                    break;
                }

                String host = body.substring(
                        start + 1,
                        end
                );

                if (!found.contains(host)) {
                    found.add(host);
                }

                cursor = end + 1;
            }

            Object selected = hosts.getSelectedItem();

            hosts.removeAllItems();

            found.forEach(hosts::addItem);

            if (selected != null
                    && found.contains(selected.toString())) {
                hosts.setSelectedItem(selected);
            } else if (!found.isEmpty()) {
                hosts.setSelectedIndex(0);
            }

            if (!found.isEmpty()) {
                activeHost = found.get(0);
                loadReport(activeHost);
            }

        } catch (Exception ex) {
            output.setText(
                    "Host parsing error: "
                            + ex.getMessage()
            );
        }
    }

    private static String quoteJson(String value) {
        StringBuilder builder =
                new StringBuilder("\"");

        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);

            switch (c) {
                case '\\' -> builder.append("\\\\");
                case '"' -> builder.append("\\\"");
                case '\n' -> builder.append("\\n");
                case '\r' -> builder.append("\\r");
                case '\t' -> builder.append("\\t");
                default -> {
                    if (c < 0x20) {
                        builder.append(
                                String.format(
                                        "\\u%04x",
                                        (int) c
                                )
                        );
                    } else {
                        builder.append(c);
                    }
                }
            }
        }

        return builder.append("\"").toString();
    }
}
