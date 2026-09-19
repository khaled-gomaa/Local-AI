# Burp Recon AI bridge

This extension is deliberately thin.

Burp -> Montoya Java extension -> `http://127.0.0.1:5000/burp_analyze` -> Local RAG/Ollama.

It does not embed Python or Jython.

Build:

```bash
chmod +x gradlew
./gradlew clean jar
```

Requirements:
- JDK 21
- network access for Maven Central on first build

If `gradle` is already installed, the local launcher will use it. Otherwise it downloads Gradle 8.8 into the user's cache.
