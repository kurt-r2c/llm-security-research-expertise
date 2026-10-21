import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;

public class Jobs {
    static final Map<String, String> subscriptions = new HashMap<>();
    static final HttpClient client = HttpClient.newHttpClient();

    // POST /subscribe  body: name, callbackUrl
    public static void subscribe(String name, String callbackUrl) {
        subscriptions.put(name, callbackUrl);
    }

    // runs every minute
    public static void notifyAll(String payload) throws Exception {
        for (String cb : subscriptions.values()) {
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(cb))
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();
            client.send(req, HttpResponse.BodyHandlers.ofString());
        }
    }

    // GET /thumb?src=...
    public static String thumb(String src) throws Exception {
        if (!src.matches("https://cdn\\.example\\.com/img/[a-z0-9]+\\.png")) {
            throw new IllegalArgumentException("bad src");
        }
        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(src)).GET().build();
        return client.send(req, HttpResponse.BodyHandlers.ofString()).body();
    }
}
