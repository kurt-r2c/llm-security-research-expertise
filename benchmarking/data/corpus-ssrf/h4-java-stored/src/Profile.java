import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class Profile {
    String webhookUrl;
    String iconUrl;

    // PUT /profile
    void update(String webhook, String icon) {
        if (!webhook.matches("https://hooks\\.example\\.com/[A-Za-z0-9]{20}")) {
            throw new IllegalArgumentException("invalid webhook");
        }
        this.webhookUrl = webhook;
        this.iconUrl = icon;
    }

    // nightly job
    void sync(HttpClient c) throws Exception {
        c.send(HttpRequest.newBuilder().uri(URI.create(webhookUrl)).POST(HttpRequest.BodyPublishers.noBody()).build(),
            HttpResponse.BodyHandlers.discarding());
        c.send(HttpRequest.newBuilder().uri(URI.create(iconUrl)).GET().build(),
            HttpResponse.BodyHandlers.ofByteArray());
    }
}
