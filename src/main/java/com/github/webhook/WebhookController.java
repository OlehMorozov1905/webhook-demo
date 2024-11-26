package com.github.webhook;

import org.apache.commons.codec.binary.Hex;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
@RequestMapping("/webhook")
public class WebhookController {

    private static final String SECRET_KEY = "your_secret_key"; // Введите ваш секретный ключ, указанный в настройках GitHub

    @PostMapping
    public ResponseEntity<String> handleWebhook(@RequestBody String payload,
                                                @RequestHeader(value = "X-Hub-Signature-256", required = false) String signature) {
        if (signature == null || !isValidSignature(payload, signature)) {
            return new ResponseEntity<>("Invalid signature", HttpStatus.FORBIDDEN);
        }

        // Обработка полученного payload
        try {
            // Преобразование payload в JsonNode
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(payload);

            // Пример обработки данных
            String ref = jsonNode.path("ref").asText();  // Ссылка на ветку
            JsonNode commitsNode = jsonNode.path("commits");

            // Логирование информации о коммитах
            for (JsonNode commit : commitsNode) {
                String commitId = commit.path("id").asText();
                String message = commit.path("message").asText();
                System.out.println("Commit ID: " + commitId + ", Message: " + message);
            }

            // Логирование других данных из webhook
            System.out.println("Received push on ref: " + ref);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return new ResponseEntity<>("Webhook received", HttpStatus.OK);
    }

    private boolean isValidSignature(String payload, String signature) {
        try {
            // Генерация подписи с использованием секретного ключа
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] calculatedHash = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            String calculatedSignature = "sha256=" + Hex.encodeHexString(calculatedHash);

            // Сравнение с подписью из заголовка
            return signature.equals(calculatedSignature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
