package com.github.webhook;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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

        try {
            // Преобразование payload в JsonNode
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(payload);

            // Поле repository (информация о репозитории)
            JsonNode repositoryNode = jsonNode.path("repository");
            String repositoryName = repositoryNode.path("name").asText();
            String repositoryUrl = repositoryNode.path("url").asText();
            System.out.println("Repository: " + repositoryName);
            System.out.println("Repository URL: " + repositoryUrl);

            // Поле ref (ссылка на ветку)
            String ref = jsonNode.path("ref").asText();
            System.out.println("Ref: " + ref);

            // Поле commits (информация о коммитах)
            JsonNode commitsNode = jsonNode.path("commits");
            for (JsonNode commit : commitsNode) {
                String commitId = commit.path("id").asText();
                String message = commit.path("message").asText();
                System.out.println("Commit ID: " + commitId + ", Message: " + message);
            }

            // Поля added, modified, removed (измененные файлы)
            JsonNode headCommitNode = jsonNode.path("head_commit");
            JsonNode addedFiles = headCommitNode.path("added");
            JsonNode modifiedFiles = headCommitNode.path("modified");
            JsonNode removedFiles = headCommitNode.path("removed");

            // Логирование добавленных файлов
            System.out.println("Added files: ");
            addedFiles.forEach(file -> System.out.println(file.asText()));

            // Логирование измененных файлов
            System.out.println("Modified files: ");
            modifiedFiles.forEach(file -> System.out.println(file.asText()));

            // Логирование удаленных файлов
            System.out.println("Removed files: ");
            removedFiles.forEach(file -> System.out.println(file.asText()));

        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("Error processing webhook", HttpStatus.INTERNAL_SERVER_ERROR);
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
