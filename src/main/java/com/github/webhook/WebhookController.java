package com.github.webhook;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/webhook")
public class WebhookController {

    private static final String SECRET_KEY = "your_secret_key"; // Ваш секретный ключ
    private static final Logger logger = LoggerFactory.getLogger(WebhookController.class); // Логгер

    @PostMapping
    public ResponseEntity<String> handleWebhook(@RequestBody String payload,
                                                @RequestHeader(value = "X-Hub-Signature-256", required = false) String signature) {
        // Проверка подписи
        if (signature == null || !isValidSignature(payload, signature)) {
            logger.error("Invalid or missing signature");
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
            logger.info("Repository: " + repositoryName);
            logger.info("Repository URL: " + repositoryUrl);

            // Поле ref (ссылка на ветку)
            String ref = jsonNode.path("ref").asText();
            logger.info("Ref: " + ref);

            // Поле commits (информация о коммитах)
            JsonNode commitsNode = jsonNode.path("commits");
            for (JsonNode commit : commitsNode) {
                String commitId = commit.path("id").asText();
                String message = commit.path("message").asText();
                logger.info("Commit ID: " + commitId + ", Message: " + message);
            }

            // Поля added, modified, removed (измененные файлы)
            JsonNode headCommitNode = jsonNode.path("head_commit");
            JsonNode addedFiles = headCommitNode.path("added");
            JsonNode modifiedFiles = headCommitNode.path("modified");
            JsonNode removedFiles = headCommitNode.path("removed");

            // Логирование добавленных файлов
            logger.info("Added files: ");
            addedFiles.forEach(file -> logger.info(file.asText()));

            // Логирование измененных файлов
            logger.info("Modified files: ");
            modifiedFiles.forEach(file -> logger.info(file.asText()));

            // Логирование удаленных файлов
            logger.info("Removed files: ");
            removedFiles.forEach(file -> logger.info(file.asText()));

        } catch (Exception e) {
            logger.error("Error processing webhook", e);
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
            logger.error("Error validating signature", e);
            return false;
        }
    }
}
