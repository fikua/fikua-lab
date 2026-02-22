package com.fikua.lab.admin;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import io.javalin.http.sse.SseClient;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Custom Logback appender that buffers recent log events in a ring buffer
 * and broadcasts new events to connected SSE clients.
 */
public class LogBufferAppender extends AppenderBase<ILoggingEvent> {

    private static final int BUFFER_SIZE = 500;
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_INSTANT;

    private static final Queue<LogEntry> BUFFER = new ConcurrentLinkedQueue<>();
    private static final CopyOnWriteArrayList<SseClient> SSE_CLIENTS = new CopyOnWriteArrayList<>();

    public record LogEntry(String timestamp, String level, String source, String message) {}

    @Override
    protected void append(ILoggingEvent event) {
        String source = event.getLoggerName();
        int lastDot = source.lastIndexOf('.');
        if (lastDot >= 0) {
            source = source.substring(lastDot + 1);
        }

        LogEntry entry = new LogEntry(
                Instant.ofEpochMilli(event.getTimeStamp())
                        .atOffset(ZoneOffset.UTC)
                        .format(ISO_FORMATTER),
                event.getLevel().toString(),
                source,
                event.getFormattedMessage()
        );

        BUFFER.add(entry);
        while (BUFFER.size() > BUFFER_SIZE) {
            BUFFER.poll();
        }

        String json = toJson(entry);
        for (SseClient client : SSE_CLIENTS) {
            try {
                client.sendEvent("log", json);
            } catch (Exception ignored) {
                // Client disconnected — will be cleaned up by onClose
            }
        }
    }

    public static List<LogEntry> getRecentLogs() {
        return List.copyOf(BUFFER);
    }

    public static void addClient(SseClient client) {
        SSE_CLIENTS.add(client);
    }

    public static void removeClient(SseClient client) {
        SSE_CLIENTS.remove(client);
    }

    private static String toJson(LogEntry entry) {
        return "{\"timestamp\":\"" + escapeJson(entry.timestamp()) +
                "\",\"level\":\"" + escapeJson(entry.level()) +
                "\",\"source\":\"" + escapeJson(entry.source()) +
                "\",\"message\":\"" + escapeJson(entry.message()) + "\"}";
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
