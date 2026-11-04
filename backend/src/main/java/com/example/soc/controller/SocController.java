package com.example.soc.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;

import java.time.*;
import java.sql.Timestamp;
import java.util.*;

@RestController
@RequestMapping("/api")
public class SocController {

    private final JdbcTemplate db;
    private final StringRedisTemplate redis;
    private final SimpMessagingTemplate ws;
    private final WebClient ml;
    private final ObjectMapper json = new ObjectMapper();

    public SocController(
            JdbcTemplate db,
            StringRedisTemplate redis,
            SimpMessagingTemplate ws,
            @Value("${app.ml-url}") String mlUrl) {

        this.db = db;
        this.redis = redis;
        this.ws = ws;
        this.ml = WebClient.builder().baseUrl(mlUrl).build();
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok", "service", "soc-backend");
    }

    record Event(
            String timestamp,
            String sourceType,
            String username,
            String ip,
            String host,
            String action,
            String outcome,
            Map<String, Object> extra
    ) {}

    @PostMapping("/logs")
    public Map<String, Object> ingest(@RequestBody List<Event> events) {
        int count = 0;

        for (Event e : events) {
            process(e);
            count++;
        }

        return Map.of("accepted", count);
    }

    @PostMapping("/logs/single")
    public Map<String, Object> ingestOne(@RequestBody Event e) {
        process(e);
        return Map.of("accepted", 1);
    }

    private void process(Event e) {
        try {
            Instant ts = e.timestamp() == null
                    ? Instant.now()
                    : Instant.parse(e.timestamp());

            String raw = json.writeValueAsString(
                    e.extra() == null ? Map.of() : e.extra()
            );

            Long id = db.queryForObject(
                    "INSERT INTO log_events " +
                    "(event_timestamp, source_type, username, ip, host, action, outcome, raw) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?::jsonb) RETURNING id",
                    Long.class,
                    Timestamp.from(ts),
                    safe(e.sourceType()),
                    e.username(),
                    e.ip(),
                    e.host(),
                    safe(e.action()),
                    e.outcome(),
                    raw
            );

            List<String> reasons = new ArrayList<>();
            String technique = null;
            int ruleWeight = 0;

            // Failed login detection
            if ("LOGIN".equalsIgnoreCase(e.sourceType())
                    && "FAILURE".equalsIgnoreCase(e.outcome())) {

                String k = "fail:" + (e.ip() == null ? "unknown" : e.ip());

                Long n = redis.opsForValue().increment(k);
                redis.expire(k, Duration.ofMinutes(5));

                if (n != null && n >= 5) {
                    reasons.add(n + " failed logins from one IP in 5 minutes");
                    technique = "T1110";
                    ruleWeight = 75;
                }
            }

            // Unusual activity hours
            int hour = ts.atZone(ZoneOffset.UTC).getHour();

            if (hour < 6 || hour >= 22) {
                reasons.add("Activity occurred during unusual UTC hours");

                if (technique == null) {
                    technique = "T1078";
                }

                ruleWeight = Math.max(ruleWeight, 35);
            }

            // Unusual file access detection
            if ("FILE".equalsIgnoreCase(e.sourceType())
                    && e.extra() != null
                    && number(e.extra().get("filesAccessed")) >= 20) {

                reasons.add("Unusually high number of file accesses");
                technique = "T1005";
                ruleWeight = Math.max(ruleWeight, 65);
            }

            // ML feature extraction
            Map<String, Object> features = new HashMap<>();

            features.put(
                    "failed_logins",
                    "FAILURE".equalsIgnoreCase(e.outcome()) ? 1 : 0
            );

            features.put("hour", hour);

            features.put(
                    "files_accessed",
                    e.extra() == null ? 0 : number(e.extra().get("filesAccessed"))
            );

            features.put("distinct_ips", 1);

            features.put(
                    "bytes_transferred",
                    e.extra() == null ? 0 : number(e.extra().get("bytesTransferred"))
            );

            // ML anomaly scoring
            double anomaly = 0;

            try {
                Map<?, ?> score = ml.post()
                        .uri("/score")
                        .bodyValue(Map.of("features", features))
                        .retrieve()
                        .bodyToMono(Map.class)
                        .block(Duration.ofSeconds(2));

                if (score != null
                        && score.get("anomaly_score") instanceof Number v) {

                    anomaly = v.doubleValue();
                }

            } catch (Exception ignored) {
                // Continue rule-based detection if ML service is unavailable.
            }

            if (anomaly >= 0.72) {
                reasons.add(
                        String.format(Locale.US, "ML anomaly score %.2f", anomaly)
                );

                ruleWeight = Math.max(
                        ruleWeight,
                        Math.min(85, (int) (anomaly * 100))
                );

                if (technique == null) {
                    technique = "T1078";
                }
            }

            // Alert generation
            if (!reasons.isEmpty()) {

                int risk = Math.min(
                        100,
                        (int) Math.round(ruleWeight * 0.65 + anomaly * 35)
                );

                String severity = risk >= 70
                        ? "HIGH"
                        : risk >= 40 ? "MEDIUM" : "LOW";

                Long alertId = db.queryForObject(
                        "INSERT INTO alerts " +
                        "(event_id, source, risk_score, severity, reasons, mitre_technique_id) " +
                        "VALUES (?, ?, ?, ?, ?, ?) RETURNING id",

                        Long.class,

                        id,
                        anomaly >= 0.72 && ruleWeight < 70 ? "ML" : "RULE",
                        risk,
                        severity,
                        String.join("; ", reasons),
                        technique
                );

                Map<String, Object> alert = Map.of(
                        "id", alertId,
                        "eventId", id,
                        "riskScore", risk,
                        "severity", severity,
                        "reasons", String.join("; ", reasons),
                        "technique", technique,
                        "status", "NEW",
                        "createdAt", Instant.now().toString()
                );

                ws.convertAndSend("/topic/alerts", alert);

                redis.convertAndSend(
                        "soc:alerts",
                        json.writeValueAsString(alert)
                );
            }

        } catch (Exception ex) {
            throw new RuntimeException("Could not process event", ex);
        }
    }

    private String safe(String s) {
        return s == null ? "SYSTEM" : s;
    }

    private int number(Object o) {
        return o instanceof Number n ? n.intValue() : 0;
    }

    // LOG VIEWER
    @GetMapping("/logs")
    public List<Map<String, Object>> logs(
            @RequestParam(defaultValue = "100") int limit) {

        return db.queryForList(
                "SELECT id, event_timestamp, source_type, username, ip, " +
                "host, action, outcome, raw FROM log_events " +
                "ORDER BY event_timestamp DESC LIMIT ?",
                Math.min(Math.max(limit, 1), 500)
        );
    }

    // ALERTS - UPDATED SQL FILTERING
    @GetMapping("/alerts")
    public List<Map<String, Object>> alerts(
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String status) {

        StringBuilder sql = new StringBuilder(
                "SELECT a.*, m.name AS technique_name " +
                "FROM alerts a " +
                "LEFT JOIN mitre_techniques m " +
                "ON a.mitre_technique_id = m.id " +
                "WHERE 1=1"
        );

        List<Object> params = new ArrayList<>();

        if (severity != null && !severity.isBlank()) {
            sql.append(" AND a.severity = ?");
            params.add(severity);
        }

        if (status != null && !status.isBlank()) {
            sql.append(" AND a.status = ?");
            params.add(status);
        }

        sql.append(" ORDER BY a.created_at DESC LIMIT 300");

        return db.queryForList(sql.toString(), params.toArray());
    }

    // DASHBOARD
    @GetMapping("/dashboard")
    public Map<String, Object> dashboard() {

        return Map.of(
                "totalEvents",
                db.queryForObject("SELECT count(*) FROM log_events", Long.class),

                "totalAlerts",
                db.queryForObject("SELECT count(*) FROM alerts", Long.class),

                "openHigh",
                db.queryForObject(
                        "SELECT count(*) FROM alerts " +
                        "WHERE severity='HIGH' AND status<>'RESOLVED'",
                        Long.class
                ),

                "severity",
                db.queryForList(
                        "SELECT severity, count(*) AS count " +
                        "FROM alerts GROUP BY severity"
                ),

                "recent",
                db.queryForList(
                        "SELECT date_trunc('hour',created_at) AS hour, " +
                        "count(*) AS count FROM alerts " +
                        "WHERE created_at > now()-interval '24 hours' " +
                        "GROUP BY 1 ORDER BY 1"
                )
        );
    }

    // UPDATE ALERT STATUS
    @PatchMapping("/alerts/{id}/status")
    public Map<String, Object> status(
            @PathVariable long id,
            @RequestBody Map<String, String> body,
            Authentication auth) {

        String next = body.get("status");

        Set<String> allowed = Set.of(
                "NEW",
                "ACKNOWLEDGED",
                "INVESTIGATING",
                "RESOLVED",
                "FALSE_POSITIVE"
        );

        if (!allowed.contains(next)) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid status"
            );
        }

        int n = db.update(
                "UPDATE alerts SET status=? WHERE id=?",
                next,
                id
        );

        if (n == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }

        audit(
                auth,
                "ALERT_STATUS_CHANGED",
                "alert",
                String.valueOf(id),
                body
        );

        return Map.of("id", id, "status", next);
    }

    // ADD INCIDENT NOTE
    @PostMapping("/alerts/{id}/notes")
    public Map<String, Object> note(
            @PathVariable long id,
            @RequestBody Map<String, String> body,
            Authentication auth) {

        String email = auth.getName();

        Long uid = db.queryForObject(
                "SELECT id FROM users WHERE email=?",
                Long.class,
                email
        );

        Long note = db.queryForObject(
                "INSERT INTO incident_notes(alert_id, author_id, note) " +
                "VALUES (?, ?, ?) RETURNING id",
                Long.class,
                id,
                uid,
                body.getOrDefault("note", "")
        );

        audit(
                auth,
                "NOTE_ADDED",
                "alert",
                String.valueOf(id),
                body
        );

        return Map.of(
                "id", note,
                "note", body.getOrDefault("note", "")
        );
    }

    // GET INCIDENT NOTES
    @GetMapping("/alerts/{id}/notes")
    public List<Map<String, Object>> notes(@PathVariable long id) {

        return db.queryForList(
                "SELECT n.*, u.email AS author " +
                "FROM incident_notes n " +
                "LEFT JOIN users u ON n.author_id=u.id " +
                "WHERE alert_id=? ORDER BY created_at",
                id
        );
    }

    // ADMIN AUDIT
    @GetMapping("/admin/audit")
    @PreAuthorize("hasRole('ADMIN')")
    public List<Map<String, Object>> auditLogs() {

        return db.queryForList(
                "SELECT id, actor_id, action, target_type, target_id, details::text AS details, created_at " +
                "FROM audit_logs ORDER BY created_at DESC LIMIT 500"
        );
    }

    // ADMIN RULES
    @GetMapping("/admin/rules")
    @PreAuthorize("hasRole('ADMIN')")
    public List<Map<String, Object>> rules() {

        return db.queryForList(
                "SELECT * FROM detection_rules ORDER BY id"
        );
    }

    // UPDATE DETECTION RULE
    @PutMapping("/admin/rules/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> updateRule(
            @PathVariable long id,
            @RequestBody Map<String, Object> b,
            Authentication a) {

        int updated = db.update(
                "UPDATE detection_rules SET enabled=? WHERE id=?",
                Boolean.TRUE.equals(b.get("enabled")),
                id
        );

        if (updated == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }

        audit(
                a,
                "RULE_UPDATED",
                "rule",
                String.valueOf(id),
                b
        );

        return Map.of("updated", true);
    }

    // ADMIN USERS
    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    public List<Map<String, Object>> users() {

        return db.queryForList(
                "SELECT id, email, role, created_at FROM users ORDER BY id"
        );
    }

    // UPDATE USER ROLE
    @PatchMapping("/admin/users/{id}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> role(
            @PathVariable long id,
            @RequestBody Map<String, String> b,
            Authentication a) {

        String role = b.get("role");

        if (!Set.of("ADMIN", "ANALYST").contains(role)) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid role"
            );
        }

        int updated = db.update(
                "UPDATE users SET role=? WHERE id=?",
                role,
                id
        );

        if (updated == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }

        audit(
                a,
                "USER_ROLE_CHANGED",
                "user",
                String.valueOf(id),
                b
        );

        return Map.of("updated", true);
    }

    // AUDIT HELPER
    private void audit(
            Authentication a,
            String action,
            String type,
            String id,
            Map<?, ?> details) {

        try {
            Long actor = db.queryForObject(
                    "SELECT id FROM users WHERE email=?",
                    Long.class,
                    a.getName()
            );

            db.update(
                    "INSERT INTO audit_logs " +
                    "(actor_id, action, target_type, target_id, details) " +
                    "VALUES (?, ?, ?, ?, ?::jsonb)",

                    actor,
                    action,
                    type,
                    id,
                    json.writeValueAsString(details)
            );

        } catch (Exception ignored) {
            // Audit failure must not break the main operation.
        }
    }
}