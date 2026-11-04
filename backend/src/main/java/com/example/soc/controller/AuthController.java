package com.example.soc.controller;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@RestController @RequestMapping("/api/auth")
public class AuthController {
  private final JdbcTemplate db; private final PasswordEncoder encoder; private final SecretKey key;
  public AuthController(JdbcTemplate db,PasswordEncoder encoder,@Value("${app.jwt-secret}") String secret) { this.db=db; this.encoder=encoder; this.key=Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)); }
  record Register(@Email @NotBlank String email,@NotBlank String password) {}
  record Login(@Email @NotBlank String email,@NotBlank String password) {}
  @PostMapping("/register") @ResponseStatus(HttpStatus.CREATED) public Map<String,Object> register(@Valid @RequestBody Register r) {
    if(r.password().length()<10) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Password must contain at least 10 characters");
    try { db.update("INSERT INTO users(email,password_hash,role) VALUES (?,?, 'ANALYST')",r.email().toLowerCase(),encoder.encode(r.password())); }
    catch(Exception e) { throw new ResponseStatusException(HttpStatus.CONFLICT,"Email already registered"); }
    return Map.of("message","Account created. Ask an administrator to grant elevated access if required.");
  }
  @PostMapping("/login") public Map<String,Object> login(@Valid @RequestBody Login r) {
    var rows=db.queryForList("SELECT email,password_hash,role FROM users WHERE email=?",r.email().toLowerCase());
    if(rows.isEmpty() || !encoder.matches(r.password(),(String)rows.get(0).get("password_hash"))) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Invalid credentials");
    var u=rows.get(0); Instant now=Instant.now();
    String token=Jwts.builder().subject((String)u.get("email")).claim("role",u.get("role")).issuedAt(Date.from(now)).expiration(Date.from(now.plusSeconds(8*3600))).signWith(key).compact();
    return Map.of("token",token,"email",u.get("email"),"role",u.get("role"),"expiresIn",28800);
  }
}
