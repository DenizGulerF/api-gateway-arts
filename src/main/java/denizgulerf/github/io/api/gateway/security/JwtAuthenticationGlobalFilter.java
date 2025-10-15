package denizgulerf.github.io.api.gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
public class JwtAuthenticationGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationGlobalFilter.class);

    private final SecretKey secretKey;
    private final boolean enabled;

    public JwtAuthenticationGlobalFilter(
        @Value("${security.jwt.secret}") String secret,
        @Value("${security.jwt.base64:false}") boolean isBase64,
        @Value("${security.jwt.enabled:true}") boolean enabled
    ) {
        byte[] keyBytes = isBase64 ? Decoders.BASE64.decode(secret) : secret.getBytes(StandardCharsets.UTF_8);
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
        this.enabled = enabled;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        HttpMethod method = exchange.getRequest().getMethod();
        if (!enabled) {
            if (log.isDebugEnabled()) {
                log.debug("JWT filter disabled: allowing {} {}", method, path);
            }
            return chain.filter(exchange);
        }

        // Skip auth endpoints and preflight
        if ((path.startsWith("/api/auth/")) || HttpMethod.OPTIONS.equals(method)) {
            if (log.isDebugEnabled()) {
                log.debug("Skipping JWT validation for {} {}", method, path);
            }
            return chain.filter(exchange);
        }

        List<String> authHeaders = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION);
        if (authHeaders == null || authHeaders.isEmpty() || !authHeaders.get(0).startsWith("Bearer ")) {
            log.warn("Missing Bearer Authorization for {} {}", method, path);
            exchange.getResponse().getHeaders().add(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeaders.get(0).substring(7);
        try {
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

            if (log.isInfoEnabled()) {
                String subject = claims.getSubject();
                Object roles = claims.get("roles");
                log.info("JWT validated: subject={} roles={} path={}", subject, roles, path);
            }

            // Optionally propagate user info to downstream services
            ServerWebExchange mutated = exchange.mutate()
                .request(r -> r.headers(h -> {
                    h.add("X-User-Name", claims.getSubject());
                }))
                .build();

            return chain.filter(mutated);
        } catch (Exception e) {
            log.warn("Invalid JWT for path={} error={}", path, e.getMessage());
            exchange.getResponse().getHeaders().add(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    @Override
    public int getOrder() {
        // Run early, before routing
        return -100;
    }
}


