package com.campusconnect.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Slf4j
@Component
public class TracingFilter extends OncePerRequestFilter {

    // 🚀 JAVA 25: ScopedValue (Immutable & Safe)
    public static final ScopedValue<String> TRACE_ID = ScopedValue.newInstance();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String traceId = UUID.randomUUID().toString();

        // 1. Setup MDC for Logback JSON
        MDC.put("traceId", traceId);
        MDC.put("requestMethod", request.getMethod());
        MDC.put("requestPath", request.getRequestURI());
        MDC.put("clientIp", request.getRemoteAddr());
        MDC.put("userAgent", request.getHeader("User-Agent"));

        response.setHeader("X-Trace-Id", traceId);

        long start = System.currentTimeMillis();
        try {
            // Run filter chain inside the scope
            ScopedValue.where(TRACE_ID, traceId).run(() -> {
                try {
                    filterChain.doFilter(request, response);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        } finally {
            long duration = System.currentTimeMillis() - start;
            MDC.put("responseStatus", String.valueOf(response.getStatus()));

            // 🚀 THE MISSING PIECE: Check if an error detail was whispered
            String errorDetail = MDC.get("errorDetail");

            if (errorDetail != null) {
                // Log WITH failure reason
                log.info("HTTP {} {} {} - {}ms | Error: {}",
                        request.getMethod(),
                        request.getRequestURI(),
                        response.getStatus(),
                        duration,
                        errorDetail
                );
            } else {
                // Log Standard
                log.info("HTTP {} {} {} - {}ms",
                        request.getMethod(),
                        request.getRequestURI(),
                        response.getStatus(),
                        duration
                );
            }

            MDC.clear();
        }
    }
}