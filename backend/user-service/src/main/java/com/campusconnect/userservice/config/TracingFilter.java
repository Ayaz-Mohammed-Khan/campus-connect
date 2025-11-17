package com.campusconnect.userservice.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Component
public class TracingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(TracingFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String traceId = UUID.randomUUID().toString();

        MDC.put("traceId", traceId);
        MDC.put("requestMethod", request.getMethod());
        MDC.put("requestPath", request.getRequestURI());
        MDC.put("clientIp", request.getRemoteAddr());
        MDC.put("userAgent", request.getHeader("User-Agent"));

        response.setHeader("X-Trace-Id", traceId);

        try {
            log.info("Incoming request");

            filterChain.doFilter(request, response);

        } finally {
            MDC.put("responseStatus", String.valueOf(response.getStatus()));
            log.info("Completed request");
            MDC.clear();
        }
    }
}
