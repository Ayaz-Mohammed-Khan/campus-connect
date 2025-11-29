package com.campusconnect.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

@Configuration
@EnableAsync
public class AsyncConfig {

    @Bean(name = "taskExecutor")
    public Executor taskExecutor() {
        // 🚀 JAVA 25: Virtual Threads with ScopedValue Propagation
        Executor virtualExecutor = Executors.newVirtualThreadPerTaskExecutor();

        return task -> {
            // 1. Capture Trace ID from the CALLER thread
            String traceId = TracingFilter.TRACE_ID.isBound() ? TracingFilter.TRACE_ID.get() : null;

            virtualExecutor.execute(() -> {
                // 2. Re-bind Trace ID in the NEW Virtual Thread
                if (traceId != null) {
                    ScopedValue.where(TracingFilter.TRACE_ID, traceId).run(task);
                } else {
                    task.run();
                }
            });
        };
    }
}