package com.soc.ui.service;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class PipelineApiService {
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${pipeline.api.base-url:http://localhost:8000}")
    private String apiBaseUrl;

    @SuppressWarnings("unchecked")
    public Map<String, Object> analyze(String authCsv, String networkCsv, boolean includeReports) {
        Map<String, Object> body = new HashMap<>();
        body.put("auth_csv", authCsv);
        body.put("network_csv", networkCsv);
        body.put("include_reports", includeReports);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(body, headers);

        return restTemplate.postForObject(apiBaseUrl + "/analyze", request, Map.class);
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> generateReport(Map<String, Object> incidentContext, String mode) {
        Map<String, Object> body = new HashMap<>();
        body.put("incident_context", incidentContext);
        body.put("mode", mode);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(body, headers);
        return restTemplate.postForObject(apiBaseUrl + "/report", request, Map.class);
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> chat(Map<String, Object> incidentContext, Object history, String prompt) {
        Map<String, Object> body = new HashMap<>();
        body.put("incident_context", incidentContext);
        body.put("history", history);
        body.put("prompt", prompt);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(body, headers);
        return restTemplate.postForObject(apiBaseUrl + "/chat", request, Map.class);
    }
}
