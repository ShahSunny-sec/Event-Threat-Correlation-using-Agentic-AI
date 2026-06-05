package com.soc.ui.controller;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpSession;
import com.soc.ui.service.PipelineApiService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class DashboardController {
    private final PipelineApiService apiService;

    @Value("${pipeline.sample.auth-path:../data/sample/auth_linux_sample.csv}")
    private String sampleAuthPath;

    @Value("${pipeline.sample.net-path:../data/sample/network_ids_sample.csv}")
    private String sampleNetPath;

    public DashboardController(PipelineApiService apiService) {
        this.apiService = apiService;
    }

    @GetMapping("/")
    public String index(Model model, HttpSession session) {
        hydrateModelFromSession(model, session);
        return "index";
    }

    @PostMapping("/analyze")
    public String analyze(
            @RequestParam(defaultValue = "true") boolean useSample,
            @RequestParam(defaultValue = "true") boolean includeReports,
            @RequestParam(required = false) MultipartFile authFile,
            @RequestParam(required = false) MultipartFile netFile,
            Model model,
            HttpSession session
    ) {
        try {
            String authCsv;
            String netCsv;

            if (!useSample && authFile != null && !authFile.isEmpty() && netFile != null && !netFile.isEmpty()) {
                authCsv = new String(authFile.getBytes());
                netCsv = new String(netFile.getBytes());
                model.addAttribute("inputMode", "Uploaded CSV files");
                session.setAttribute("inputMode", "Uploaded CSV files");
            } else {
                authCsv = Files.readString(Path.of(sampleAuthPath));
                netCsv = Files.readString(Path.of(sampleNetPath));
                model.addAttribute("inputMode", "Bundled sample data");
                session.setAttribute("inputMode", "Bundled sample data");
            }

            Map<String, Object> result = apiService.analyze(authCsv, netCsv, includeReports);
            model.addAttribute("result", result);
            session.setAttribute("result", result);
            session.setAttribute("activeTab", "detections");
            session.setAttribute("chatHistory", new ArrayList<Map<String, String>>());
        } catch (IOException ex) {
            model.addAttribute("error", "Could not load sample CSV files: " + ex.getMessage());
        } catch (Exception ex) {
            model.addAttribute("error", "API call failed: " + ex.getMessage());
        }
        hydrateModelFromSession(model, session);
        model.addAttribute("activeTab", "detections");
        return "index";
    }

    @PostMapping("/report")
    public String report(
            @RequestParam int incidentIndex,
            @RequestParam(defaultValue = "fallback") String mode,
            Model model,
            HttpSession session
    ) {
        try {
            Map<String, Object> result = getResult(session);
            Map<String, Object> inc = getIncidentByIndex(result, incidentIndex);
            @SuppressWarnings("unchecked")
            Map<String, Object> context = (Map<String, Object>) inc.get("context");
            Map<String, Object> report = apiService.generateReport(context, mode);
            model.addAttribute("reportText", report.get("report"));
            model.addAttribute("reportMode", report.get("mode"));
            session.setAttribute("reportText", report.get("report"));
            session.setAttribute("reportMode", report.get("mode"));
            session.setAttribute("reportIncidentIndex", incidentIndex);
        } catch (Exception ex) {
            model.addAttribute("error", "Report generation failed: " + ex.getMessage());
        }
        hydrateModelFromSession(model, session);
        model.addAttribute("activeTab", "report");
        session.setAttribute("activeTab", "report");
        return "index";
    }

    @PostMapping("/chat")
    public String chat(
            @RequestParam int incidentIndex,
            @RequestParam String prompt,
            Model model,
            HttpSession session
    ) {
        try {
            Map<String, Object> result = getResult(session);
            Map<String, Object> inc = getIncidentByIndex(result, incidentIndex);
            @SuppressWarnings("unchecked")
            Map<String, Object> context = (Map<String, Object>) inc.get("context");

            @SuppressWarnings("unchecked")
            List<Map<String, String>> history = (List<Map<String, String>>) session.getAttribute("chatHistory");
            if (history == null) {
                history = new ArrayList<>();
            }
            Map<String, String> userMsg = new HashMap<>();
            userMsg.put("role", "user");
            userMsg.put("content", prompt);
            history.add(userMsg);

            Map<String, Object> resp = apiService.chat(context, history, prompt);
            Map<String, String> asstMsg = new HashMap<>();
            asstMsg.put("role", "assistant");
            asstMsg.put("content", String.valueOf(resp.get("response")));
            history.add(asstMsg);

            session.setAttribute("chatHistory", history);
            session.setAttribute("chatIncidentIndex", incidentIndex);
            model.addAttribute("chatHistory", history);
        } catch (Exception ex) {
            model.addAttribute("error", "Chat failed: " + ex.getMessage());
        }
        hydrateModelFromSession(model, session);
        model.addAttribute("activeTab", "chat");
        session.setAttribute("activeTab", "chat");
        return "index";
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getResult(HttpSession session) {
        return (Map<String, Object>) session.getAttribute("result");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getIncidentByIndex(Map<String, Object> result, int incidentIndex) {
        List<Map<String, Object>> incidents = (List<Map<String, Object>>) result.get("incidents");
        if (incidents == null || incidents.isEmpty()) {
            throw new IllegalStateException("No incidents available.");
        }
        int idx = Math.max(0, Math.min(incidentIndex, incidents.size() - 1));
        return incidents.get(idx);
    }

    private void hydrateModelFromSession(Model model, HttpSession session) {
        Object result = session.getAttribute("result");
        if (result != null) {
            model.addAttribute("result", result);
        }
        Object inputMode = session.getAttribute("inputMode");
        if (inputMode != null) {
            model.addAttribute("inputMode", inputMode);
        }
        Object reportText = session.getAttribute("reportText");
        if (reportText != null) {
            model.addAttribute("reportText", reportText);
        }
        Object reportMode = session.getAttribute("reportMode");
        if (reportMode != null) {
            model.addAttribute("reportMode", reportMode);
        }
        Object reportIncidentIndex = session.getAttribute("reportIncidentIndex");
        if (reportIncidentIndex != null) {
            model.addAttribute("reportIncidentIndex", reportIncidentIndex);
        }
        Object chatHistory = session.getAttribute("chatHistory");
        if (chatHistory != null) {
            model.addAttribute("chatHistory", chatHistory);
        }
        Object chatIncidentIndex = session.getAttribute("chatIncidentIndex");
        if (chatIncidentIndex != null) {
            model.addAttribute("chatIncidentIndex", chatIncidentIndex);
        }
        Object activeTab = session.getAttribute("activeTab");
        if (activeTab != null) {
            model.addAttribute("activeTab", activeTab);
        }
    }
}
