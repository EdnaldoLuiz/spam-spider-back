package com.virustotal.spamspider.controller;

import com.virustotal.spamspider.model.URLScanModel;
import com.virustotal.spamspider.service.URLScanService;
import com.virustotal.spamspider.utils.URLValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class URLScanController {

    @Autowired
    private URLScanService urlScanService;

    @PostMapping("/scan")
    public ResponseEntity<URLScanModel> scanUrl(@RequestBody Map<String, String> requestBody) {
        try {
            String url = requestBody.get("url");

            if (!URLValidator.isURLValid(url)) {
                return ResponseEntity.badRequest().body(null);
            }

            String response = urlScanService.analyzeUrl(url);
            URLScanModel lastAnalysisStats = urlScanService.getLastAnalysisStats(response);

            return ResponseEntity.ok(lastAnalysisStats);
        } catch (IOException e) {
            return ResponseEntity.status(500).body(null);
        } catch (NoSuchAlgorithmException e) {
            return ResponseEntity.status(500).body(null);
        }
    }

}