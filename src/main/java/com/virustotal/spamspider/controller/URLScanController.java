package com.virustotal.spamspider.controller;

import com.virustotal.spamspider.service.URLScanService;
import com.virustotal.spamspider.utils.URLValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

@RestController
@RequestMapping("/api")
public class URLScanController {

    @Autowired
    private URLScanService urlScanService;

    @Autowired
    private URLValidator urlValidator;

    @PostMapping("/scan")
    public ResponseEntity<String> scanUrl(@RequestParam String url) {
        try {
            if (!urlValidator.isURLValid(url)) {
                return ResponseEntity.badRequest().body("Invalid URL");
            }

            String response = urlScanService.analyzeUrl(url);

            urlScanService.printLastAnalysisStats(response);

            return ResponseEntity.ok(response);
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Error processing request: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            return ResponseEntity.status(500).body("Error processing request: " + e.getMessage());
        }
    }
}
