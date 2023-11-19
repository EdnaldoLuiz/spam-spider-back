package com.virustotal.spamspider.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.virustotal.spamspider.service.URLScanService;
import com.virustotal.spamspider.utils.URLValidator;

@RestController
public class URLScanController {

    @Autowired
    private URLScanService analysis;

  @PostMapping("/scan")
    public ResponseEntity scan(@RequestBody String url) throws Exception {

        if(!URLValidator.isURLValid(url)) {
            return ResponseEntity.badRequest().build();
        } 

        var result = analysis.analyzeUrl(url);
        analysis.printLastAnalysisStats(result);

        return ResponseEntity.ok().build();
    }

}
