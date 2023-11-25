package com.virustotal.spamspider.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class URLScanModel {
    
    private int harmless;
    private int malicious;
    private int suspicious;
    private int undetected;
    private int timeout;
}
