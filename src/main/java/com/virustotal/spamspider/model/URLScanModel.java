package com.virustotal.spamspider.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class URLScanModel {
    
    private Long id;
    private String harmless;
    private String malicious;
    private String suspicious;
    private String undetected;
    private String timeout;
}
