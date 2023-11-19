package com.virustotal.spamspider.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class URLScanService {

    @Value("${api.key}")
    private String API_KEY;

    public String analyzeUrl(String targetUrl) throws IOException, NoSuchAlgorithmException {

        String urlId = base64UrlEncode(targetUrl);
        String apiUrl = "https://www.virustotal.com/api/v3/urls/" + urlId;

        URL url = new URL(apiUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        connection.setRequestMethod("GET");
        connection.setRequestProperty("Accept", "application/json");
        connection.setRequestProperty("x-apikey", API_KEY);

        int responseCode = connection.getResponseCode();

        if (responseCode == HttpURLConnection.HTTP_OK) {
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }

            in.close();

            return response.toString();
        } else {
            throw new IOException("HTTP request failed with response code: " + responseCode);
        }
    }

    public String base64UrlEncode(String targetUrl) {

        byte[] bytes = targetUrl.getBytes(StandardCharsets.UTF_8);
        String base64 = java.util.Base64.getUrlEncoder().encodeToString(bytes);
        return base64.replace("=", "");
    }

    public void printLastAnalysisStats(String response) {

        JSONObject jsonResponse = new JSONObject(response);

        JSONObject attributes = jsonResponse.getJSONObject("data").getJSONObject("attributes");
        JSONObject lastAnalysisStats = attributes.getJSONObject("last_analysis_stats");

        System.out.println("Last Analysis Stats:");
        System.out.println("Harmless: " + lastAnalysisStats.getInt("harmless"));
        System.out.println("Malicious: " + lastAnalysisStats.getInt("malicious"));
        System.out.println("Suspicious: " + lastAnalysisStats.getInt("suspicious"));
        System.out.println("Undetected: " + lastAnalysisStats.getInt("undetected"));
        System.out.println("Timeout: " + lastAnalysisStats.getInt("timeout"));
    }
}