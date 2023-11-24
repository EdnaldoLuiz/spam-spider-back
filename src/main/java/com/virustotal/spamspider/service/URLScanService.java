package com.virustotal.spamspider.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import com.virustotal.spamspider.result.LastAnalysisResult;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class URLScanService {

    @Value("${api.key}")
    private String API_KEY;

    public String analyzeUrl(String targetUrl) throws IOException, NoSuchAlgorithmException {
        if (!isURLValid(targetUrl)) {
            throw new IllegalArgumentException("Invalid URL: " + targetUrl);
        }

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

    public String getLastAnalysisStats(String response) {
        JSONObject jsonResponse = new JSONObject(response);

        JSONObject attributes = jsonResponse.getJSONObject("data").getJSONObject("attributes");
        JSONObject lastAnalysisStats = attributes.getJSONObject("last_analysis_stats");

        LastAnalysisResult result = new LastAnalysisResult();
        result.setTitle(attributes.getString("title"));
        result.setLastAnalysisStats(lastAnalysisStats);

        // Use uma biblioteca de serialização JSON, como Jackson, para converter o objeto em JSON
        // Neste exemplo, estou usando a classe JSONObject do JSON-java para simplificar

        JSONObject jsonResult = new JSONObject(result);

        return jsonResult.toString();
    }

    private boolean isURLValid(String targetUrl) {
        try {
            new URL(targetUrl).toURI();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
