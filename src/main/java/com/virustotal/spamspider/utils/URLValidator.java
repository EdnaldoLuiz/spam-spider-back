package com.virustotal.spamspider.utils;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

@Component
public class URLValidator {

    public static boolean isURLValid(String url) throws IOException {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }

        if (!isValidFormat(url)) {
            return false;
        }

        return isAccessible(url);
    }

    private static boolean isValidFormat(String url) {
        try {
            new URL(url).toURI();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isAccessible(String url) throws IOException {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setRequestMethod("HEAD");
            connection.setInstanceFollowRedirects(true);

            int responseCode = connection.getResponseCode();

            return responseCode >= HttpURLConnection.HTTP_OK && responseCode < HttpURLConnection.HTTP_MULT_CHOICE;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}
