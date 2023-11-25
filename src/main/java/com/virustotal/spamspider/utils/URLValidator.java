package com.virustotal.spamspider.utils;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public class URLValidator {

    public static boolean isURLValid(String url) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestMethod("HEAD");

        int responseCode = connection.getResponseCode();
        return responseCode == HttpURLConnection.HTTP_OK;
    }
}