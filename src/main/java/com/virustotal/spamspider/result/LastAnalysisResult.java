package com.virustotal.spamspider.result;

import org.json.JSONObject;

    public class LastAnalysisResult {
        private String title;
        private JSONObject lastAnalysisStats;

        public String getTitle() {
            return title;
        }

        public void setTitle(String title) {
            this.title = title;
        }

        public JSONObject getLastAnalysisStats() {
            return lastAnalysisStats;
        }

        public void setLastAnalysisStats(JSONObject lastAnalysisStats) {
            this.lastAnalysisStats = lastAnalysisStats;
        }
    }


