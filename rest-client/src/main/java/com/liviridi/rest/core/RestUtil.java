package com.liviridi.rest.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

public class RestUtil {

    public static final int MILLI_IN_SECOND = 1000;

    /**
     * HPSP送信
     *
     * @param method
     *            方式
     * @param url
     *            URL
     * @param header
     *            リクエストヘッダ
     * @param body
     *            リクエストボディ
     * @return conn HttpURLConnection
     * @throws IOException
     *             書き失敗
     */
    public static HttpURLConnection sendRest(String method, String url, Map<String, String> header, String body, int timeout)
            throws IOException {
        System.setProperty("sun.net.http.allowRestrictedHeaders", "true");
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod(method);
        if (timeout > 0) {
            conn.setConnectTimeout(timeout * MILLI_IN_SECOND);
            conn.setReadTimeout(timeout * MILLI_IN_SECOND);
        }
        if (header != null) {
            Iterator<Entry<String, String>> iter = header.entrySet().iterator();
            while (iter.hasNext()) {
                Map.Entry<String, String> entry = (Map.Entry<String, String>) iter.next();
                conn.setRequestProperty(entry.getKey(), entry.getValue());
            }
        }
        if (body != null && !"".equals(body)) {
            conn.setDoOutput(true);
            writeAllText(conn.getOutputStream(), body);
        }
        return conn;
    }

    /**
     * Streamへ文字列を書き（書きした後にStreamをクローズ）
     *
     * @param s
     *            Stream
     * @param text
     *            文字列
     * @throws IOException
     *             書き失敗
     */
    private static void writeAllText(OutputStream s, String text) throws IOException {
        try {
            s.write(text.getBytes());
        } finally {
            try {
                if (s != null)
                    s.close();
            } catch (IOException e) {
            }
        }
    }

    /**
     * Streamから文字列を読み（読みした後にStreamをクローズ）
     *
     * @param s
     *            Stream
     * @return 取得文字列
     * @throws IOException
     *             読み失敗
     */
    public static String readAllText(InputStream s) throws IOException {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(s));
            String result = "";
            String line;
            while ((line = reader.readLine()) != null) {
                result += line;
            }
            return result;
        } finally {
            try {
                if (reader != null)
                    reader.close();
            } catch (IOException e) {
            }
        }
    }

}
