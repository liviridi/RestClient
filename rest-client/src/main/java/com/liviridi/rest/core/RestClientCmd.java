package com.liviridi.rest.core;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.UnsupportedCharsetException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.FileEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.springframework.http.MediaType;
import org.springframework.web.util.UriUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * REST通信クライアント
 *
 */
public class RestClientCmd {

    /** デフォルトオブジェクトマッパ */
    public static final ObjectMapper DEFAULT_OBJECT_MAPPER = new ObjectMapper();

    /** 接続URL */
    private String connectionURL;

    /** HTTPメソッド */
    private Method httpMethod;

    /** 基本認証情報 */
    private String basicAuthentication;

    /** プロキシアドレス */
    private String proxyAddress;

    /** プロキシ認証情報 */
    private String proxyAuthentication;

    /** HTTPヘッダ */
    private Map<String, String> headers;

    /**
     * コンストラクタ
     *
     */
    public RestClientCmd() {
        headers = new LinkedHashMap<String, String>();
    }

    /**
     * 接続URL取得
     *
     * @return 接続URL
     */
    public String getConnectionURL() {
        return connectionURL;
    }

    /**
     * 接続URL設定
     *
     * @param connectionURL 接続URL
     */
    public void setConnectionURL(String connectionURL) {
        this.connectionURL = connectionURL;
    }

    /**
     * HTTPメソッド取得
     *
     * @return HTTPメソッド
     */
    public Method getHttpMethod() {
        return httpMethod;
    }

    /**
     * HTTPメソッド設定
     *
     * @param httpMethod HTTPメソッド
     */
    public void setHttpMethod(Method httpMethod) {
        this.httpMethod = httpMethod;
    }

    /**
     * 基本認証情報取得
     *
     * @return 基本認証情報
     */
    public String getBasicAuthentication() {
        return basicAuthentication;
    }

    /**
     * 基本認証情報設定
     *
     * @param basicAuthentication 基本認証情報
     */
    public void setBasicAuthentication(String basicAuthentication) {
        this.basicAuthentication = basicAuthentication;
    }

    /**
     * プロキシアドレス取得
     *
     * @return プロキシアドレス
     */
    public String getProxyAddress() {
        return proxyAddress;
    }

    /**
     * プロキシアドレス設定
     *
     * @param proxyAddress プロキシアドレス
     */
    public void setProxyAddress(String proxyAddress) {
        this.proxyAddress = proxyAddress;
    }

    /**
     * プロキシ認証情報取得
     *
     * @return プロキシ認証情報
     */
    public String getProxyAuthentication() {
        return proxyAuthentication;
    }

    /**
     * プロキシ認証情報設定
     *
     * @param proxyAuthentication プロキシ認証情報
     */
    public void setProxyAuthentication(String proxyAuthentication) {
        this.proxyAuthentication = proxyAuthentication;
    }

    /**
     * HTTPヘッダ取得
     *
     * @return HTTPヘッダ
     */
    public Map<String, String> getHeaders() {
        return headers;
    }

    @Override
    public String toString() {
        try {
            return DEFAULT_OBJECT_MAPPER.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            return super.toString();
        }
    }

    /**
     * HTTP-GETリクエスト実行
     *
     * @return HTTPレスポンス
     * @throws Exception
     */
    public Response requestGet() throws Exception {
        return execute(getHttpGetRequest());
    }

    /**
     * HTTP-GETリクエスト実行
     *
     * @param parameters クエリパラメータ
     * @return HTTPレスポンス
     * @throws Exception
     */
    public Response requestGet(Map<String, String> parameters) throws Exception {
        return execute(getHttpGetRequest(parameters));
    }

    /**
     * HTTP-GETリクエスト実行
     *
     * @param entity Entityオブジェクト
     * @return HTTPレスポンス
     * @throws Exception
     */
    public Response requestGet(Object entity) throws Exception {
        return execute(getHttpGetRequest(entity));
    }

    /**
     * HTTP-POSTリクエスト実行
     *
     * @param parameters クエリパラメータ
     * @return HTTPレスポンス
     * @throws Exception
     */
    public Response requestPost(Map<String, String> parameters) throws Exception {
        return execute(getHttpPostRequest(parameters));
    }

    /**
     * HTTP-POSTリクエスト実行
     *
     * @param entity Entityオブジェクト
     * @return HTTPレスポンス
     * @throws Exception
     */
    public Response requestPost(Object entity) throws Exception {
        return execute(getHttpPostRequest(entity));
    }

    /**
     * HTTP-POSTリクエスト実行
     *
     * @param mimeType MIME形式値
     * @param entityFile Entityファイル
     * @return HTTPレスポンス
     * @throws Exception
     */
    public Response requestPost(String mimeType, File entityFile) throws Exception {
        return execute(getHttpPostRequest(mimeType, entityFile));
    }

    /**
     * HTTPリクエスト実行
     *
     * @param method HTTPメソッド
     * @param mimeType MIME形式
     * @param entity Entity文字列
     * @return HTTPレスポンス
     * @throws Exception
     */
    public Response request(Method method, String mimeType, String entity) throws Exception {
        return execute(getHttpRequest(method, mimeType, entity));
    }

    /**
     * HTTPリクエスト実行
     *
     * @param request HTTPリクエスト
     * @return HTTPレスポンス
     * @throws Exception
     */
    protected Response execute(HttpRequest request) throws Exception {
        StringBuilder commandLine = createCommandLine(request.getHttpMethod(), request.getURI());
        HttpClientBuilder builder = HttpClients.custom();

        if (PROTOCOL_HTTPS.equals(request.getURI().getScheme())) {
            // SSLに関する処理
            TrustManager[] tm = { new DefaultX509TrustManager() };
            SSLContext sslContext = SSLContext.getInstance("SSL", "SunJSSE");
            sslContext.init(null, tm, new java.security.SecureRandom());
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                    sslContext, new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" }, null, new AnyHostnameVerifier());
            builder.setSSLSocketFactory(sslsf);
        }
        if (getProxyAddress() != null) {
            HttpHost proxy = getProxy(getProxyAddress());

            builder.setProxy(proxy);
            addOption(commandLine, Option.PROXY, getProxyAddress());
            if (getProxyAuthentication() != null) {
                String[] fields = decodeAuthentication(getProxyAuthentication()).split(":");
                CredentialsProvider credentialsProvider = new BasicCredentialsProvider();

                credentialsProvider.setCredentials(
                        new AuthScope(proxy),
                        new UsernamePasswordCredentials(fields[0], fields[1])
                        );
                builder.setDefaultCredentialsProvider(credentialsProvider);
                addOption(commandLine, Option.PROXY_AUTH, getProxyAuthentication());
            }
        }
        if (getBasicAuthentication() != null) {
            request.setHeader(AUTHENTICATION, encodeAuthentication(getBasicAuthentication()));
            addOption(commandLine, Option.AUTH, getBasicAuthentication());
        }
        for (Map.Entry<String, String> header : headers.entrySet()) {
            String name  = header.getKey();
            String value = header.getValue();

            request.setHeader(name, value);
            addOption(commandLine, Option.HEADER, String.format("\"%s: %s\"", name, value));
        }
        if (request.getEntity() instanceof FossStringEntity) {
            FossStringEntity entity = (FossStringEntity) request.getEntity();

            addOption(commandLine, Option.MIME, entity.getMimeType());
            addOption(commandLine, Option.DATA, entity.getEntityData());
        }
        if (request.getEntity() instanceof FossFileEntity) {
            FossFileEntity entity = (FossFileEntity) request.getEntity();

            addOption(commandLine, Option.MIME, entity.getMimeType());
            addOption(commandLine, Option.FILE, entity.getEntityFile().getPath());
        }
        HttpClient client = builder.build();
        HttpResponse response = client.execute(request);

        return new Response(commandLine.toString(), response);
    }

    /**
     * コマンドライン生成
     *
     * @param method HTTPメソッド
     * @param uri 接続URI
     * @param コマンドライン
     */
    private StringBuilder createCommandLine(Method method, URI uri) {
        StringBuilder commandLine = new StringBuilder();

        commandLine.append(whichCommandPath(DEFAULT_REST_COMMAND));
        switch (method) {
            case GET:   addOption(commandLine, Option.GET);  break;
            case POST:  addOption(commandLine, Option.POST); break;
            default:
                throw new IllegalArgumentException(method.toString());
        }
        return addOption(commandLine, Option.URL, uri.toString());
    }

    /**
     * オプション追加
     *
     * @param commandLine コマンドライン
     * @param option オプション
     * @return コマンドライン
     */
    private StringBuilder addOption(StringBuilder commandLine, Option option) {
        commandLine.append(" ").append(option);
        return commandLine;
    }

    /**
     * オプション追加
     *
     * @param commandLine コマンドライン
     * @param option オプション
     * @param value オプション値
     * @return コマンドライン
     */
    private StringBuilder addOption(StringBuilder commandLine,Option option, String value) {
        commandLine.append(" ").append(option).append("=\'").append(value).append("\'");
        return commandLine;
    }

    /**
     * プロキシ情報取得
     *
     * @param proxyAddress プロキシアドレス
     * @return プロキシ情報
     * @throws URISyntaxException
     */
    private HttpHost getProxy(String proxyAddress) throws URISyntaxException {
        int schema = proxyAddress.indexOf("://");

        if (schema > 0) {
            URI uri = new URI(proxyAddress);

            return new HttpHost(uri.getHost(), uri.getPort(), uri.getScheme());
        } else {
            String[] fields = proxyAddress.split(":");

            if (fields.length != 2) {
                throw new IllegalArgumentException(proxyAddress);
            }
            return new HttpHost(fields[0], Integer.parseInt(fields[1]));
        }
    }

    /**
     * HTTP-GETリクエスト取得
     *
     * @return HTTP-GETリクエスト
     * @throws Exception
     */
    protected HttpRequest getHttpGetRequest() throws Exception {
        HttpRequest request = new HttpRequest(Method.GET);

        request.setURI(new URI(getConnectionURL()));
        return request;
    }

    /**
     * HTTP-GETリクエスト取得
     *
     * @param parameters クエリパラメータ
     * @return HTTP-GETリクエスト
     * @throws Exception
     */
    protected HttpRequest getHttpGetRequest(Map<String, String> parameters) throws Exception {
        HttpRequest request = new HttpRequest(Method.GET);

        request.setURI(new URI(getConnectionURL() + "?" + getQueryString(parameters)));
        return request;
    }

    /**
     * HTTP-GETリクエスト取得
     *
     * @param entity Entityオブジェクト
     * @return HTTP-GETリクエスト
     * @throws Exception
     */
    protected HttpRequest getHttpGetRequest(Object entity) throws Exception {
        return getHttpRequest(Method.GET,
                MediaType.APPLICATION_JSON_UTF8_VALUE,
                DEFAULT_OBJECT_MAPPER.writeValueAsString(entity)
                );
    }

    /**
     * HTTP-POSTリクエスト取得
     *
     * @param parameters クエリパラメータ
     * @return HTTP-POSTリクエスト
     * @throws Exception
     */
    protected HttpRequest getHttpPostRequest(Map<String, String> parameters) throws Exception {
        return getHttpRequest(Method.POST,
                MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                getQueryString(parameters)
                );
    }

    /**
     * HTTP-POSTリクエスト取得
     *
     * @param entity Entityオブジェクト
     * @return HTTP-POSTリクエスト
     * @throws Exception
     */
    protected HttpRequest getHttpPostRequest(Object entity) throws Exception {
        return getHttpRequest(Method.POST,
                MediaType.APPLICATION_JSON_UTF8_VALUE,
                DEFAULT_OBJECT_MAPPER.writeValueAsString(entity)
                );
    }

    /**
     * HTTP-POSTリクエスト取得
     *
     * @param mimeType MIME形式
     * @param entityFile エンティティファイル
     * @return HTTP-POSTリクエスト
     * @throws Exception
     */
    protected HttpRequest getHttpPostRequest(String mimeType, File entityFile) throws Exception {
        HttpRequest request = new HttpRequest(Method.POST);

        request.setURI(new URI(getConnectionURL()));
        request.setEntity(new FossFileEntity(mimeType, entityFile));
        return request;
    }

    /**
     * HTTPリクエスト取得
     *
     * @param method HTTPメソッド
     * @param mimeType MIME形式
     * @param entity Entity文字列
     * @return HTTPリクエスト
     * @throws Exception
     */
    protected HttpRequest getHttpRequest(Method method, String mimeType, String entity) throws Exception {
        HttpRequest request = new HttpRequest(method);

        if (Method.GET.equals(method) && MediaType.APPLICATION_FORM_URLENCODED_VALUE.equals(mimeType)) {
            request.setURI(new URI(getConnectionURL() + "?" + entity));
        } else {
            request.setURI(new URI(getConnectionURL()));
            request.setEntity(new FossStringEntity(mimeType, entity));
        }
        return request;
    }

    /**
     * クエリ文字列取得
     *
     * @param parameters クエリパラメータ
     * @return クエリ文字列
     */
    protected String getQueryString(Map<String, String> parameters) {
        StringBuilder query = new StringBuilder();

        try {
            for (Map.Entry<String,String> entry : parameters.entrySet()) {
                String name  = entry.getKey();
                String value = entry.getValue();

                if (query.length() > 0) {
                    query.append('&');
                }
                query.append(UriUtils.encode(name, UTF_8));
                query.append('=');
                query.append(UriUtils.encode(value, UTF_8));
            }
        } catch (UnsupportedEncodingException e) {
        }
        return query.toString();
    }

    /**
     * コマンドパス取得
     *
     * @param defaultCommandPath デフォルトコマンドパス
     * @return コマンドパス
     */
    protected String whichCommandPath(String defaultCommandPath) {
        String commandPath = System.getProperty(REST);

        if (commandPath != null) {
            return commandPath;
        }
        return defaultCommandPath;
    }

    /**
     * 認証情報デコード
     *
     * @param value 認証情報
     * @return 認証文字列
     */
    public static String decodeAuthentication(String value) {
        String credential = value;

        if (BASE64_CHARS.matcher(value).matches()) {
            try {
              credential = new String(Base64.getDecoder().decode(value), UTF_8);
            } catch (UnsupportedEncodingException ex) {
                throw new IllegalArgumentException(ex);
            }
        }
        if (CREDENTIAL.matcher(credential).matches()) {
            return credential;
        }
        throw new IllegalArgumentException(value);
    }

    /**
     * 認証情報エンコード
     *
     * @param value 認証情報
     * @return 認証文字列
     * @throws UnsupportedEncodingException
     */
    public static String encodeAuthentication(String value) throws UnsupportedEncodingException {
        if (BASE64_CHARS.matcher(value).matches()) {
            return value;
        }
        if (CREDENTIAL.matcher(value).matches()) {
            return new String(Base64.getEncoder().encode(value.getBytes(UTF_8)), UTF_8);
        }
        throw new IllegalArgumentException(value);
    }

    /**
     * コマンドライン実行
     *
     * @param arguments コマンドライン引数
     * @throws Exception
     */
    public static void main(String[] arguments) throws Exception {
        Map<Option,List<String>> options = getOptions(arguments);

        if (options.size() == 0 || !validate(options)) {
            printUsage(System.out);
            System.exit(1);
        }
        RestClientCmd client = createClient(options);
        String mimeType = getOptionValue(options, Option.MIME);
        String data = getOptionValue(options, Option.DATA);
        String file = getOptionValue(options, Option.FILE);

        if (options.containsKey(Option.POST)) {
            if (file != null) {
                printResponse(System.out, client.requestPost(mimeType, new File(file)));
            } else {
                printResponse(System.out, client.request(Method.POST, mimeType, data));
            }
        } else
        if (options.containsKey(Option.GET)) {
            if (mimeType != null && data != null) {
                printResponse(System.out, client.request(Method.GET, mimeType, data));
            } else {
                printResponse(System.out, client.requestGet());
            }
        }
        System.exit(0);
    }

    /**
     * REST通信クライアント生成
     *
     * @param options コマンドオプションマップ
     * @return REST通信クライアント
     */
    private static RestClientCmd createClient(Map<Option,List<String>> options) {
        RestClientCmd client = new RestClientCmd();

        if (options.containsKey(Option.AUTH)) {
            client.setBasicAuthentication(getOptionValue(options, Option.AUTH));
        }
        if (options.containsKey(Option.PROXY)) {
            client.setProxyAddress(getOptionValue(options, Option.PROXY));
        }
        if (options.containsKey(Option.PROXY_AUTH)) {
            client.setProxyAuthentication(getOptionValue(options, Option.PROXY_AUTH));
        }
        Map<String, String> headers = client.getHeaders();

        for (String header : getOptionValues(options, Option.HEADER)) {
            String name  = header;
            String value = null;
            int separator = header.indexOf(':');

            if (separator > 0) {
                name  = header.substring(0, separator).trim();
                value = header.substring(separator + 1).trim();
            }
            headers.put(name, value);
        }
        client.setConnectionURL(getOptionValue(options, Option.URL));
        return client;
    }

    /**
     * コマンドオプションマップ取得
     *
     * @param arguments コマンドライン引数
     * @return コマンドオプションマップ
     */
    private static Map<Option,List<String>> getOptions(String[] arguments) {
        Map<Option,List<String>> options = new LinkedHashMap<Option,List<String>>();

        for (String argument : arguments) {
            String name  = argument;
            String value = null;
            int separator = argument.indexOf('=');

            if (separator > 0) {
                name  = argument.substring(0, separator).trim();
                value = argument.substring(separator + 1).trim();
            }
            Option option = Option.nameOf(name);

            if (option != null) {
                List<String> values = options.get(option);

                if (values == null) {
                    values = new ArrayList<String>();
                    options.put(option, values);
                }
                if (value != null) {
                    values.add(value);
                }
            }
        }
        return options;
    }

    /**
     * コマンドオプションの妥当性検証
     *
     * @param options コマンドオプションマップ
     * @return 妥当性検証OKの場合は、true
     */
    private static boolean validate(Map<Option,List<String>> options) {
        if (!options.containsKey(Option.URL)) {
            return false;
        }
        if (options.containsKey(Option.GET)) {
            return true;
        } else
        if (options.containsKey(Option.POST) && options.containsKey(Option.MIME) &&
            (options.containsKey(Option.DATA) || options.containsKey(Option.FILE))) {
            return true;
        }
        return false;
    }

    /**
     * コマンドオプション値取得
     *
     * @param options コマンドオプションマップ
     * @param option コマンドオプション
     * @return コマンドオプション値
     */
    private static String getOptionValue(Map<Option,List<String>> options, Option option) {
        List<String> values = options.get(option);

        return (values != null && values.size() > 0)?  values.get(0): null;
    }

    /**
     * コマンドオプション値リスト取得
     *
     * @param options コマンドオプションマップ
     * @param option コマンドオプション
     * @return コマンドオプション値リスト
     */
    private static List<String> getOptionValues(Map<Option,List<String>> options, Option option) {
        List<String> values = options.get(option);

        return (values != null)?  values: Arrays.asList();
    }

    /**
     * コマンド使用法表示
     *
     * @param stdout 標準出力
     */
    private static void printUsage(PrintStream stdout) {
        stdout.println("使用方法:");
        stdout.println(DEFAULT_REST_COMMAND);
        for (Option option : Option.values()) {
            stdout.println(option.description());
        }
    }

    /**
     * HTTPレスポンス表示
     *
     * @param stdout 標準出力
     * @param response HTTPレスポンス
     */
    private static void printResponse(PrintStream stdout, Response response) {
        stdout.printf("%s\n", response.getCommandLine());
        stdout.printf("%s %d %s\n", response.getHttpVersion(), response.getStatusCode(), response.getMessage());
        for (Map.Entry<String,String> entry : response.getHeaders().entrySet()) {
            String name  = entry.getKey();
            String value = entry.getValue();

            stdout.printf("%s: %s\n", name, value);
        }
        stdout.println();
        stdout.println(response.getBodyAsString());
    }

    /**
     * HTTPメソッド
     *
     */
    public static enum Method {
        DELETE,
        GET,
        HEAD,
        POST,
        PUT
    }

    /**
     * コマンドオプション
     *
     */
    public static enum Option {
        GET("--get", "--get: HTTP-GETメソッド"),
        POST("--post", "--post: HTTP-POSTメソッド"),
        URL("--url", "--url=\"<接続URL>\""),
        AUTH("--auth", "--auth=<BASIC認証文字列> | <ユーザ名>:<パスワード>"),
        PROXY("--proxy", "--proxy=[プロトコル名://]<プロキシホスト>:<プロキシポート番号>"),
        PROXY_AUTH("--proxy_auth", "--proxy_auth=<BASIC認証文字列> | <ユーザ名>:<パスワード>"),
        HEADER("-H", "-H=\"<ヘッダ名>: <ヘッダ値>\""),
        MIME("--mime", "--mime=<MIME形式>"),
        DATA("--data", "--data=\"エンティティデータ\""),
        FILE("--file", "--file=\"<エンティティファイルパス>\"")
        ;

        /** オプション名 */
        private String name;

        /** オプション説明 */
        private String description;

        Option(String name, String description) {
            this.name = name;
            this.description = description;
        }

        /**
         * オプション説明返却
         *
         * @return オプション説明
         */
        public String description() {
            return description;
        }

        @Override
        public String toString() {
            return name;
        }

        /**
         * コマンドオプション返却
         *
         * @param name オプション名
         * @return コマンドオプション
         */
        public static Option nameOf(String name) {
            for (Option option : values()) {
                if (option.name.equals(name)) {
                    return option;
                }
            }
            return null;
        }
    }

    /**
     * FOSS文字列エンティティ
     *
     */
    protected class FossStringEntity extends StringEntity {

        /** MIME形式 */
        private String mimeType;

        /** Entityデータ */
        private String entity;

        /**
         * コンストラクタ
         *
         * @param mimeType MIME形式
         * @param entity Entityデータ
         * @throws UnsupportedCharsetException
         */
        public FossStringEntity(String mimeType, String entity) throws UnsupportedCharsetException {
            super(entity, ContentType.create(mimeType, UTF_8));
            this.entity = entity;
            this.mimeType = mimeType;
        }

        /**
         * MIME形式取得
         *
         * @return MIME形式
         */
        public String getMimeType() {
            return mimeType;
        }

        /**
         * Entityデータ取得
         *
         * @return Entityデータ
         */
        public String getEntityData() {
            return entity;
        }
    }

    /**
     * FOSSファイルエンティティ
     *
     */
    protected class FossFileEntity extends FileEntity {

        /** MIME形式 */
        private String mimeType;

        /** Entityファイル */
        private File entityFile;

        /**
         * コンストラクタ
         *
         * @param mimeType MIME形式
         * @param entityFile Entityファイル
         * @throws UnsupportedCharsetException
         */
        public FossFileEntity(String mimeType, File entityFile) throws UnsupportedCharsetException {
            super(entityFile, ContentType.create(mimeType));
            this.entityFile = entityFile;
            this.mimeType = mimeType;
        }

        /**
         * MIME形式取得
         *
         * @return MIME形式
         */
        public String getMimeType() {
            return mimeType;
        }

        /**
         * Entityファイル取得
         *
         * @return Entityファイル
         */
        public File getEntityFile() {
            return entityFile;
        }
    }

    /**
     * HTTPリクエスト
     *
     */
    protected class HttpRequest extends HttpEntityEnclosingRequestBase {

        /** HTTPメソッド */
        private Method method;

        /**
         * コンストラクタ
         *
         * @param method HTTPメソッド
         */
        public HttpRequest(Method method) {
            this.method = method;
        }

        /**
         * HTTPメソッド取得
         *
         * @return HTTPメソッド
         */
        public Method getHttpMethod() {
            return method;
        }

        @Override
        public String getMethod() {
            return method.name();
        }
    }

    /**
     * HTTPレスポンス
     *
     */
    public class Response {

        /** コマンドライン */
        private String commandLine;

        /** HTTPバージョン */
        private String httpVersion;

        /** ステータスコード */
        private int statusCode;

        /** メッセージ */
        private String message;

        /** HTTPヘッダ */
        private Map<String, String> headers;

        /** ボディ部生データ */
        private byte[] rawBody;

        /**
         * コンストラクタ
         *
         * @param commandLine コマンドライン
         * @param response HTTP応答
         * @throws IOException 通信例外
         */
        public Response(String commandLine, HttpResponse response) throws IOException {
            setCommandLine(commandLine);
            readStatusLine(response.getStatusLine());
            readHeaders(response.getAllHeaders());
            readEntity(response.getEntity());
        }

        /**
         * ステータス行読み取り
         *
         * @param statusLine ステータス行
         */
        private void readStatusLine(StatusLine statusLine) {
            setHttpVersion(statusLine.getProtocolVersion().toString());
            setStatusCode(statusLine.getStatusCode());
            setMessage(statusLine.getReasonPhrase());
        }

        /**
         * HTTPヘッダ読み取り
         *
         * @param httpHeaders HTTPヘッダ
         */
        private void readHeaders(Header[] httpHeaders) {
            headers = new LinkedHashMap<String, String>();
            for (Header httpHeader : httpHeaders) {
                headers.put(httpHeader.getName(), httpHeader.getValue());
            }
        }

        /**
         * HTTPエンティティ読み取り
         *
         * @param httpEntity HTTPエンティティ
         * @throws IOException 通信例外
         */
        private void readEntity(HttpEntity httpEntity) throws IOException {
            if (httpEntity == null) {
                rawBody = new byte[0];
                return;
            }
            InputStream recvIn = httpEntity.getContent();
            int contentLength = getContentLength(DEFAULT_BUF_SIZE);

            if (contentLength > MAXIMUM_BUF_SIZE) {
                recvIn.skip(Long.MAX_VALUE);
                throw new IOException("Exceed maximum content length < " + contentLength);
            }
            byte[] buffer = new byte[contentLength];
            int position = 0;

            for(;;) {
                int chunk = recvIn.read(buffer, position, contentLength - position);

                if (chunk <= 0) {
                    break;
                }
                position += chunk;
                if (position == contentLength) {
                    contentLength *= 2;
                    if (contentLength > MAXIMUM_BUF_SIZE) {
                        recvIn.skip(Long.MAX_VALUE);
                        throw new IOException("Exceed maximum content length < " + contentLength);
                    }
                    byte[] newBuffer = new byte[contentLength];

                    System.arraycopy(buffer, 0, newBuffer, 0, position);
                    buffer = newBuffer;
                }
            }
            rawBody = new byte[position];
            if (position > 0) {
                System.arraycopy(buffer, 0, rawBody, 0, position);
            }
        }

        /**
         * コマンドライン取得
         *
         * @return コマンドライン
         */
        public String getCommandLine() {
            return commandLine;
        }

        /**
         * コマンドライン設定
         *
         * @param commandLine コマンドライン
         */
        private void setCommandLine(String commandLine) {
            this.commandLine = commandLine;
        }

        /**
         * HTTPバージョン取得
         *
         * @return HTTPバージョン
         */
        public String getHttpVersion() {
            return httpVersion;
        }

        /**
         * HTTPバーション設定
         *
         * @param httpVersion HTTPバージョン
         */
        private void setHttpVersion(String httpVersion) {
            this.httpVersion = httpVersion;
        }

        /**
         * ステータスコード取得
         *
         * @return ステータスコード
         */
        public int getStatusCode() {
            return statusCode;
        }

        /**
         * ステータスコード設定
         *
         * @param statusCode ステータスコード
         */
        private void setStatusCode(int statusCode) {
            this.statusCode = statusCode;
        }

        /**
         * 応答メッセージ取得
         *
         * @return 応答メッセージ
         */
        public String getMessage() {
            return message;
        }

        /**
         * 応答メッセージ設定
         *
         * @param message 応答メッセージ
         */
        private void setMessage(String message) {
            this.message = message;
        }

        /**
         * HTTPヘッダ取得
         *
         * @return HTTPヘッダ
         */
        public Map<String, String> getHeaders() {
            return headers;
        }

        /**
         * ボティ部生データ取得
         *
         * @return ボティ部生データ
         */
        public byte[] getRawBody() {
            return rawBody;
        }

        /**
         * ボディ部エンティティ取得
         *
         * @param entityClass エンティティクラス
         * @return エンティティオブジェクト
         * @throws IOException
         */
        public <T> T getBodyAsEntity(Class<T> entityClass) throws IOException {
            return DEFAULT_OBJECT_MAPPER.readValue(getBodyAsString(UTF_8), entityClass);
        }

        /**
         * ボディ部文字列取得
         *
         * @return ボディ部文字列
         */
        public String getBodyAsString() {
            try {
                return getBodyAsString(UTF_8);
            } catch (IOException ex) {
                return "";
            }
        }

        /**
         * ボディ部文字列取得
         *
         * @param defaultCharset デフォルト文字セット名
         * @return ボディ部文字列
         * @throws IOException
         */
        public String getBodyAsString(String defaultCharset) throws IOException {
            return new String(getRawBody(), getCharset(defaultCharset));
        }

        /**
         * Content-Lengthヘッダ値取得
         *
         * @param defaultLength デフォルト長
         * @return Content-Lengthヘッダ値
         */
        public int getContentLength(int defaultLength) {
            String value = headers.get(CONTENT_LENGTH);

            if (value != null) {
                try {
                    return Integer.parseInt(value);
                } catch (NumberFormatException ex) {
                }
            }
            return defaultLength;
        }

        /**
         * Content-Typeヘッダ値取得
         *
         * @return Content-Typeヘッダ値
         */
        public String getContentType() {
            String value = headers.get(CONTENT_TYPE);

            if (value != null) {
                int end = value.indexOf(';');

                if (end > 0) {
                    return value.substring(0, end);
                } else {
                    return value;
                }
            }
            return null;
        }

        /**
         * 文字セット名取得
         *
         * @param defaultCharset デフォルト文字セット名
         * @return 文字セット名
         */
        public String getCharset(String defaultCharset) {
            String value = headers.get(CONTENT_TYPE);

            if (value != null) {
                int pos = value.indexOf("charset=");

                if (pos > 0) {
                    return value.substring(pos + 8);
                }
            }
            return defaultCharset;
        }
    }

    /**
     * デフォルトX509トラスト管理
     *
     */
    private static class DefaultX509TrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    /**
     * 任意ホスト名検証
     *
     */
    private static class AnyHostnameVerifier implements HostnameVerifier {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

    /** 文字エンコーディング：UTF-8 */
    private static final String UTF_8 = "UTF-8";

    /** Authenticationヘッダ */
    private static final String AUTHENTICATION = "Authentication";

    /** Content-Typeヘッダ */
    private static final String CONTENT_TYPE = "Content-Type";

    /** Content-Lengthヘッダ */
    private static final String CONTENT_LENGTH = "Content-Length";

    /** プロトコル：HTTPS */
    private static final String PROTOCOL_HTTPS = "https";

    /** RESTコマンド名 */
    private static final String REST = "rest";

    /** デフォルトRESTコマンド */
    private static final String DEFAULT_REST_COMMAND = "/etc/foss/script/rest.sh";

    /** 認証文字列パターン */
    private static final Pattern CREDENTIAL = Pattern.compile("^\\w+\\:\\w+$");

    /** BASE64文字列パターン */
    private static final Pattern BASE64_CHARS = Pattern.compile("[A-Za-z0-9\\+\\/\\=]+");

    /** デフォルトバッファサイズ */
    private static final int DEFAULT_BUF_SIZE = 32768;

    /** 最大バッファサイズ */
    private static final int MAXIMUM_BUF_SIZE = 10485760;
}
