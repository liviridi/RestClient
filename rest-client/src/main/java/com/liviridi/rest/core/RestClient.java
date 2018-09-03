package com.liviridi.rest.core;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.UnsupportedCharsetException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
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
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.FileEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;

import com.liviridi.rest.exception.UnexecutableException;

public class RestClient {

    /** http response message: OK */
    public static final String RM_OK = "OK";

    /** header Authentication */
    public static final String AUTHENTICATION = "Authentication";

    /** header Content-Type */
    public static final String CONTENT_TYPE = "Content-Type";

    /** header Content-Length */
    public static final String CONTENT_LENGTH = "Content-Length";

    /** protocol： HTTPS */
    public static final String PROTOCOL_HTTPS = "https";

    /** media type :application/json;charset=UTF-8 */
    public static final String APPLICATION_JSON = "application/json";

    /** media type :application/x-www-form-urlencoded */
    public static final String APPLICATION_FORM_URLENCODED_VALUE = "application/x-www-form-urlencoded";

    /** charset： UTF-8 */
    private static final String UTF_8 = "UTF-8";

    /** basic authentication info pattern */
    private static final Pattern CREDENTIAL = Pattern.compile("^\\w+\\:\\w+$");

    /** BASE64 authentication info pattern */
    private static final Pattern BASE64_CHARS = Pattern.compile("[A-Za-z0-9\\+\\/\\=]+");

    private static final String[] SUPPORTED_PROTOCOLS = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" };

    /** default buffer size */
    private static final int DEFAULT_BUF_SIZE = 32768;

    /** max buffer size */
    private static final int MAXIMUM_BUF_SIZE = 10485760;

    /** default buffer read size */
    private static final int DEFAULT_READ_BUF_SIZE = 1024;

    /** request info */
    private HttpRequestEntity request = null;

    /** request status */
    private State status = State.UNINITIALIZED;

    /** proxy */
    private HttpHost proxy = null;

    /** proxy authentication info */
    private String proxyAuthentication = null;

    private RestResponse response;

    /**
     * RestClient constructor
     * 
     */
    public RestClient() {
        checkStatus();
    }

    /**
     * RestClient constructor
     * 
     * @param method
     *            http method
     * @param url
     *            URL
     * @throws URISyntaxException
     *             URL format error
     * 
     */
    public RestClient(String method, String url) throws URISyntaxException {
        this.request = new HttpRequestEntity(method);
        this.request.setURI(new URI(url));
        checkStatus();
    }

    /**
     * RestClient constructor
     * 
     * @param method
     *            http method
     * @param url
     *            URL
     * @param headers
     *            request header
     * @param body
     *            request body
     * @param timeout
     *            connection request timeout(second)
     * @throws URISyntaxException
     *             URL format error
     * @throws UnsupportedEncodingException
     *             charset error
     * 
     */
    public RestClient(String method, String url, Map<String, String> headers, String body, int timeout)
            throws URISyntaxException, UnsupportedEncodingException {
        this.request = new HttpRequestEntity(method);
        this.request.setURI(new URI(url));
        if (headers != null) {
            for (Map.Entry<String, String> header : headers.entrySet()) {
                this.request.setHeader(header.getKey(), header.getValue());
            }
        }
        if (body != null) {
            this.request.setEntity(new RestStringEntity(APPLICATION_JSON, body));
        }
        if (timeout > 0) {
            int timeoutMs = timeout * 1000;
            RequestConfig requestConfig = RequestConfig.custom().setConnectionRequestTimeout(timeoutMs)
                    .setConnectTimeout(timeoutMs).setSocketTimeout(timeoutMs).build();
            request.setConfig(requestConfig);
        }
        checkStatus();
    }

    /**
     * method setter
     * 
     * @param method
     *            http method
     * 
     */
    public void setMethod(String method) {
        if (this.request == null) {
            this.request = new HttpRequestEntity();
        }
        this.request.setHttpMethod(method);
        checkStatus();
    }

    /**
     * url setter
     * 
     * @param url
     *            URL
     * @throws URISyntaxException
     *             URL format error
     * 
     */
    public void setUrl(String url) throws URISyntaxException {
        if (this.request == null) {
            this.request = new HttpRequestEntity();
        }
        this.request.setURI(new URI(url));
        checkStatus();
    }

    /**
     * basicAuthentication setter
     * 
     * @param basicAuthentication
     *            basic Authentication info
     * @throws UnsupportedEncodingException
     *             charset error
     * 
     */
    public void setBasicAuthentication(String basicAuthentication) throws UnsupportedEncodingException {
        if (this.request == null) {
            this.request = new HttpRequestEntity();
        }
        if (basicAuthentication != null) {
            this.request.setHeader(AUTHENTICATION, encodeAuthentication(basicAuthentication));
        }
        checkStatus();
    }

    /**
     * headers setter
     * 
     * @param headers
     *            http request headers
     * 
     */
    public void setHeaders(Map<String, String> headers) {
        if (this.request == null) {
            this.request = new HttpRequestEntity();
        }
        if (headers != null) {
            for (Map.Entry<String, String> header : headers.entrySet()) {
                this.request.setHeader(header.getKey(), header.getValue());
            }
        }
        checkStatus();
    }

    /**
     * string body setter
     * 
     * @param body
     *            http request body
     * @throws UnsupportedEncodingException
     *             charset unsupported
     */
    public void setStringBody(String body) throws UnsupportedEncodingException {
        if (this.request == null) {
            this.request = new HttpRequestEntity();
        }
        this.request.setEntity(new RestStringEntity(APPLICATION_JSON, body));
        checkStatus();
    }

    /**
     * file content set into string body
     * 
     * @param filePath
     *            file path
     * @throws IOException
     *             file read error
     * @throws UnsupportedCharsetException
     *             charset unsupported
     * 
     */
    public void setStringBodyFromFile(String filePath) throws UnsupportedCharsetException, IOException {
        setStringBodyFromFile(new File(filePath));
    }

    /**
     * file content set into string body
     * 
     * @param body
     *            body file object
     * @throws IOException
     *             file read error
     * @throws UnsupportedCharsetException
     *             charset unsupported
     * 
     */
    public void setStringBodyFromFile(File body) throws UnsupportedCharsetException, IOException {
        if (this.request == null) {
            this.request = new HttpRequestEntity();
        }
        this.request.setEntity(new RestStringEntity(APPLICATION_JSON, readFileContent(body, UTF_8)));
        checkStatus();
    }

    /**
     * string body setter
     * 
     * @param mimeType
     *            MIME type
     * @param body
     *            http request body
     * @throws UnsupportedEncodingException
     *             charset unsupported
     */
    public void setStringBody(String mimeType, String body) throws UnsupportedEncodingException {
        if (this.request == null) {
            this.request = new HttpRequestEntity();
        }
        this.request.setEntity(new RestStringEntity(mimeType, body));
        checkStatus();
    }

    /**
     * file body setter
     * 
     * @param body
     *            body file object
     * @throws UnsupportedEncodingException
     *             charset unsupported
     */
    public void setFileBody(File body) throws UnsupportedEncodingException {
        if (this.request == null) {
            this.request = new HttpRequestEntity();
        }
        this.request.setEntity(new RestFileEntity(APPLICATION_FORM_URLENCODED_VALUE, body));
        checkStatus();
    }

    /**
     * proxy setter
     * 
     * @param proxyAddress
     *            proxy address(format addr:port)
     * @throws URISyntaxException
     *             address error
     */
    public void setProxy(String proxyAddress) throws URISyntaxException {
        this.proxy = getProxyInfo(proxyAddress);
        checkStatus();
    }

    /**
     * proxy setter
     * 
     * @param proxyAddress
     *            proxy address
     * @param port
     *            port no
     * @throws URISyntaxException
     *             address error
     */
    public void setProxy(String proxyAddress, int port) throws URISyntaxException {
        this.proxy = getProxyInfo(proxyAddress + ":" + port);
        checkStatus();
    }

    /**
     * proxy setter
     * 
     * @param headers
     *            http request headers
     * @throws URISyntaxException
     *             address error
     * 
     */
    public void setProxyAuthentication(String proxyAuthentication) throws URISyntaxException {
        if (proxyAuthentication != null) {
            this.proxyAuthentication = proxyAuthentication;
        }
        checkStatus();
    }

    /**
     * Authentication encode
     *
     * @param value
     *            encode target
     * @return encode result
     * @throws UnsupportedEncodingException
     *             charset error
     * 
     */
    public String encodeAuthentication(String value) throws UnsupportedEncodingException {

        if (BASE64_CHARS.matcher(value).matches()) {
            return value;
        }
        if (CREDENTIAL.matcher(value).matches()) {
            return new String(Base64.getEncoder().encode(value.getBytes(UTF_8)), UTF_8);
        }
        throw new IllegalArgumentException(value);
    }

    /**
     * Authentication decode
     *
     * @param value
     *            decode target
     * @return decode result
     * @throws UnsupportedEncodingException
     *             charset error
     */
    public static String decodeAuthentication(String value) throws UnsupportedEncodingException {
        String credential = value;

        if (BASE64_CHARS.matcher(value).matches()) {
            credential = new String(Base64.getDecoder().decode(value), UTF_8);
        }
        if (CREDENTIAL.matcher(credential).matches()) {
            return credential;
        }
        throw new IllegalArgumentException(value);
    }

    /**
     * HTTPリクエスト実行
     *
     * @param request
     *            HTTPリクエスト
     * @return HTTPレスポンス
     * @throws Exception
     */
    public void execute() throws Exception {

        status.executeByState(this);
    }

    /**
     * string entity class
     *
     */
    protected class RestStringEntity extends StringEntity {

        /** MIME Type */
        private String mimeType;

        /** Entity content */
        private String entity;

        /**
         * constructor
         *
         * @param mimeType
         *            MIME Type
         * @param entity
         *            Entity content
         * @throws UnsupportedCharsetException
         */
        public RestStringEntity(String mimeType, String entity) throws UnsupportedCharsetException {
            super(entity, ContentType.create(mimeType, UTF_8));
            this.entity = entity;
            this.mimeType = mimeType;
        }

        /**
         * MIME Type getter
         *
         * @return MIME Type
         */
        public String getMimeType() {
            return mimeType;
        }

        /**
         * Entity content getter
         *
         * @return Entity content
         */
        public String getEntityData() {
            return entity;
        }

        @Override
        public String toString() {
            StringBuffer result = new StringBuffer();
            result.append(super.toString() + "\n");
            result.append(entity);
            return result.toString();
        }

    }

    /**
     * File entity class
     *
     */
    protected class RestFileEntity extends FileEntity {

        /** MIME type */
        private String mimeType;

        /** Entity File */
        private File entityFile;

        /**
         * constructor
         *
         * @param mimeType
         *            MIME type
         * @param entityFile
         *            Entity File
         * @throws UnsupportedCharsetException
         */
        public RestFileEntity(String mimeType, File entityFile) throws UnsupportedCharsetException {
            super(entityFile, ContentType.create(mimeType));
            this.entityFile = entityFile;
            this.mimeType = mimeType;
        }

        /**
         * MIME type getter
         *
         * @return MIME type
         */
        public String getMimeType() {
            return mimeType;
        }

        /**
         * Entity File getter
         *
         * @return Entity file
         */
        public File getEntityFile() {
            return entityFile;
        }
    }

    protected class HttpRequestEntity extends HttpEntityEnclosingRequestBase {

        /** HTTP Method */
        private Method method;

        /**
         * Default HttpRequestEntity constructor
         *
         * @param method
         *            HTTP Method
         */
        public HttpRequestEntity() {
            this.method = Method.POST;
        }

        /**
         * HttpRequestEntity constructor
         *
         * @param method
         *            HTTP Method
         */
        public HttpRequestEntity(Method method) {
            this.method = method;
            if (this.method == null) {
                this.method = Method.POST;
            }
        }

        /**
         * HttpRequestEntity constructor
         *
         * @param method
         *            HTTP Method
         */
        public HttpRequestEntity(String method) {
            try {
                this.method = Method.valueOf(method);
            } catch (IllegalArgumentException iae) {
                this.method = Method.POST;
            }
        }

        /**
         * HTTP Method setter
         *
         * @param method
         *            HTTP Method
         */
        public void setHttpMethod(Method method) {
            this.method = method;
            if (this.method == null) {
                this.method = Method.POST;
            }
        }

        /**
         * HTTP Method setter
         *
         * @param method
         *            HTTP Method
         */
        public void setHttpMethod(String method) {
            try {
                setHttpMethod(Method.valueOf(method));
            } catch (IllegalArgumentException iae) {
                setHttpMethod(Method.POST);
            }
        }

        @Override
        public String getMethod() {
            return method.name();
        }
    }

    /**
     * status enum (not initialized, ready to send request, sent request)
     *
     */
    public enum State {
        UNINITIALIZED("not initialized yet") {
            @Override
            protected void executeByState(RestClient rest) throws UnexecutableException {
                StringBuffer errMsg = new StringBuffer();
                errMsg.append("Send request failed.The RestClient haven't finished initialization yet.\n");
                errMsg.append("The url is required.(default method is POST)");
                throw new UnexecutableException(errMsg.toString());
            }
        },
        READY("ready to send request") {
            @Override
            protected void executeByState(RestClient rest) throws KeyManagementException, NoSuchAlgorithmException,
                    NoSuchProviderException, ClientProtocolException, IOException {
                rest.executeRequest();
            }
        },
        ERROR("request has sent, but the result has error") {
            @Override
            protected void executeByState(RestClient rest) throws KeyManagementException, NoSuchAlgorithmException,
                    NoSuchProviderException, ClientProtocolException, IOException {
                rest.executeRequest();
            }
        },
        NORMAL("request has sent, and the result has no error") {
            @Override
            protected void executeByState(RestClient rest) throws KeyManagementException, NoSuchAlgorithmException,
                    NoSuchProviderException, ClientProtocolException, IOException {
                rest.executeRequest();
            }
        };

        private String description;

        State(String description) {
            this.description = description;
        }

        @Override
        public String toString() {
            return this.description;
        }

        abstract protected void executeByState(RestClient rest) throws KeyManagementException, NoSuchAlgorithmException,
                NoSuchProviderException, UnsupportedEncodingException, ClientProtocolException, IOException, UnexecutableException;
    }

    /**
     * HTTP Method
     *
     */
    public static enum Method {
        DELETE, GET, HEAD, POST, PUT
    }

    /**
     * HTTP response info
     *
     */
    public class RestResponse {

        /** HTTP version */
        private String httpVersion;

        /** response status code */
        private int statusCode;

        /** response message */
        private String message;

        /** HTTP response header */
        private Map<String, String> resHeaders;

        /** body (byte) */
        private byte[] rawBody;

        /**
         * コンストラクタ
         *
         * @param response
         *            response
         * @throws IOException
         *             i/o error
         */
        public RestResponse(HttpResponse response) throws IOException {
            readStatusLine(response.getStatusLine());
            readHeaders(response.getAllHeaders());
            readEntity(response.getEntity());
        }

        /**
         * status line analyse
         *
         * @param statusLine
         *            status line
         */
        private void readStatusLine(StatusLine statusLine) {
            httpVersion = statusLine.getProtocolVersion().toString();
            statusCode = statusLine.getStatusCode();
            message = statusLine.getReasonPhrase();
        }

        /**
         * HTTP headers getter
         *
         * @param httpHeaders
         *            HTTP headers
         */
        private void readHeaders(Header[] httpHeaders) {
            resHeaders = new LinkedHashMap<String, String>();
            for (Header httpHeader : httpHeaders) {
                resHeaders.put(httpHeader.getName(), httpHeader.getValue());
            }
        }

        /**
         * HTTP entity content getter
         *
         * @param httpEntity
         *            HTTP entity
         * @throws IOException
         *             i/o error
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

            for (;;) {
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
         * HTTP version getter
         *
         * @return HTTP version
         */
        public String getHttpVersion() {
            return httpVersion;
        }

        /**
         * status code getter
         *
         * @return status code
         */
        public int getStatusCode() {
            return statusCode;
        }

        /**
         * response message getter
         *
         * @return response message
         */
        public String getMessage() {
            return message;
        }

        /**
         * HTTP header getter
         *
         * @return HTTP headers
         */
        public Map<String, String> getHeaders() {
            return resHeaders;
        }

        /**
         * body content(byte) getter
         *
         * @return body content
         */
        public byte[] getRawBody() {
            return this.rawBody;
        }

        /**
         * body string getter
         *
         * @return body
         */
        public String getBodyAsString() {
            try {
                return getBodyAsString(UTF_8);
            } catch (IOException ex) {
                return "";
            }
        }

        /**
         * body string get by charset
         *
         * @param defaultCharset
         *            charset name
         * @return body
         * @throws IOException
         *             charset error
         */
        public String getBodyAsString(String defaultCharset) throws IOException {
            return new String(getRawBody(), getCharset(defaultCharset));
        }

        /**
         * Content-Length getter
         *
         * @param defaultLength
         *            default length
         * @return Content-Length
         */
        public int getContentLength(int defaultLength) {
            String value = resHeaders.get(CONTENT_LENGTH);

            if (value != null) {
                try {
                    return Integer.parseInt(value);
                } catch (NumberFormatException ex) {
                }
            }
            return defaultLength;
        }

        /**
         * Content-Type getter
         *
         * @return Content-Type
         */
        public String getContentType() {
            String value = resHeaders.get(CONTENT_TYPE);

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
         * charset getter
         *
         * @param defaultCharset
         *            default chaset name
         * @return chaset name
         */
        public String getCharset(String defaultCharset) {
            String value = resHeaders.get(CONTENT_TYPE);

            if (value != null) {
                int pos = value.indexOf("charset=");

                if (pos > 0) {
                    return value.substring(pos + 8);
                }
            }
            return defaultCharset;
        }

        @Override
        public String toString() {

            StringBuffer result = new StringBuffer();

            result.append("httpVersion: " + httpVersion + "\n");
            result.append("statusCode: " + statusCode + "\n");
            result.append("message: " + message + "\n");
            result.append("headers \n");
            for (Map.Entry<String, String> header : resHeaders.entrySet()) {
                result.append(header.getKey() + ": " + header.getValue() + "\n");
            }
            try {
                result.append("body: \n" + getBodyAsString(UTF_8) + "\n");
            } catch (IOException e) {
            }

            return result.toString();
        }

    }

    /**
     * Any host Verifier
     *
     */
    private static class AnyHostnameVerifier implements HostnameVerifier {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

    /**
     * default X509 trust manager
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

    private void executeRequest() throws KeyManagementException, NoSuchAlgorithmException, NoSuchProviderException,
            ClientProtocolException, IOException {
        HttpClientBuilder builder = HttpClients.custom();

        if (PROTOCOL_HTTPS.equals(request.getURI().getScheme())) {
            // SSL
            TrustManager[] tm = { new DefaultX509TrustManager() };
            SSLContext sslContext = SSLContext.getInstance("SSL", "SunJSSE");
            sslContext.init(null, tm, new java.security.SecureRandom());
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext, SUPPORTED_PROTOCOLS, null,
                    new AnyHostnameVerifier());
            builder.setSSLSocketFactory(sslsf);
        }
        if (proxy != null) {

            builder.setProxy(proxy);
            if (proxyAuthentication != null) {
                String[] fields = decodeAuthentication(proxyAuthentication).split(":");
                CredentialsProvider credentialsProvider = new BasicCredentialsProvider();

                credentialsProvider.setCredentials(new AuthScope(proxy),
                        new UsernamePasswordCredentials(fields[0], fields[1]));
                builder.setDefaultCredentialsProvider(credentialsProvider);
            }
        }
        HttpClient client = builder.build();
        setResponse(client.execute(request));
    }

    /**
     * restClient status check
     *
     */
    private void checkStatus() {
        if (request == null || request.getURI() == null) {
            status = State.UNINITIALIZED;
            return;
        }
        status = State.READY;
    }

    /**
     * read file content as string
     *
     * @param file
     *            file object
     * @param encode
     *            file charset
     * @return file content
     * @throws IOException
     *             file read i/o error
     */
    private String readFileContent(File file, String encode) throws IOException {
        StringBuffer fileContent = new StringBuffer();
        byte[] buffer = new byte[DEFAULT_READ_BUF_SIZE];
        ByteArrayOutputStream byteOs = null;
        InputStream fileInStr = null;
        try {
            fileInStr = new FileInputStream(file);
            byteOs = new ByteArrayOutputStream();
            int readLen = 0;
            while ((readLen = fileInStr.read(buffer)) != -1) {
                byteOs.write(buffer, 0, readLen);
            }
            fileContent.append(new String(byteOs.toByteArray(), encode));
        } finally {
            if (fileInStr != null) {
                fileInStr.close();
            }
            if (byteOs != null) {
                byteOs.close();
            }
        }
        return fileContent.toString();
    }

    /**
     * proxy info getter
     *
     * @param proxyAddress
     *            proxy address(addr:port)
     * @return proxy host
     * @throws URISyntaxException
     */
    private HttpHost getProxyInfo(String proxyAddress) throws URISyntaxException {
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
     * response getter
     * 
     * @param http
     *            response
     * @throws IOException
     */
    private void setResponse(HttpResponse response) throws IOException {
        this.response = new RestResponse(response);
        this.status = State.NORMAL;
        if (!RM_OK.equals(this.response.getMessage())) {
            this.status = State.ERROR;
        }
    }

    /**
     * response getter
     * 
     * @return http response info
     */
    public RestResponse getResponse() {
        return response;
    }

    @Override
    public String toString() {
        StringBuffer result = new StringBuffer();

        result.append("status: " + status.description + "\n");
        result.append("method: " + request.getMethod() + "\n");
        result.append("url: " + request.getURI() + "\n");
        result.append("headers \n");
        for (Header header : request.getAllHeaders()) {
            result.append(header.getName() + ": " + header.getValue() + "\n");
        }
        result.append("body: \n" + request.getEntity() + "\n");
        result.append("proxy host: " + proxy + "\n");
        result.append("proxy Authentication: " + proxyAuthentication + "\n");

        return result.toString();
    }

}
