
package org.apache.catalina.filters;


import java.io.IOException;

import java.text.DateFormat;

import java.text.SimpleDateFormat;

import java.util.ArrayList;

import java.util.Arrays;

import java.util.Collections;

import java.util.Date;

import java.util.Enumeration;

import java.util.HashMap;

import java.util.Iterator;

import java.util.LinkedList;

import java.util.List;

import java.util.Locale;

import java.util.Map;

import java.util.regex.Pattern;

import java.util.regex.PatternSyntaxException;


import javax.servlet.Filter;

import javax.servlet.FilterChain;

import javax.servlet.FilterConfig;

import javax.servlet.ServletException;

import javax.servlet.ServletRequest;

import javax.servlet.ServletResponse;

import javax.servlet.http.HttpServletRequest;

import javax.servlet.http.HttpServletRequestWrapper;

import javax.servlet.http.HttpServletResponse;


import org.apache.juli.logging.Log;

import org.apache.juli.logging.LogFactory;

public class RemoteIpFilter implements Filter {

    public static class XForwardedRequest extends HttpServletRequestWrapper {

        

        final static ThreadLocal<SimpleDateFormat[]> threadLocalDateFormats = new ThreadLocal<SimpleDateFormat[]>() {

            @Override

            protected SimpleDateFormat[] initialValue() {

                return new SimpleDateFormat[] {

                    new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US),

                    new SimpleDateFormat("EEEEEE, dd-MMM-yy HH:mm:ss zzz", Locale.US),

                    new SimpleDateFormat("EEE MMMM d HH:mm:ss yyyy", Locale.US)

                };

                

            }

        };

        

        protected Map<String, List<String>> headers;

        

        protected String remoteAddr;

        

        protected String remoteHost;

        

        protected String scheme;

        

        protected boolean secure;

        

        protected int serverPort;

        

        public XForwardedRequest(HttpServletRequest request) {

            super(request);

            this.remoteAddr = request.getRemoteAddr();

            this.remoteHost = request.getRemoteHost();

            this.scheme = request.getScheme();

            this.secure = request.isSecure();

            this.serverPort = request.getServerPort();

            

            headers = new HashMap<String, List<String>>();

            for (Enumeration<String> headerNames = request.getHeaderNames(); headerNames.hasMoreElements();) {

                String header = headerNames.nextElement();

                headers.put(header, Collections.list(request.getHeaders(header)));

            }

        }

        

        @Override

        public long getDateHeader(String name) {

            String value = getHeader(name);

            if (value == null) {

                return -1;

            }

            DateFormat[] dateFormats = threadLocalDateFormats.get();

            Date date = null;

            for (int i = 0; ((i < dateFormats.length) && (date == null)); i++) {

                DateFormat dateFormat = dateFormats[i];

                try {

                    date = dateFormat.parse(value);

                } catch (Exception ParseException) {

                    // Ignore

                }

            }

            if (date == null) {

                throw new IllegalArgumentException(value);

            }

            return date.getTime();

        }

        

        @Override

        public String getHeader(String name) {

            Map.Entry<String, List<String>> header = getHeaderEntry(name);

            if (header == null || header.getValue() == null || header.getValue().isEmpty()) {

                return null;

            }

            return header.getValue().get(0);

        }

        

        protected Map.Entry<String, List<String>> getHeaderEntry(String name) {

            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {

                if (entry.getKey().equalsIgnoreCase(name)) {

                    return entry;

                }

            }

            return null;

        }

        

        @Override

        public Enumeration<String> getHeaderNames() {

            return Collections.enumeration(headers.keySet());

        }

        

        @Override

        public Enumeration<String> getHeaders(String name) {

            Map.Entry<String, List<String>> header = getHeaderEntry(name);

            if (header == null || header.getValue() == null) {

                return Collections.enumeration(Collections.<String>emptyList());

            }

            return Collections.enumeration(header.getValue());

        }

        

        @Override

        public int getIntHeader(String name) {

            String value = getHeader(name);

            if (value == null) {

                return -1;

            }

            return Integer.parseInt(value);

        }

        

        @Override

        public String getRemoteAddr() {

            return this.remoteAddr;

        }

        

        @Override

        public String getRemoteHost() {

            return this.remoteHost;

        }

        

        @Override

        public String getScheme() {

            return scheme;

        }

        

        @Override

        public int getServerPort() {

            return serverPort;

        }

        

        @Override

        public boolean isSecure() {

            return secure;

        }

        

        public void removeHeader(String name) {

            Map.Entry<String, List<String>> header = getHeaderEntry(name);

            if (header != null) {

                headers.remove(header.getKey());

            }

        }

        

        public void setHeader(String name, String value) {

            List<String> values = Arrays.asList(value);

            Map.Entry<String, List<String>> header = getHeaderEntry(name);

            if (header == null) {

                headers.put(name, values);

            } else {

                header.setValue(values);

            }

            

        }

        

        public void setRemoteAddr(String remoteAddr) {

            this.remoteAddr = remoteAddr;

        }

        

        public void setRemoteHost(String remoteHost) {

            this.remoteHost = remoteHost;

        }

        

        public void setScheme(String scheme) {

            this.scheme = scheme;

        }

        

        public void setSecure(boolean secure) {

            this.secure = secure;

        }

        

        public void setServerPort(int serverPort) {

            this.serverPort = serverPort;

        }

    }

    

    /**

     * {@link Pattern} for a comma delimited string that support whitespace characters

     */

    private static final Pattern commaSeparatedValuesPattern = Pattern.compile("\\s*,\\s*");

    

    protected static final String HTTP_SERVER_PORT_PARAMETER = "httpServerPort";


    protected static final String HTTPS_SERVER_PORT_PARAMETER = "httpsServerPort";

    

    protected static final String INTERNAL_PROXIES_PARAMETER = "internalProxies";

    

    /**

     * Logger

     */

    private static final Log log = LogFactory.getLog(RemoteIpFilter.class);

    

    protected static final String PROTOCOL_HEADER_PARAMETER = "protocolHeader";

    

    protected static final String PROTOCOL_HEADER_HTTPS_VALUE_PARAMETER = "protocolHeaderHttpsValue";

    

    protected static final String PROXIES_HEADER_PARAMETER = "proxiesHeader";

    

    protected static final String REMOTE_IP_HEADER_PARAMETER = "remoteIpHeader";

    

    protected static final String TRUSTED_PROXIES_PARAMETER = "trustedProxies";

    

    /**

     * Convert a given comma delimited list of regular expressions into an array of compiled {@link Pattern}

     * 

     * @return array of patterns (not <code>null</code>)

     */

    protected static Pattern[] commaDelimitedListToPatternArray(String commaDelimitedPatterns) {

        String[] patterns = commaDelimitedListToStringArray(commaDelimitedPatterns);

        List<Pattern> patternsList = new ArrayList<Pattern>();

        for (String pattern : patterns) {

            try {

                patternsList.add(Pattern.compile(pattern));

            } catch (PatternSyntaxException e) {

                throw new IllegalArgumentException("Illegal pattern syntax '" + pattern + "'", e);

            }

        }

        return patternsList.toArray(new Pattern[0]);

    }

    

    /**

     * Convert a given comma delimited list of regular expressions into an array of String

     * 

     * @return array of patterns (non <code>null</code>)

     */

    protected static String[] commaDelimitedListToStringArray(String commaDelimitedStrings) {

        return (commaDelimitedStrings == null || commaDelimitedStrings.length() == 0) ? new String[0] : commaSeparatedValuesPattern

            .split(commaDelimitedStrings);

    }

    

    /**

     * Convert an array of strings in a comma delimited string

     */

    protected static String listToCommaDelimitedString(List<String> stringList) {

        if (stringList == null) {

            return "";

        }

        StringBuilder result = new StringBuilder();

        for (Iterator<String> it = stringList.iterator(); it.hasNext();) {

            Object element = it.next();

            if (element != null) {

                result.append(element);

                if (it.hasNext()) {

                    result.append(", ");

                }

            }

        }

        return result.toString();

    }

    

    /**

     * Return <code>true</code> if the given <code>str</code> matches at least one of the given <code>patterns</code>.

     */

    protected static boolean matchesOne(String str, Pattern... patterns) {

        for (Pattern pattern : patterns) {

            if (pattern.matcher(str).matches()) {

                return true;

            }

        }

        return false;

    }

    

    /**

     * @see #setHttpServerPort(int)

     */

    private int httpServerPort = 80;


    /**

     * @see #setHttpsServerPort(int)

     */

    private int httpsServerPort = 443;


    /**

     * @see #setInternalProxies(String)

     */

    private Pattern[] internalProxies = new Pattern[] {

        Pattern.compile("10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"), Pattern.compile("192\\.168\\.\\d{1,3}\\.\\d{1,3}"),

        Pattern.compile("169\\.254\\.\\d{1,3}\\.\\d{1,3}"), Pattern.compile("127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")

    };

    

    /**

     * @see #setProtocolHeader(String)

     */

    private String protocolHeader = null;

    

    private String protocolHeaderHttpsValue = "https";

    

    /**

     * @see #setProxiesHeader(String)

     */

    private String proxiesHeader = "X-Forwarded-By";

    

    /**

     * @see #setRemoteIpHeader(String)

     */

    private String remoteIpHeader = "X-Forwarded-For";

    

    /**

     * @see #setTrustedProxies(String)

     */

    private Pattern[] trustedProxies = new Pattern[0];

    

    public void destroy() {

        // NOOP

    }

    

    public void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        

        if (matchesOne(request.getRemoteAddr(), internalProxies)) {

            String remoteIp = null;

            // In java 6, proxiesHeaderValue should be declared as a java.util.Deque

            LinkedList<String> proxiesHeaderValue = new LinkedList<String>();

            

            String[] remoteIpHeaderValue = commaDelimitedListToStringArray(request.getHeader(remoteIpHeader));

            int idx;

            // loop on remoteIpHeaderValue to find the first trusted remote ip and to build the proxies chain

            for (idx = remoteIpHeaderValue.length - 1; idx >= 0; idx--) {

                String currentRemoteIp = remoteIpHeaderValue[idx];

                remoteIp = currentRemoteIp;

                if (matchesOne(currentRemoteIp, internalProxies)) {

                    // do nothing, internalProxies IPs are not appended to the

                } else if (matchesOne(currentRemoteIp, trustedProxies)) {

                    proxiesHeaderValue.addFirst(currentRemoteIp);

                } else {

                    idx--; // decrement idx because break statement doesn't do it

                    break;

                }

            }

            // continue to loop on remoteIpHeaderValue to build the new value of the remoteIpHeader

            LinkedList<String> newRemoteIpHeaderValue = new LinkedList<String>();

            for (; idx >= 0; idx--) {

                String currentRemoteIp = remoteIpHeaderValue[idx];

                newRemoteIpHeaderValue.addFirst(currentRemoteIp);

            }

            

            XForwardedRequest xRequest = new XForwardedRequest(request);

            if (remoteIp != null) {

                

                xRequest.setRemoteAddr(remoteIp);

                xRequest.setRemoteHost(remoteIp);

                

                if (proxiesHeaderValue.size() == 0) {

                    xRequest.removeHeader(proxiesHeader);

                } else {

                    String commaDelimitedListOfProxies = listToCommaDelimitedString(proxiesHeaderValue);

                    xRequest.setHeader(proxiesHeader, commaDelimitedListOfProxies);

                }

                if (newRemoteIpHeaderValue.size() == 0) {

                    xRequest.removeHeader(remoteIpHeader);

                } else {

                    String commaDelimitedRemoteIpHeaderValue = listToCommaDelimitedString(newRemoteIpHeaderValue);

                    xRequest.setHeader(remoteIpHeader, commaDelimitedRemoteIpHeaderValue);

                }

            }

            

            if (protocolHeader != null) {

                String protocolHeaderValue = request.getHeader(protocolHeader);

                if (protocolHeaderValue == null) {

                    // don't modify the secure,scheme and serverPort attributes of the request

                } else if (protocolHeaderHttpsValue.equalsIgnoreCase(protocolHeaderValue)) {

                    xRequest.setSecure(true);

                    xRequest.setScheme("https");

                    xRequest.setServerPort(httpsServerPort);

                } else {

                    xRequest.setSecure(false);

                    xRequest.setScheme("http");

                    xRequest.setServerPort(httpServerPort);

                }

            }

            

            if (log.isDebugEnabled()) {

                log.debug("Incoming request " + request.getRequestURI() + " with originalRemoteAddr '" + request.getRemoteAddr()

                        + "', originalRemoteHost='" + request.getRemoteHost() + "', originalSecure='" + request.isSecure()

                        + "', originalScheme='" + request.getScheme() + "', original[" + remoteIpHeader + "]='"

                        + request.getHeader(remoteIpHeader) + ", original[" + protocolHeader + "]='"

                        + (protocolHeader == null ? null : request.getHeader(protocolHeader)) + "' will be seen as newRemoteAddr='"

                        + xRequest.getRemoteAddr() + "', newRemoteHost='" + xRequest.getRemoteHost() + "', newScheme='"

                        + xRequest.getScheme() + "', newSecure='" + xRequest.isSecure() + "', new[" + remoteIpHeader + "]='"

                        + xRequest.getHeader(remoteIpHeader) + ", new[" + proxiesHeader + "]='" + xRequest.getHeader(proxiesHeader) + "'");

            }

            chain.doFilter(xRequest, response);

        } else {

            if (log.isDebugEnabled()) {

                log.debug("Skip RemoteIpFilter for request " + request.getRequestURI() + " with originalRemoteAddr '"

                        + request.getRemoteAddr() + "'");

            }

            chain.doFilter(request, response);

        }

        

    }

    

    /**

     * Wrap the incoming <code>request</code> in a {@link XForwardedRequest} if the http header <code>x-forwareded-for</code> is not empty.

     */

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {

            doFilter((HttpServletRequest)request, (HttpServletResponse)response, chain);

        } else {

            chain.doFilter(request, response);

        }

    }

    

    public int getHttpsServerPort() {

        return httpsServerPort;

    }

    

    public Pattern[] getInternalProxies() {

        return internalProxies;

    }

    

    public String getProtocolHeader() {

        return protocolHeader;

    }

    

    public String getProtocolHeaderHttpsValue() {

        return protocolHeaderHttpsValue;

    }

    

    public String getProxiesHeader() {

        return proxiesHeader;

    }

    

    public String getRemoteIpHeader() {

        return remoteIpHeader;

    }

    

    public Pattern[] getTrustedProxies() {

        return trustedProxies;

    }

    

    public void init(FilterConfig filterConfig) throws ServletException {

        if (filterConfig.getInitParameter(INTERNAL_PROXIES_PARAMETER) != null) {

            setInternalProxies(filterConfig.getInitParameter(INTERNAL_PROXIES_PARAMETER));

        }

        

        if (filterConfig.getInitParameter(PROTOCOL_HEADER_PARAMETER) != null) {

            setProtocolHeader(filterConfig.getInitParameter(PROTOCOL_HEADER_PARAMETER));

        }

        

        if (filterConfig.getInitParameter(PROTOCOL_HEADER_HTTPS_VALUE_PARAMETER) != null) {

            setProtocolHeaderHttpsValue(filterConfig.getInitParameter(PROTOCOL_HEADER_HTTPS_VALUE_PARAMETER));

        }

        

        if (filterConfig.getInitParameter(PROXIES_HEADER_PARAMETER) != null) {

            setProxiesHeader(filterConfig.getInitParameter(PROXIES_HEADER_PARAMETER));

        }

        

        if (filterConfig.getInitParameter(REMOTE_IP_HEADER_PARAMETER) != null) {

            setRemoteIpHeader(filterConfig.getInitParameter(REMOTE_IP_HEADER_PARAMETER));

        }

        

        if (filterConfig.getInitParameter(TRUSTED_PROXIES_PARAMETER) != null) {

            setTrustedProxies(filterConfig.getInitParameter(TRUSTED_PROXIES_PARAMETER));

        }

        

        if (filterConfig.getInitParameter(HTTP_SERVER_PORT_PARAMETER) != null) {

            try {

                setHttpServerPort(Integer.parseInt(filterConfig.getInitParameter(HTTP_SERVER_PORT_PARAMETER)));

            } catch (NumberFormatException e) {

                throw new NumberFormatException("Illegal " + HTTP_SERVER_PORT_PARAMETER + " : " + e.getMessage());

            }

        }

        

        if (filterConfig.getInitParameter(HTTPS_SERVER_PORT_PARAMETER) != null) {

            try {

                setHttpsServerPort(Integer.parseInt(filterConfig.getInitParameter(HTTPS_SERVER_PORT_PARAMETER)));

            } catch (NumberFormatException e) {

                throw new NumberFormatException("Illegal " + HTTPS_SERVER_PORT_PARAMETER + " : " + e.getMessage());

            }

        }

    }

    

    /**

     * <p>

     * Server Port value if the {@link #protocolHeader} indicates HTTP (i.e. {@link #protocolHeader} is not null and

     * has a value different of {@link #protocolHeaderHttpsValue}). 

     * </p>

     * <p>

     * Default value : 80

     * </p>

     */

    public void setHttpServerPort(int httpServerPort) {

        this.httpServerPort = httpServerPort;

    }

    

    /**

     * <p>

     * Server Port value if the {@link #protocolHeader} indicates HTTPS

     * </p>

     * <p>

     * Default value : 443

     * </p>

     */

    public void setHttpsServerPort(int httpsServerPort) {

        this.httpsServerPort = httpsServerPort;

    }

    

    /**

     * <p>

     * Comma delimited list of internal proxies. Can be expressed with regular expressions.

     * </p>

     * <p>

     * Default value : 10\.\d{1,3}\.\d{1,3}\.\d{1,3}, 192\.168\.\d{1,3}\.\d{1,3}, 127\.\d{1,3}\.\d{1,3}\.\d{1,3}

     * </p>

     */

    public void setInternalProxies(String internalProxies) {

        this.internalProxies = commaDelimitedListToPatternArray(internalProxies);

    }

    

    /**

     * <p>

     * Header that holds the incoming protocol, usally named <code>X-Forwarded-Proto</code>. If <code>null</code>, request.scheme and

     * request.secure will not be modified.

     * </p>

     * <p>

     * Default value : <code>null</code>

     * </p>

     */

    public void setProtocolHeader(String protocolHeader) {

        this.protocolHeader = protocolHeader;

    }

    

    /**

     * <p>

     * Case insensitive value of the protocol header to indicate that the incoming http request uses HTTPS.

     * </p>

     * <p>

     * Default value : <code>https</code>

     * </p>

     */

    public void setProtocolHeaderHttpsValue(String protocolHeaderHttpsValue) {

        this.protocolHeaderHttpsValue = protocolHeaderHttpsValue;

    }

    

    /**

     * <p>

     * The proxiesHeader directive specifies a header into which mod_remoteip will collect a list of all of the intermediate client IP

     * addresses trusted to resolve the actual remote IP. Note that intermediate RemoteIPTrustedProxy addresses are recorded in this header,

     * while any intermediate RemoteIPInternalProxy addresses are discarded.

     * </p>

     * <p>

     * Name of the http header that holds the list of trusted proxies that has been traversed by the http request.

     * </p>

     * <p>

     * The value of this header can be comma delimited.

     * </p>

     * <p>

     * Default value : <code>X-Forwarded-By</code>

     * </p>

     */

    public void setProxiesHeader(String proxiesHeader) {

        this.proxiesHeader = proxiesHeader;

    }

    

    /**

     * <p>

     * Name of the http header from which the remote ip is extracted.

     * </p>

     * <p>

     * The value of this header can be comma delimited.

     * </p>

     * <p>

     * Default value : <code>X-Forwarded-For</code>

     * </p>

     */

    public void setRemoteIpHeader(String remoteIpHeader) {

        this.remoteIpHeader = remoteIpHeader;

    }

    

    /**

     * <p>

     * Comma delimited list of proxies that are trusted when they appear in the {@link #remoteIpHeader} header. Can be expressed as a

     * regular expression.

     * </p>

     * <p>

     * Default value : empty list, no external proxy is trusted.

     * </p>

     */

    public void setTrustedProxies(String trustedProxies) {

        this.trustedProxies = commaDelimitedListToPatternArray(trustedProxies);

    }

}


searchcode is proudly made in Sydney Australia by Ben Boyter
