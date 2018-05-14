package org.bonitasoft.filter.allowed;

import java.io.IOException;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FilterRemoteAddr implements Filter {

    private final String bannerHeader = "--------------------- FilterRemoteAddr V1.0: ";

    public Logger logger = Logger.getLogger(FilterRemoteAddr.class.getName());

    FilterConfig filterConfig = null;
    String allowSt = null;
    String denySt = null;
    /**
     * The regular expression used to test for allowed requests.
     */
    protected Pattern allow = null;
    protected Pattern deny = null;



    public void init(final FilterConfig filterConfig) throws ServletException {
        allowSt = filterConfig.getInitParameter("allow");
        denySt = filterConfig.getInitParameter("deny");
        allow = compileWithLog(allowSt, "allow");
        deny = compileWithLog(denySt, "deny");
        
        logger.info(bannerHeader+" allowSt[" + allowSt + "] Active? "+(allow!=null)+" denySt["+denySt+"] Active? "+(deny!=null));
        this.filterConfig = filterConfig;
    }

    Pattern compileWithLog( String source, String name)
    {
        try
        {
        if (source!=null && source.length()>0)
            return Pattern.compile(source);
        return null;
        } catch(PatternSyntaxException pe )
        {
            logger.severe(bannerHeader+" source["+name+"] pattern[" + source + "] Exception "+pe.getMessage());
        }
        return null;
        
    }
    /**
     * Each URL come
     */
    public void doFilter(final ServletRequest servletRequest,
            final ServletResponse servletResponse, final FilterChain chain)
            throws IOException, ServletException {
        
        final HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;

        // final String url = httpRequest.getRequestURL().toString();
        boolean isAllowed = isAllowed(httpRequest.getRemoteAddr());
        if (isAllowed)
            logger.info(bannerHeader+" RemoteAddr "+httpRequest.getRemoteAddr()+"] allowed? "+isAllowed);
        else
            logger.severe(bannerHeader+" RemoteAddr "+httpRequest.getRemoteAddr()+"] allowed? "+isAllowed);
        
        if (isAllowed)
            chain.doFilter(httpRequest, servletResponse);
        else
            throw new ServletException("Not allowed");
        return;

    }

    public void destroy() {

    }
    public boolean isAllowed(String property) {

        // Check the deny patterns, if any
        if (deny != null && deny.matcher(property).matches()) {
            return false;
        }

        // Check the allow patterns, if any
        if (allow != null && allow.matcher(property).matches()) {
            return true;
        }

        // Allow if denies specified but not allows
        if (deny != null && allow == null) {
            return true;
        }

        // Deny this request
        return false;
    }
}
