package com.redmonkeysoftware.proxiedssl;

import java.io.IOException;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.channel.SecureChannelProcessor;
import org.springframework.stereotype.Component;

@Component
public class ProxiedSecureChannelProcessor extends SecureChannelProcessor {

    private final static Logger logger = Logger.getLogger(ProxiedSecureChannelProcessor.class.getName());

    @Override
    public void decide(FilterInvocation invocation, Collection<ConfigAttribute> config) throws IOException, ServletException {
        for (ConfigAttribute attribute : config) {
            if (supports(attribute)) {
                String forwardedProto = invocation.getHttpRequest().getHeader("X-Forwarded-Proto");
                if ("http".equalsIgnoreCase(forwardedProto)) {
                    logger.log(Level.FINE, "Channel is not secure according to X-Forwarded-Proto header - Redirecting");
                    getEntryPoint().commence(invocation.getRequest(), invocation.getResponse());
                } else if ("https".equalsIgnoreCase(forwardedProto)) {
                    logger.log(Level.FINE, "Channel is secure according to X-Forwarded-Proto - Proceeding");
                } else {
                    logger.log(Level.WARNING, "Cannot determine X-Forwarded-Proto header, falling back to default decider");
                    super.decide(invocation, config);
                }
            }
        }
    }
}
