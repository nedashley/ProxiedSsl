package com.redmonkeysoftware.proxiedssl;

import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.web.access.channel.ChannelDecisionManagerImpl;
import org.springframework.security.web.access.channel.ChannelProcessor;

@Configuration
public class ProxiedSslPostProcessor implements BeanPostProcessor {

    @Autowired
    private ProxiedSecureChannelProcessor secureChannelProcessor;
    @Autowired
    private ProxiedInsecureChannelProcessor insecureChannelProcessor;
    @Autowired
    private Environment env;

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (env.getProperty("behind.loadbalancer", Boolean.class, false) && bean instanceof ChannelDecisionManagerImpl) {
            List<ChannelProcessor> processors = new ArrayList<ChannelProcessor>();
            processors.add(insecureChannelProcessor);
            processors.add(secureChannelProcessor);
            ((ChannelDecisionManagerImpl) bean).setChannelProcessors(processors);
        }
        return bean;
    }

    public void setSecureChannelProcessor(ProxiedSecureChannelProcessor secureChannelProcessor) {
        this.secureChannelProcessor = secureChannelProcessor;
    }

    public void setInsecureChannelProcessor(ProxiedInsecureChannelProcessor insecureChannelProcessor) {
        this.insecureChannelProcessor = insecureChannelProcessor;
    }
}
