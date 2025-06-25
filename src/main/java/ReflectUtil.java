import java.lang.reflect.Field;

public class ReflectUtil {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = null;
        Class<?> clazz = obj.getClass();
        while (clazz != null) {
            try {
                field = clazz.getDeclaredField(fieldName);
                break;
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        if (field == null) {
            throw new NoSuchFieldException(fieldName);
        }
        field.setAccessible(true);
        field.set(obj, value);
    }
}

