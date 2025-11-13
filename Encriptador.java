import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class Encriptador {

    public static class AesResultado {
        public byte[] cipher;
        public byte[] iv;
        public SecretKey clave;
    }

    public static SecretKey generarClaveAES() throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        return kgen.generateKey();
    }

    public static AesResultado cifrarConAES(byte[] datos, SecretKey clave) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, clave, new IvParameterSpec(iv));
        AesResultado res = new AesResultado();
        res.cipher = cipher.doFinal(datos);
        res.iv = iv;
        res.clave = clave;
        return res;
    }

    public static byte[] descifrarConAES(byte[] datos, byte[] iv, byte[] claveBytes) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(claveBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
        return cipher.doFinal(datos);
    }

    public static byte[] cifrarClaveAESConRSA(SecretKey claveAES, PublicKey pubRSA) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubRSA);
        return cipher.doFinal(claveAES.getEncoded());
    }

    public static byte[] descifrarClaveAESConRSA(byte[] claveCifrada, PrivateKey privRSA) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privRSA);
        return cipher.doFinal(claveCifrada);
    }

    public static String publicKeyToBase64(PublicKey clave) {
        return Base64.getEncoder().encodeToString(clave.getEncoded());
    }

    public static PublicKey publicKeyFromBase64(String b64) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(b64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public static void guardarClavePublicaEnArchivo(String nombre, String pubB64) {
        try {
            Path dir = Paths.get("keys");
            if (!Files.exists(dir)) Files.createDirectories(dir);
            Files.writeString(dir.resolve(nombre + ".pub"), pubB64);
        } catch (IOException e) {
            System.err.println("Error guardando clave pública: " + e.getMessage());
        }
    }

    public static String leerClavePublicaDesdeArchivoComoBase64(String nombre) {
        try {
            Path path = Paths.get("keys", nombre + ".pub");
            if (Files.exists(path)) return Files.readString(path).trim();
        } catch (IOException ignored) {}
        return null;
    }
}
