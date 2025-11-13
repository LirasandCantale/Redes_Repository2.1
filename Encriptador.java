import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;

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

    // --- HEX helpers ---
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() == 0) return new byte[0];
        int len = hex.length();
        if (len % 2 != 0) throw new IllegalArgumentException("Hex string must have even length");
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }

    // Convert public key <-> hex (instead of Base64)
    public static String publicKeyToHex(PublicKey clave) {
        return bytesToHex(clave.getEncoded());
    }

    public static PublicKey publicKeyFromHex(String hex) throws Exception {
        byte[] bytes = hexToBytes(hex);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    // sanitize filenames for Windows (replace ':' -> '_')
    private static String sanitizeFilename(String nombre) {
        return nombre.replace(':', '_');
    }

    public static void guardarClavePublicaEnArchivo(String nombre, String pubHex) {
        try {
            Path dir = Paths.get("keys");
            if (!Files.exists(dir)) Files.createDirectories(dir);
            String safe = sanitizeFilename(nombre);
            Files.writeString(dir.resolve(safe + ".pub"), pubHex);
        } catch (IOException e) {
            System.err.println("Error guardando clave pública: " + e.getMessage());
        }
    }

    public static String leerClavePublicaDesdeArchivoComoHex(String nombre) {
        try {
            String safe = sanitizeFilename(nombre);
            Path path = Paths.get("keys", safe + ".pub");
            if (Files.exists(path)) return Files.readString(path).trim();
        } catch (IOException ignored) {}
        return null;
    }
}
