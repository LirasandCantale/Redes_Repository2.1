import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class Encriptador {

    // Genera una clave AES aleatoria (para cifrar el mensaje *cifrado simetrico*)
    public static SecretKey generarClaveAES() throws Exception {
        KeyGenerator generador = KeyGenerator.getInstance("AES");
        generador.init(128);
        return generador.generateKey();
    }

    // Cifra texto con AES
    public static String cifrarAES(String texto, SecretKey clave) throws Exception {
        Cipher cifrador = Cipher.getInstance("AES");
        cifrador.init(Cipher.ENCRYPT_MODE, clave);
        byte[] cifrado = cifrador.doFinal(texto.getBytes());
        return Base64.getEncoder().encodeToString(cifrado);
    }

    // Descifra texto con AES
    public static String descifrarAES(String textoCifrado, SecretKey clave) throws Exception {
        Cipher cifrador = Cipher.getInstance("AES");
        cifrador.init(Cipher.DECRYPT_MODE, clave);
        byte[] decodificado = Base64.getDecoder().decode(textoCifrado);
        byte[] descifrado = cifrador.doFinal(decodificado);
        return new String(descifrado);
    }

    // Genera un par de claves RSA (pública/privada *cifrado asimetrico*)
    public static KeyPair generarParRSA() throws Exception {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
        generador.initialize(2048);
        return generador.generateKeyPair();
    }

    // Cifra datos con RSA (normalmente usado para cifrar la clave AES)
    public static String cifrarRSA(byte[] datos, PublicKey clavePublica) throws Exception {
        Cipher cifrador = Cipher.getInstance("RSA");
        cifrador.init(Cipher.ENCRYPT_MODE, clavePublica);
        byte[] cifrado = cifrador.doFinal(datos);
        return Base64.getEncoder().encodeToString(cifrado);
    }

    // Descifra datos con RSA
    public static byte[] descifrarRSA(String datosCifrados, PrivateKey clavePrivada) throws Exception {
        Cipher cifrador = Cipher.getInstance("RSA");
        cifrador.init(Cipher.DECRYPT_MODE, clavePrivada);
        byte[] decodificado = Base64.getDecoder().decode(datosCifrados);
        return cifrador.doFinal(decodificado);
    }
}
