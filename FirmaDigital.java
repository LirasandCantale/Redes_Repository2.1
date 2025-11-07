import java.security.*;
import java.util.Base64;

public class FirmaDigital {

    // Crea una firma digital usando la clave privada
    public static String firmar(String mensaje, PrivateKey clavePrivada) throws Exception {
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initSign(clavePrivada);
        firma.update(mensaje.getBytes());
        byte[] firmaBytes = firma.sign();
        return Base64.getEncoder().encodeToString(firmaBytes);
    }

    // Verifica la firma digital usando la clave pública
    public static boolean verificarFirma(String mensaje, String firmaBase64, PublicKey clavePublica) throws Exception {
        Signature verificador = Signature.getInstance("SHA256withRSA");
        verificador.initVerify(clavePublica);
        verificador.update(mensaje.getBytes());
        byte[] firmaBytes = Base64.getDecoder().decode(firmaBase64);
        return verificador.verify(firmaBytes);
    }
}
