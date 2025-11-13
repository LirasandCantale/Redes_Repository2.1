import java.security.*;
import java.util.Base64;

public class FirmaDigital {
    public static String firmar(byte[] datos, PrivateKey clavePrivada) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(clavePrivada);
        sig.update(datos);
        return Base64.getEncoder().encodeToString(sig.sign());
    }

    public static boolean verificarFirma(byte[] datos, String firmaB64, PublicKey clavePublica) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(clavePublica);
        sig.update(datos);
        byte[] firma = Base64.getDecoder().decode(firmaB64);
        return sig.verify(firma);
    }
}
