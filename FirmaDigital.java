import java.security.*;

public class FirmaDigital {
    // Firma devuelve HEX (en lugar de Base64)
    public static String firmar(byte[] datos, PrivateKey clavePrivada) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(clavePrivada);
        sig.update(datos);
        byte[] firma = sig.sign();
        return Encriptador.bytesToHex(firma);
    }

    // Verifica usando firma HEX
    public static boolean verificarFirma(byte[] datos, String firmaHex, PublicKey clavePublica) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(clavePublica);
        sig.update(datos);
        byte[] firma = Encriptador.hexToBytes(firmaHex);
        return sig.verify(firma);
    }
}
