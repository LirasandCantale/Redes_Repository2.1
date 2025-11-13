import java.util.*;

public class Mensaje {
    private String origen;
    private String destino;
    private String encAesKeyB64;
    private String ivB64;
    private String ciphertextB64;
    private String signatureB64;
    private List<String> camino;

    public Mensaje(String origen, String destino, String encAesKeyB64, String ivB64,
                   String ciphertextB64, String signatureB64, String primerNodo) {
        this.origen = origen;
        this.destino = destino;
        this.encAesKeyB64 = encAesKeyB64;
        this.ivB64 = ivB64;
        this.ciphertextB64 = ciphertextB64;
        this.signatureB64 = signatureB64;
        this.camino = new ArrayList<>();
        this.camino.add(primerNodo);
    }

    public static Mensaje desdeTexto(String texto) {
        String[] partes = texto.split(";", 7);
        Mensaje m = new Mensaje(partes[0], partes[1], partes[2], partes[3], partes[4], partes[5], partes[6]);
        m.camino = new ArrayList<>(Arrays.asList(partes[6].split(",")));
        return m;
    }

    public String aTexto() {
        return String.join(";", origen, destino, encAesKeyB64, ivB64, ciphertextB64, signatureB64, String.join(",", camino));
    }

    public void agregarAlCamino(String nodo) {
        if (!camino.contains(nodo)) camino.add(nodo);
    }

    public String getOrigen() { return origen; }
    public String getDestino() { return destino; }
    public String getEncAesKeyB64() { return encAesKeyB64; }
    public String getIvB64() { return ivB64; }
    public String getCiphertextB64() { return ciphertextB64; }
    public String getSignatureB64() { return signatureB64; }
    public List<String> getCamino() { return camino; }
}
