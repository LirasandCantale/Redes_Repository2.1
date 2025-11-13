import java.util.*;

public class Mensaje {
    private String origen;
    private String destino;
    private String encAesKeyHex;
    private String ivHex;
    private String ciphertextHex;
    private String signatureHex;
    private List<String> camino;

    public Mensaje(String origen, String destino, String encAesKeyHex, String ivHex,
                   String ciphertextHex, String signatureHex, String primerNodo) {
        this.origen = origen;
        this.destino = destino;
        this.encAesKeyHex = encAesKeyHex;
        this.ivHex = ivHex;
        this.ciphertextHex = ciphertextHex;
        this.signatureHex = signatureHex;
        this.camino = new ArrayList<>();
        if (primerNodo != null && !primerNodo.isEmpty()) {
            this.camino.add(primerNodo);
        }
    }

    public static Mensaje desdeTexto(String texto) {
        String[] partes = texto.split(";", 7);
        // defensiva: validar longitud
        if (partes.length < 7) {
            throw new IllegalArgumentException("Formato de mensaje inválido, se esperaban 7 partes");
        }
        // partes[6] es la lista de camino separada por comas (puede estar vacía)
        String caminoStr = partes[6];
        // primerNodo será el primer elemento del camino (si existe) para compatibilidad con constructor
        String primerNodo = "";
        if (!caminoStr.isEmpty()) {
            String[] caminoParts = caminoStr.split(",");
            if (caminoParts.length > 0) primerNodo = caminoParts[0];
        }
        Mensaje m = new Mensaje(partes[0], partes[1], partes[2], partes[3], partes[4], partes[5], primerNodo);
        // reconstruimos la lista entera correctamente
        m.camino = new ArrayList<>();
        if (!caminoStr.isEmpty()) {
            String[] caminoParts = caminoStr.split(",");
            for (String c : caminoParts) {
                if (!c.isEmpty()) m.camino.add(c);
            }
        }
        return m;
    }

    public String aTexto() {
        return String.join(";", origen, destino, encAesKeyHex, ivHex, ciphertextHex, signatureHex, String.join(",", camino));
    }

    public void agregarAlCamino(String nodo) {
        if (!camino.contains(nodo)) camino.add(nodo);
    }

    public String getOrigen() { return origen; }
    public String getDestino() { return destino; }
    public String getEncAesKeyHex() { return encAesKeyHex; }
    public String getIvHex() { return ivHex; }
    public String getCiphertextHex() { return ciphertextHex; }
    public String getSignatureHex() { return signatureHex; }
    public List<String> getCamino() { return camino; }
}
