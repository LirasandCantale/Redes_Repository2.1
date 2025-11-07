public class Mensaje {
    private String origen;
    private String destino;
    private String contenidoCifrado;
    private String claveCifrada;
    private String firma;
    private String camino;

    public Mensaje(String origen, String destino, String contenidoCifrado,
                   String claveCifrada, String firma, String camino) {
        this.origen = origen;
        this.destino = destino;
        this.contenidoCifrado = contenidoCifrado;
        this.claveCifrada = claveCifrada;
        this.firma = firma;
        this.camino = camino;
    }

    public static Mensaje desdeTexto(String texto) {
        String[] partes = texto.split(";");
        return new Mensaje(partes[0], partes[1], partes[2], partes[3], partes[4], partes[5]);
    }

    public String aTexto() {
        return String.join(";", origen, destino, contenidoCifrado, claveCifrada, firma, camino);
    }

    public void agregarAlCamino(String nodo) {
        this.camino += " -> " + nodo;
    }

    public String getOrigen() { return origen; }
    public String getDestino() { return destino; }
    public String getContenidoCifrado() { return contenidoCifrado; }
    public String getClaveCifrada() { return claveCifrada; }
    public String getFirma() { return firma; }
    public String getCamino() { return camino; }
}
