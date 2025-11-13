import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

public class PCNode {
    private String ip;
    private int puerto;
    private List<String> vecinos;
    public String nombre;

    ServerSocket server;
    volatile boolean activo = true;

    private PublicKey miClavePublica;
    private PrivateKey miClavePrivada;

    private static ConcurrentMap<String, PublicKey> clavesPublicas = new ConcurrentHashMap<>();

    public PCNode(String ip, int puerto) throws Exception {
        this.ip = ip;
        this.puerto = puerto;
        this.vecinos = new ArrayList<>();
        this.nombre = ip + "_" + puerto;

        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        this.miClavePublica = kp.getPublic();
        this.miClavePrivada = kp.getPrivate();

        String miPubHex = Encriptador.publicKeyToHex(miClavePublica);
        Encriptador.guardarClavePublicaEnArchivo(this.nombre, miPubHex);
        System.out.println("Nodo " + nombre + " iniciado. Clave pública guardada en keys/" + nombre + ".pub");
    }

    public void agregarVecino(String ip, int puerto) {
        vecinos.add(ip + "_" + puerto);
    }

    public void iniciar() {
        new Thread(() -> {
            try {
                server = new ServerSocket(puerto);
                System.out.println("PC " + nombre + " escuchando en puerto " + puerto);

                while (activo) {
                    try (Socket socket = server.accept();
                         BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                         PrintWriter out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true)) {

                        String linea = in.readLine();
                        if (linea == null) continue;

                        // DEBUG: mostramos lo que llega crudo
                        System.out.println("[DEBUG] Recibido crudo en " + nombre + ": " + linea);

                        if (linea.equals("GET_PUBKEY")) {
                            out.println(Encriptador.publicKeyToHex(miClavePublica));
                            continue;
                        }

                        procesarMensaje(linea);

                    } catch (SocketException se) {
                        if (!activo) break;
                    } catch (Exception e) {
                        System.err.println("Error en conexión (aceptar/manejar): ");
                        e.printStackTrace();
                    }
                }
            } catch (IOException e) {
                System.err.println("Error creando ServerSocket: " + e.getMessage());
                e.printStackTrace();
            } finally {
                System.out.println("Servidor de " + nombre + " detenido.");
            }
        }).start();
    }

    private void procesarMensaje(String texto) {
        try {
            Mensaje mensaje = Mensaje.desdeTexto(texto);
            mensaje.agregarAlCamino(nombre);

            boolean soyDestino = nombre.equals(mensaje.getDestino()) || "TODOS".equals(mensaje.getDestino());

            if (soyDestino) {
                try {
                    byte[] encAesKey = Encriptador.hexToBytes(mensaje.getEncAesKeyHex());
                    byte[] aesKeyBytes = Encriptador.descifrarClaveAESConRSA(encAesKey, miClavePrivada);

                    byte[] iv = Encriptador.hexToBytes(mensaje.getIvHex());
                    byte[] cipher = Encriptador.hexToBytes(mensaje.getCiphertextHex());

                    PublicKey pubOrigen = clavesPublicas.get(mensaje.getOrigen());
                    if (pubOrigen == null) {
                        String pubHex = Encriptador.leerClavePublicaDesdeArchivoComoHex(mensaje.getOrigen());
                        if (pubHex != null) {
                            pubOrigen = Encriptador.publicKeyFromHex(pubHex);
                            clavesPublicas.put(mensaje.getOrigen(), pubOrigen);
                            System.out.println("[OK] Clave pública cargada para " + mensaje.getOrigen());
                        }
                    }

                    boolean firmaValida = false;
                    if (pubOrigen != null) {
                        try {
                            firmaValida = FirmaDigital.verificarFirma(cipher, mensaje.getSignatureHex(), pubOrigen);
                        } catch (Exception vf) {
                            System.err.println("[WARN] Error verificando firma: " + vf.getMessage());
                        }
                    }

                    byte[] plain = Encriptador.descifrarConAES(cipher, iv, aesKeyBytes);
                    String contenido = new String(plain, StandardCharsets.UTF_8);

                    System.out.println("Mensaje recibido en " + nombre + " desde " + mensaje.getOrigen());
                    System.out.println("  Contenido: " + contenido);
                    System.out.println("  Firma válida: " + firmaValida);
                    System.out.println("  Ruta: " + mensaje.getCamino());
                    System.out.println();
                    return;

                } catch (Exception e) {
                    System.err.println("[WARN] No pude procesar como destino (posible error descifrado/verificación). Detalle:");
                    e.printStackTrace();
                    // no return here: si queremos que se reenvíe si falla descifrar, se sigue
                }
            }

            // Reenvío a vecinos que no estén en el camino
            for (String vecino : vecinos) {
                if (!mensaje.getCamino().contains(vecino)) {
                    enviarMensaje(mensaje, vecino);
                } else {
                    System.out.println("[DEBUG] Omitiendo reenviar a " + vecino + " (ya en camino).");
                }
            }

        } catch (Exception e) {
            System.err.println("Error procesando mensaje (parseo/estructura): " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void enviarMensaje(Mensaje mensaje, String vecino) {
        String[] partes = vecino.split("_");
        if (partes.length < 2) {
            System.err.println("[ERROR] Vecino mal formado: " + vecino);
            return;
        }
        String ipVec = partes[0];
        int puertoVec;
        try {
            puertoVec = Integer.parseInt(partes[1]);
        } catch (NumberFormatException nfe) {
            System.err.println("[ERROR] Puerto mal formado en vecino: " + vecino);
            return;
        }

        try (Socket socket = new Socket(ipVec, puertoVec);
             PrintWriter out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true)) {
            out.println(mensaje.aTexto());
            out.flush();
            System.out.println("Reenviado mensaje desde " + nombre + " hacia " + vecino);
        } catch (IOException e) {
            System.err.println("Error enviando mensaje a " + vecino + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Intento de obtener la clave pública de un nodo y guardarla
    public boolean solicitarYGuardarClavePublica(String destino) {
        String[] partes = destino.split("_");
        if (partes.length < 2) {
            System.err.println("[ERROR] Destino mal formado: " + destino);
            return false;
        }
        String ipDest = partes[0];
        int puertoDest;
        try {
            puertoDest = Integer.parseInt(partes[1]);
        } catch (NumberFormatException nfe) {
            System.err.println("[ERROR] Puerto destino mal formado: " + destino);
            return false;
        }

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ipDest, puertoDest), 3000);
            PrintWriter out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

            out.println("GET_PUBKEY");
            String pubHex = in.readLine();
            if (pubHex == null || pubHex.trim().isEmpty()) {
                System.err.println("[ERROR] Respuesta vacía al pedir clave pública a " + destino);
                return false;
            }

            Encriptador.guardarClavePublicaEnArchivo(destino, pubHex);
            PublicKey pub = Encriptador.publicKeyFromHex(pubHex);
            clavesPublicas.put(destino, pub);
            System.out.println("[OK] Clave pública de " + destino + " obtenida y guardada.");
            return true;

        } catch (Exception e) {
            System.err.println("[ERROR] No se pudo obtener la clave pública de " + destino + ": " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public void enviarMensajeInicial(String destino, String contenido) {
        try {
            if (!clavesPublicas.containsKey(destino)) {
                boolean ok = solicitarYGuardarClavePublica(destino);
                if (!ok) {
                    System.err.println("No se pudo obtener clave pública de " + destino + ". Abortando envío.");
                    return;
                }
            }

            PublicKey pubDestino = clavesPublicas.get(destino);
            SecretKey aes = Encriptador.generarClaveAES();
            Encriptador.AesResultado ar = Encriptador.cifrarConAES(contenido.getBytes(StandardCharsets.UTF_8), aes);

            byte[] aesKeyCifrada = Encriptador.cifrarClaveAESConRSA(ar.clave, pubDestino);
            String signatureHex = FirmaDigital.firmar(ar.cipher, miClavePrivada);

            Mensaje m = new Mensaje(nombre, destino,
                    Encriptador.bytesToHex(aesKeyCifrada),
                    Encriptador.bytesToHex(ar.iv),
                    Encriptador.bytesToHex(ar.cipher),
                    signatureHex, nombre);

            // --- NUEVO: intentar enviar DIRECTO al destino primero ---
            try {
                System.out.println("[DEBUG] Intentando enviar DIRECTO a " + destino);
                enviarMensaje(m, destino);
            } catch (Exception e) {
                System.err.println("[WARN] Envío directo a " + destino + " falló: " + e.getMessage());
            }

            // Luego, también reenvío a vecinos para que lo enruten si corresponde
            for (String vecino : vecinos) {
                if (!m.getCamino().contains(vecino)) {
                    enviarMensaje(m, vecino);
                }
            }

        } catch (Exception e) {
            System.err.println("Error preparando/enviando mensaje inicial: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // MAIN dentro de la clase (igual que tu versión)
    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Uso: java PCNode <archivo_config> <ip_puerto>");
            return;
        }

        String archivo = args[0];
        String pcActual = args[1];
        String ip = pcActual.split("_")[0];
        int puerto = Integer.parseInt(pcActual.split("_")[1]);

        PCNode pc;
        try {
            pc = new PCNode(ip, puerto);
        } catch (Exception e) {
            System.err.println("Error creando nodo: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(archivo))) {
            String linea;
            while ((linea = br.readLine()) != null) {
                linea = linea.trim();
                if (linea.isEmpty() || linea.startsWith("#")) continue;
                String[] partes = linea.split(" ");
                String nodo = partes[0];

                String pubHex = Encriptador.leerClavePublicaDesdeArchivoComoHex(nodo);
                if (pubHex != null) {
                    try {
                        PublicKey pub = Encriptador.publicKeyFromHex(pubHex);
                        clavesPublicas.put(nodo, pub);
                    } catch (Exception ignored) {}
                } else {
                    System.out.println("[INFO] No había clave precargada para " + nodo);
                }

                if (nodo.equals(pcActual)) {
                    for (int i = 1; i < partes.length; i++) {
                        String vecino = partes[i];
                        String[] datos = vecino.split("_");
                        pc.agregarVecino(datos[0], Integer.parseInt(datos[1]));
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Error leyendo archivo: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        pc.iniciar();

        Scanner sc = new Scanner(System.in);
        while (true) {
            System.out.print("Destino (ip_puerto o 'exit')> ");
            String destino = sc.nextLine();
            if (destino.equalsIgnoreCase("exit")) {
                pc.activo = false;
                try { pc.server.close(); } catch (IOException ignored) {}
                break;
            }
            System.out.print("Mensaje> ");
            String contenido = sc.nextLine();
            pc.enviarMensajeInicial(destino, contenido);
        }
        sc.close();
    }
}
