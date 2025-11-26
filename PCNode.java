import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

public class PCNode {

    // ============================
    //        ATRIBUTOS
    // ============================

    private final String ip;
    private final int puerto;
    private final String nombre;
    private final List<String> vecinos = new ArrayList<>();

    private ServerSocket server;
    volatile boolean activo = true;

    private final PublicKey miClavePublica;
    private final PrivateKey miClavePrivada;

    private static final ConcurrentMap<String, PublicKey> clavesPublicas = new ConcurrentHashMap<>();


    // ============================
    //       CONSTRUCTOR
    // ============================

    public PCNode(String ip, int puerto) throws Exception {
        this.ip = ip;
        this.puerto = puerto;
        this.nombre = ip + "_" + puerto;

        KeyPair kp = generarParDeClaves();
        miClavePublica  = kp.getPublic();
        miClavePrivada = kp.getPrivate();

        guardarMiClavePublica();

        System.out.println("Nodo " + nombre + " iniciado.");
    }


    // ============================
    //     CARGA DE CONFIGURACIÓN
    // ============================

    public void cargarConfiguracion(String archivoConfig, String pcActual) {
        try (BufferedReader br = new BufferedReader(new FileReader(archivoConfig))) {
            String linea;

            while ((linea = br.readLine()) != null) {
                linea = linea.trim();

                if (linea.isEmpty() || linea.startsWith("#"))
                    continue;

                procesarLineaConfig(linea, pcActual);
            }

        } catch (Exception e) {
            System.err.println("Error leyendo archivo de config: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void procesarLineaConfig(String linea, String pcActual) {
        String[] partes = linea.split(" ");
        String nodo = partes[0];

        cargarClaveSiExiste(nodo);

        if (nodo.equals(pcActual))
            cargarVecinos(partes);
    }

    private void cargarClaveSiExiste(String nodo) {
        try {
            String pubHex = Encriptador.leerClavePublicaDesdeArchivoComoHex(nodo);
            if (pubHex != null) {
                PublicKey pub = Encriptador.publicKeyFromHex(pubHex);
                clavesPublicas.put(nodo, pub);
            } else {
                System.out.println("[INFO] No había clave precargada para " + nodo);
            }
        } catch (Exception ignored) {}
    }

    public void agregarVecino(String vecino) {
        if (vecino == null) {
            System.err.println("[ERROR] agregarVecino: valor nulo");
            return;
        }

        String v = vecino.trim();
        if (v.isEmpty()) {
            System.err.println("[ERROR] agregarVecino: cadena vacía");
            return;
        }

        String[] partes = v.split("_");
        if (partes.length != 2) {
            System.err.println("[ERROR] agregarVecino: formato incorrecto (se esperaba ip_puerto). Recibido: " + vecino);
            return;
        }

        String ip = partes[0].trim();
        String puertoStr = partes[1].trim();

        int puerto;
        try {
            puerto = Integer.parseInt(puertoStr);
        } catch (NumberFormatException e) {
            System.err.println("[ERROR] agregarVecino: puerto inválido en: " + vecino);
            return;
        }

        String id = ip + "_" + puerto;
    }


    private void cargarVecinos(String[] partes) {
        for (int i = 1; i < partes.length; i++) {
            agregarVecino(partes[i]);
        }
    }


    // ============================
    //        RED Y SERVIDOR
    // ============================

    public void iniciarServidor() {
        new Thread(() -> {
            try {
                server = new ServerSocket(puerto);
                System.out.println("PC " + nombre + " escuchando en puerto " + puerto);

                while (activo)
                    aceptarConexion();

            } catch (IOException e) {
                System.err.println("Error en servidor: " + e.getMessage());
                e.printStackTrace();
            }
        }).start();
    }

    private void aceptarConexion() {
        try (Socket socket = server.accept()) {
            manejarConexion(socket);

        } catch (SocketException se) {
            if (!activo) return;

        } catch (Exception e) {
            System.err.println("Error manejando conexión: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void manejarConexion(Socket socket) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        PrintWriter out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);

        String linea = in.readLine();
        if (linea == null) return;

        if (linea.equals("GET_PUBKEY")) {
            responderClavePublica(out);
            return;
        }

        procesarMensajeEntrante(linea);
    }

    private void responderClavePublica(PrintWriter out) {
        out.println(Encriptador.publicKeyToHex(miClavePublica));
    }


    // ============================
    //      PROCESAR MENSAJES
    // ============================

    private void procesarMensajeEntrante(String texto) {
        try {
            Mensaje mensaje = Mensaje.desdeTexto(texto);
            mensaje.agregarAlCamino(nombre);

            if (esDestino(mensaje))
                procesarComoDestino(mensaje);
            else
                reenviarMensaje(mensaje);

        } catch (Exception e) {
            System.err.println("Error procesando mensaje: " + e.getMessage());
        }
    }

    private boolean esDestino(Mensaje m) {
        return m.getDestino().equals(nombre) || m.getDestino().equals("TODOS");
    }

    private void procesarComoDestino(Mensaje m) {
        try {
            byte[] aesKey = descifrarClaveAES(m);
            byte[] plain = descifrarContenidoAES(m, aesKey);
            boolean firmaCorrecta = verificarFirma(m);

            System.out.println("Mensaje recibido en " + nombre);
            System.out.println("Contenido: " + new String(plain, StandardCharsets.UTF_8));
            System.out.println("Firma válida: " + firmaCorrecta);
            System.out.println("Ruta: " + m.getCamino() + "\n");

        } catch (Exception e) {
            System.err.println("[WARN] Error procesando como destino:");
            e.printStackTrace();
        }
    }

    private byte[] descifrarClaveAES(Mensaje m) throws Exception {
        byte[] encAes = Encriptador.hexToBytes(m.getEncAesKeyHex());
        return Encriptador.descifrarClaveAESConRSA(encAes, miClavePrivada);
    }

    private byte[] descifrarContenidoAES(Mensaje m, byte[] aesKey) throws Exception {
        byte[] iv = Encriptador.hexToBytes(m.getIvHex());
        byte[] cipher = Encriptador.hexToBytes(m.getCiphertextHex());
        return Encriptador.descifrarConAES(cipher, iv, aesKey);
    }

    private boolean verificarFirma(Mensaje m) {
        try {
            PublicKey pub = obtenerClaveOrigen(m.getOrigen());
            if (pub == null) return false;

            return FirmaDigital.verificarFirma(
                    Encriptador.hexToBytes(m.getCiphertextHex()),
                    m.getSignatureHex(),
                    pub
            );

        } catch (Exception e) {
            return false;
        }
    }

    private PublicKey obtenerClaveOrigen(String origen) {
        PublicKey pub = clavesPublicas.get(origen);
        if (pub != null) return pub;

        try {
            String hex = Encriptador.leerClavePublicaDesdeArchivoComoHex(origen);
            if (hex != null) {
                pub = Encriptador.publicKeyFromHex(hex);
                clavesPublicas.put(origen, pub);
                return pub;
            }
        } catch (Exception ignored) {}

        return null;
    }


    // ============================
    //         ENVÍO MENSAJES
    // ============================

    public void enviarMensajeInicial(String destino, String contenido) {
        try {
            PublicKey claveDestino = obtenerClavePublica(destino);
            if (claveDestino == null) {
                System.err.println("No se pudo obtener clave de destino.");
                return;
            }

            Mensaje mensaje = construirMensaje(destino, contenido, claveDestino);

            enviarDirecto(destino, mensaje);
            reenviarMensaje(mensaje);

        } catch (Exception e) {
            System.err.println("Error enviando mensaje inicial: " + e.getMessage());
        }
    }

    private PublicKey obtenerClavePublica(String destino) {
        if (clavesPublicas.containsKey(destino))
            return clavesPublicas.get(destino);

        solicitarYGuardarClavePublica(destino);
        return clavesPublicas.get(destino);
    }

    private Mensaje construirMensaje(String destino, String contenido, PublicKey pubDestino) throws Exception {
        SecretKey aes = Encriptador.generarClaveAES();

        Encriptador.AesResultado ar = Encriptador.cifrarConAES(
                contenido.getBytes(StandardCharsets.UTF_8),
                aes
        );

        return new Mensaje(
                nombre,
                destino,
                Encriptador.bytesToHex(Encriptador.cifrarClaveAESConRSA(ar.clave, pubDestino)),
                Encriptador.bytesToHex(ar.iv),
                Encriptador.bytesToHex(ar.cipher),
                FirmaDigital.firmar(ar.cipher, miClavePrivada),
                nombre
        );
    }

    private void enviarDirecto(String destino, Mensaje m) {
        try {
            enviarMensaje(m, destino);
        } catch (Exception ignored) {}
    }

    private void reenviarMensaje(Mensaje m) {
        for (String vecino : vecinos)
            if (!m.getCamino().contains(vecino))
                enviarMensaje(m, vecino);
    }

    private void enviarMensaje(Mensaje m, String vecino) {
        try {
            String[] datos = vecino.split("_");
            Socket socket = new Socket(datos[0], Integer.parseInt(datos[1]));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            out.println(m.aTexto());
            socket.close();
        } catch (Exception e) {
            System.err.println("Error enviando a " + vecino + ": " + e.getMessage());
        }
    }


    // ============================
    //        CLAVES PÚBLICAS
    // ============================

    private void guardarMiClavePublica() throws IOException {
        Encriptador.guardarClavePublicaEnArchivo(nombre,
                Encriptador.publicKeyToHex(miClavePublica));
    }

    private KeyPair generarParDeClaves() throws Exception {
        return KeyPairGenerator.getInstance("RSA").generateKeyPair();
    }

    public boolean solicitarYGuardarClavePublica(String destino) {
        try {
            String[] partes = destino.split("_");
            String ipDest = partes[0];
            int puertoDest = Integer.parseInt(partes[1]);

            Socket socket = new Socket(ipDest, puertoDest);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            out.println("GET_PUBKEY");
            String pubHex = in.readLine();

            if (pubHex == null) return false;

            PublicKey pub = Encriptador.publicKeyFromHex(pubHex);
            clavesPublicas.put(destino, pub);
            Encriptador.guardarClavePublicaEnArchivo(destino, pubHex);
            socket.close();
            return true;

        } catch (Exception e) {
            System.err.println("Error solicitando clave: " + e.getMessage());
            return false;
        }
    }


    // ============================
    //             MAIN
    // ============================

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Uso: java PCNode <archivo_config> <ip_puerto>");
            return;
        }

        String archivo = args[0];
        String actual = args[1];

        try {
            String[] datos = actual.split("_");
            PCNode pc = new PCNode(datos[0], Integer.parseInt(datos[1]));

            pc.cargarConfiguracion(archivo, actual);
            pc.iniciarServidor();

            Scanner sc = new Scanner(System.in);
            while (true) {
                System.out.print("Destino> ");
                String destino = sc.nextLine();
                if (destino.equalsIgnoreCase("exit")) break;

                System.out.print("Mensaje> ");
                pc.enviarMensajeInicial(destino, sc.nextLine());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

public class PCNode {

    // ============================
    //        ATRIBUTOS
    // ============================

    private final String ip;
    private final int puerto;
    private final String nombre;
    private final List<String> vecinos = new ArrayList<>();

    private ServerSocket server;
    volatile boolean activo = true;

    private final PublicKey miClavePublica;
    private final PrivateKey miClavePrivada;

    private static final ConcurrentMap<String, PublicKey> clavesPublicas = new ConcurrentHashMap<>();


    // ============================
    //       CONSTRUCTOR
    // ============================

    public PCNode(String ip, int puerto) throws Exception {
        this.ip = ip;
        this.puerto = puerto;
        this.nombre = ip + "_" + puerto;

        KeyPair kp = generarParDeClaves();
        miClavePublica  = kp.getPublic();
        miClavePrivada = kp.getPrivate();

        guardarMiClavePublica();

        System.out.println("Nodo " + nombre + " iniciado.");
    }


    // ============================
    //     CARGA DE CONFIGURACIÓN
    // ============================

    public void cargarConfiguracion(String archivoConfig, String pcActual) {
        try (BufferedReader br = new BufferedReader(new FileReader(archivoConfig))) {
            String linea;

            while ((linea = br.readLine()) != null) {
                linea = linea.trim();

                if (linea.isEmpty() || linea.startsWith("#"))
                    continue;

                procesarLineaConfig(linea, pcActual);
            }

        } catch (Exception e) {
            System.err.println("Error leyendo archivo de config: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void procesarLineaConfig(String linea, String pcActual) {
        String[] partes = linea.split(" ");
        String nodo = partes[0];

        cargarClaveSiExiste(nodo);

        if (nodo.equals(pcActual))
            cargarVecinos(partes);
    }

    private void cargarClaveSiExiste(String nodo) {
        try {
            String pubHex = Encriptador.leerClavePublicaDesdeArchivoComoHex(nodo);
            if (pubHex != null) {
                PublicKey pub = Encriptador.publicKeyFromHex(pubHex);
                clavesPublicas.put(nodo, pub);
            } else {
                System.out.println("[INFO] No había clave precargada para " + nodo);
            }
        } catch (Exception ignored) {}
    }

    public void agregarVecino(String vecino) {
        if (vecino == null) {
            System.err.println("[ERROR] agregarVecino: valor nulo");
            return;
        }

        String v = vecino.trim();
        if (v.isEmpty()) {
            System.err.println("[ERROR] agregarVecino: cadena vacía");
            return;
        }

        String[] partes = v.split("_");
        if (partes.length != 2) {
            System.err.println("[ERROR] agregarVecino: formato incorrecto (se esperaba ip_puerto). Recibido: " + vecino);
            return;
        }

        String ip = partes[0].trim();
        String puertoStr = partes[1].trim();

        int puerto;
        try {
            puerto = Integer.parseInt(puertoStr);
        } catch (NumberFormatException e) {
            System.err.println("[ERROR] agregarVecino: puerto inválido en: " + vecino);
            return;
        }

        String id = ip + "_" + puerto;
    }


    private void cargarVecinos(String[] partes) {
        for (int i = 1; i < partes.length; i++) {
            agregarVecino(partes[i]);
        }
    }


    // ============================
    //        RED Y SERVIDOR
    // ============================

    public void iniciarServidor() {
        new Thread(() -> {
            try {
                server = new ServerSocket(puerto);
                System.out.println("PC " + nombre + " escuchando en puerto " + puerto);

                while (activo)
                    aceptarConexion();

            } catch (IOException e) {
                System.err.println("Error en servidor: " + e.getMessage());
                e.printStackTrace();
            }
        }).start();
    }

    private void aceptarConexion() {
        try (Socket socket = server.accept()) {
            manejarConexion(socket);

        } catch (SocketException se) {
            if (!activo) return;

        } catch (Exception e) {
            System.err.println("Error manejando conexión: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void manejarConexion(Socket socket) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        PrintWriter out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);

        String linea = in.readLine();
        if (linea == null) return;

        if (linea.equals("GET_PUBKEY")) {
            responderClavePublica(out);
            return;
        }

        procesarMensajeEntrante(linea);
    }

    private void responderClavePublica(PrintWriter out) {
        out.println(Encriptador.publicKeyToHex(miClavePublica));
    }


    // ============================
    //      PROCESAR MENSAJES
    // ============================

    private void procesarMensajeEntrante(String texto) {
        try {
            Mensaje mensaje = Mensaje.desdeTexto(texto);
            mensaje.agregarAlCamino(nombre);

            if (esDestino(mensaje))
                procesarComoDestino(mensaje);
            else
                reenviarMensaje(mensaje);

        } catch (Exception e) {
            System.err.println("Error procesando mensaje: " + e.getMessage());
        }
    }

    private boolean esDestino(Mensaje m) {
        return m.getDestino().equals(nombre) || m.getDestino().equals("TODOS");
    }

    private void procesarComoDestino(Mensaje m) {
        try {
            byte[] aesKey = descifrarClaveAES(m);
            byte[] plain = descifrarContenidoAES(m, aesKey);
            boolean firmaCorrecta = verificarFirma(m);

            System.out.println("Mensaje recibido en " + nombre);
            System.out.println("Contenido: " + new String(plain, StandardCharsets.UTF_8));
            System.out.println("Firma válida: " + firmaCorrecta);
            System.out.println("Ruta: " + m.getCamino() + "\n");

        } catch (Exception e) {
            System.err.println("[WARN] Error procesando como destino:");
            e.printStackTrace();
        }
    }

    private byte[] descifrarClaveAES(Mensaje m) throws Exception {
        byte[] encAes = Encriptador.hexToBytes(m.getEncAesKeyHex());
        return Encriptador.descifrarClaveAESConRSA(encAes, miClavePrivada);
    }

    private byte[] descifrarContenidoAES(Mensaje m, byte[] aesKey) throws Exception {
        byte[] iv = Encriptador.hexToBytes(m.getIvHex());
        byte[] cipher = Encriptador.hexToBytes(m.getCiphertextHex());
        return Encriptador.descifrarConAES(cipher, iv, aesKey);
    }

    private boolean verificarFirma(Mensaje m) {
        try {
            PublicKey pub = obtenerClaveOrigen(m.getOrigen());
            if (pub == null) return false;

            return FirmaDigital.verificarFirma(
                    Encriptador.hexToBytes(m.getCiphertextHex()),
                    m.getSignatureHex(),
                    pub
            );

        } catch (Exception e) {
            return false;
        }
    }

    private PublicKey obtenerClaveOrigen(String origen) {
        PublicKey pub = clavesPublicas.get(origen);
        if (pub != null) return pub;

        try {
            String hex = Encriptador.leerClavePublicaDesdeArchivoComoHex(origen);
            if (hex != null) {
                pub = Encriptador.publicKeyFromHex(hex);
                clavesPublicas.put(origen, pub);
                return pub;
            }
        } catch (Exception ignored) {}

        return null;
    }


    // ============================
    //         ENVÍO MENSAJES
    // ============================

    public void enviarMensajeInicial(String destino, String contenido) {
        try {
            PublicKey claveDestino = obtenerClavePublica(destino);
            if (claveDestino == null) {
                System.err.println("No se pudo obtener clave de destino.");
                return;
            }

            Mensaje mensaje = construirMensaje(destino, contenido, claveDestino);

            enviarDirecto(destino, mensaje);
            reenviarMensaje(mensaje);

        } catch (Exception e) {
            System.err.println("Error enviando mensaje inicial: " + e.getMessage());
        }
    }

    private PublicKey obtenerClavePublica(String destino) {
        if (clavesPublicas.containsKey(destino))
            return clavesPublicas.get(destino);

        solicitarYGuardarClavePublica(destino);
        return clavesPublicas.get(destino);
    }

    private Mensaje construirMensaje(String destino, String contenido, PublicKey pubDestino) throws Exception {
        SecretKey aes = Encriptador.generarClaveAES();

        Encriptador.AesResultado ar = Encriptador.cifrarConAES(
                contenido.getBytes(StandardCharsets.UTF_8),
                aes
        );

        return new Mensaje(
                nombre,
                destino,
                Encriptador.bytesToHex(Encriptador.cifrarClaveAESConRSA(ar.clave, pubDestino)),
                Encriptador.bytesToHex(ar.iv),
                Encriptador.bytesToHex(ar.cipher),
                FirmaDigital.firmar(ar.cipher, miClavePrivada),
                nombre
        );
    }

    private void enviarDirecto(String destino, Mensaje m) {
        try {
            enviarMensaje(m, destino);
        } catch (Exception ignored) {}
    }

    private void reenviarMensaje(Mensaje m) {
        for (String vecino : vecinos)
            if (!m.getCamino().contains(vecino))
                enviarMensaje(m, vecino);
    }

    private void enviarMensaje(Mensaje m, String vecino) {
        try {
            String[] datos = vecino.split("_");
            Socket socket = new Socket(datos[0], Integer.parseInt(datos[1]));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            out.println(m.aTexto());
            socket.close();
        } catch (Exception e) {
            System.err.println("Error enviando a " + vecino + ": " + e.getMessage());
        }
    }


    // ============================
    //        CLAVES PÚBLICAS
    // ============================

    private void guardarMiClavePublica() throws IOException {
        Encriptador.guardarClavePublicaEnArchivo(nombre,
                Encriptador.publicKeyToHex(miClavePublica));
    }

    private KeyPair generarParDeClaves() throws Exception {
        return KeyPairGenerator.getInstance("RSA").generateKeyPair();
    }

    public boolean solicitarYGuardarClavePublica(String destino) {
        try {
            String[] partes = destino.split("_");
            String ipDest = partes[0];
            int puertoDest = Integer.parseInt(partes[1]);

            Socket socket = new Socket(ipDest, puertoDest);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            out.println("GET_PUBKEY");
            String pubHex = in.readLine();

            if (pubHex == null) return false;

            PublicKey pub = Encriptador.publicKeyFromHex(pubHex);
            clavesPublicas.put(destino, pub);
            Encriptador.guardarClavePublicaEnArchivo(destino, pubHex);
            socket.close();
            return true;

        } catch (Exception e) {
            System.err.println("Error solicitando clave: " + e.getMessage());
            return false;
        }
    }


    // ============================
    //             MAIN
    // ============================

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Uso: java PCNode <archivo_config> <ip_puerto>");
            return;
        }

        String archivo = args[0];
        String actual = args[1];

        try {
            String[] datos = actual.split("_");
            PCNode pc = new PCNode(datos[0], Integer.parseInt(datos[1]));

            pc.cargarConfiguracion(archivo, actual);
            pc.iniciarServidor();

            Scanner sc = new Scanner(System.in);
            while (true) {
                System.out.print("Destino> ");
                String destino = sc.nextLine();
                if (destino.equalsIgnoreCase("exit")) break;

                System.out.print("Mensaje> ");
                pc.enviarMensajeInicial(destino, sc.nextLine());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
