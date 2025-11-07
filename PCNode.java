import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class PCNode {
    private String ip;
    private int puerto;
    private List<String> vecinos;
    public String nombre;

    private PublicKey clavePublica;
    private PrivateKey clavePrivada;
    private static Map<String, PublicKey> clavesPublicas = new HashMap<>();

    private ServerSocket servidor;
    private volatile boolean activo = true;

    public PCNode(String ip, int puerto) {
        this.ip = ip;
        this.puerto = puerto;
        this.vecinos = new ArrayList<>();
        this.nombre = ip + ":" + puerto;
        try {
            KeyPair parRSA = Encriptador.generarParRSA();
            this.clavePublica = parRSA.getPublic();
            this.clavePrivada = parRSA.getPrivate();
            clavesPublicas.put(nombre, clavePublica);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void agregarVecino(String ip, int puerto) {
        vecinos.add(ip + ":" + puerto);
    }

    public void iniciar() {
        new Thread(() -> {
            try {
                servidor = new ServerSocket(puerto);
                System.out.println("PC " + nombre + " escuchando en puerto " + puerto);

                while (activo) {
                    try (Socket socket = servidor.accept()) {
                        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                        String texto = in.readLine();
                        procesarMensaje(texto);
                    } catch (SocketException se) {
                        if (!activo) break;
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();
    }

    private void procesarMensaje(String texto) {
        try {
            Mensaje mensaje = Mensaje.desdeTexto(texto);
            mensaje.agregarAlCamino(nombre);

            // Obtener clave pública del origen
            PublicKey clavePublicaOrigen = clavesPublicas.get(mensaje.getOrigen());
            if (clavePublicaOrigen == null) {
                System.err.println("No se conoce la clave pública de " + mensaje.getOrigen());
                return;
            }

            // Descifrar la clave AES con mi clave privada
            byte[] claveAESBytes = Encriptador.descifrarRSA(mensaje.getClaveCifrada(), clavePrivada);
            SecretKey claveAES = new SecretKeySpec(claveAESBytes, "AES");

            // Descifrar contenido
            String contenido = Encriptador.descifrarAES(mensaje.getContenidoCifrado(), claveAES);

            // Verificar firma
            boolean firmaValida = FirmaDigital.verificarFirma(contenido, mensaje.getFirma(), clavePublicaOrigen);

            if (nombre.equals(mensaje.getDestino()) || mensaje.getDestino().equals("TODOS")) {
                System.out.println("📩 Mensaje recibido en " + nombre);
                System.out.println("   Desde: " + mensaje.getOrigen());
                System.out.println("   Contenido: " + contenido);
                System.out.println("   Firma válida: " + firmaValida);
                System.out.println("   Ruta: " + mensaje.getCamino() + "\n");
            } else {
                for (String vecino : vecinos) {
                    if (!mensaje.getCamino().contains(vecino)) {
                        enviarMensaje(mensaje, vecino);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error procesando mensaje: " + e.getMessage());
        }
    }

    public void enviarMensaje(Mensaje mensaje, String vecino) {
        try (Socket socket = new Socket(vecino.split(":")[0], Integer.parseInt(vecino.split(":")[1]));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
            out.println(mensaje.aTexto());
            System.out.println("📤 Mensaje reenviado desde " + nombre + " hacia " + vecino);
        } catch (IOException e) {
            System.err.println("Error enviando mensaje a " + vecino);
        }
    }

    public void enviarMensajeInicial(String destino, String contenido) {
        try {
            PublicKey clavePublicaDestino = clavesPublicas.get(destino);
            if (clavePublicaDestino == null) {
                System.err.println("No se conoce la clave pública del destino " + destino);
                return;
            }

            // 1️⃣ Generar clave AES
            SecretKey claveAES = Encriptador.generarClaveAES();

            // 2️⃣ Cifrar contenido con AES
            String contenidoCifrado = Encriptador.cifrarAES(contenido, claveAES);

            // 3️⃣ Cifrar la clave AES con RSA del destino
            String claveCifrada = Encriptador.cifrarRSA(claveAES.getEncoded(), clavePublicaDestino);

            // 4️⃣ Firmar el mensaje
            String firma = FirmaDigital.firmar(contenido, clavePrivada);

            // 5️⃣ Crear y enviar mensaje
            Mensaje mensaje = new Mensaje(nombre, destino, contenidoCifrado, claveCifrada, firma, nombre);
            for (String vecino : vecinos) {
                enviarMensaje(mensaje, vecino);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // --- MAIN ---
    public static void main(String... args) {
        if (args.length < 2) {
            System.err.println("Uso: java PCNode <archivo_config> <ip:puerto>");
            return;
        }

        String rutaArchivo = args[0];
        String pcActual = args[1];
        String ip = pcActual.split(":")[0];
        int puerto = Integer.parseInt(pcActual.split(":")[1]);

        PCNode pc = new PCNode(ip, puerto);

        try (BufferedReader br = new BufferedReader(new FileReader(rutaArchivo))) {
            String linea;
            while ((linea = br.readLine()) != null) {
                linea = linea.trim();
                if (linea.isEmpty() || linea.startsWith("#")) continue;
                String[] partes = linea.split(" ");
                String nodo = partes[0];
                if (nodo.equals(pcActual)) {
                    for (int i = 1; i < partes.length; i++) {
                        String vecino = partes[i];
                        String[] datosVecino = vecino.split(":");
                        pc.agregarVecino(datosVecino[0], Integer.parseInt(datosVecino[1]));
                    }
                }
                // registrar claves públicas de todos los nodos (simulado)
                PCNode.clavesPublicas.put(nodo, pc.clavePublica);
            }
        } catch (IOException e) {
            System.err.println("Error leyendo archivo: " + e.getMessage());
            return;
        }

        pc.iniciar();

        Scanner sc = new Scanner(System.in);
        while (true) {
            System.out.print("Destino (ip:puerto o 'exit')> ");
            String destino = sc.nextLine();
            if (destino.equalsIgnoreCase("exit")) {
                pc.activo = false;
                try { pc.servidor.close(); } catch (IOException ignored) {}
                break;
            }
            System.out.print("Mensaje> ");
            String contenido = sc.nextLine();
            pc.enviarMensajeInicial(destino, contenido);
        }
    }
}
