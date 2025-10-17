import java.io.*;
import java.net.*;
import java.util.*;

public class PCNode {
    private String ip;
    private int puerto;
    private List<String> vecinos;
    public String nombre;

    private ServerSocket server;
    private volatile boolean activo = true; // controla el hilo servidor

    public PCNode(String ip, int puerto) {
        this.ip = ip;
        this.puerto = puerto;
        this.vecinos = new ArrayList<>();
        this.nombre = ip + ":" + puerto;
    }

    public void agregarVecino(String ip, int puerto) {
        vecinos.add(ip + ":" + puerto);
    }

    public void iniciar() {
        new Thread(() -> {
            try {
                server = new ServerSocket(puerto);
                System.out.println("PC " + nombre + " escuchando en puerto " + puerto);

                while (activo) {
                    try {
                        Socket socket = server.accept();
                        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                        String texto = in.readLine();
                        socket.close();
                        procesarMensaje(texto);
                    } catch (SocketException se) {
                        if (!activo) break; // salió porque cerramos el ServerSocket
                    }
                }

            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                System.out.println("Servidor de " + nombre + " detenido.");
            }
        }).start();
    }

    private void procesarMensaje(String texto) {
        try {
            Mensaje mensaje = Mensaje.crearMensajeDesdeTexto(texto);
            mensaje.agregarAlCamino(nombre);

            if (mensaje.getContenido().equals("DESCONEXION")) {
                System.out.println("Nodo " + mensaje.getOrigen() + " se ha desconectado. Notificado en " + nombre);
                return;
            }

            if (nombre.equals(mensaje.getDestino()) || mensaje.getDestino().equals("TODOS")) {
                System.out.println("Mensaje recibido en " + nombre + " desde " + mensaje.getOrigen() +
                        "  Contenido: " + mensaje.getContenido());
                System.out.println("   Ruta seguida: " + mensaje.getCamino() + "\n");
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
        try {
            String[] partes = vecino.split(":");
            String ipVecino = partes[0];
            int puertoVecino = Integer.parseInt(partes[1]);
            Socket socket = new Socket(ipVecino, puertoVecino);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            out.println(mensaje.pasarMensajeATexto());
            socket.close();
            System.out.println(" Reenviado mensaje desde " + nombre + " hacia " + vecino);
        } catch (IOException e) {
            System.err.println(" Error enviando mensaje a " + vecino);
        }
    }

    public void enviarMensajeInicial(String destino, String contenido) {
        Mensaje mensaje = new Mensaje(nombre, destino, contenido, nombre);
        for (String vecino : vecinos) {
            enviarMensaje(mensaje, vecino);
        }
    }

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

        // Leer archivo de red
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
                    break;
                }
            }
        } catch (IOException e) {
            System.err.println("Error leyendo archivo: " + e.getMessage());
            return;
        }

        // Inicia el nodo
        pc.iniciar();

        // Consola interactiva
        Scanner sc = new Scanner(System.in);
        while (true) {
            try {
                System.out.print("Destino (ip:puerto o 'exit' para salir)> ");
                String destino = sc.nextLine();
                if (destino.equalsIgnoreCase("exit")) {
                    System.out.println("Avisando vecinos que " + pc.nombre + " se desconecta...");
                    pc.enviarMensajeInicial("TODOS", "DESCONEXION");

                    // Cerrar el servidor y salir
                    pc.activo = false;
                    if (pc.server != null && !pc.server.isClosed()) {
                        try {
                            pc.server.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                    break;
                }
                System.out.print("Mensaje> ");
                String mensaje = sc.nextLine();
                pc.enviarMensajeInicial(destino, mensaje);
            } catch (Exception e) {
                System.err.println("Error leyendo entrada: " + e.getMessage());
            }
        }
        sc.close();
    }
}
