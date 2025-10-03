import java.io.*;
import java.net.*;
import java.util.*;

public class PCNode {
    private String ip;
    private int puerto;
    private List<String> vecinos; // lista de "ip:puerto"
    private String nombre;

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
        // Hilo servidor que escucha mensajes
        new Thread(() -> {
            try (ServerSocket server = new ServerSocket(puerto)) {
                System.out.println("PC " + nombre + " escuchando en puerto " + puerto);
                while (true) {
                    Socket socket = server.accept();
                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    String mensaje = in.readLine();
                    socket.close();
                    procesarMensaje(mensaje);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();
    }

    private void procesarMensaje(String mensaje) {
        String[] partes = mensaje.split(";");
        String origen = partes[0];
        String destino = partes[1];
        String contenido = partes[2];
        String camino = partes[3];
        camino += " -> " + nombre;

        // Si es mensaje de desconexión
        if (contenido.equals("DESCONEXION")) {
            System.out.println("Nodo " + origen + " se ha desconectado. Notificado en " + nombre);
            return; // no reenviamos
        }

        if (nombre.equals(destino) || destino.equals("TODOS")) {
            System.out.println("Mensaje recibido en " + nombre + " desde " + origen +
                    "  Contenido: " + contenido);
            System.out.println("   Ruta seguida: " + camino + "\n");
        } else {
            for (String vecino : vecinos) {
                if (!camino.contains(vecino)) {
                    enviarMensaje(origen, destino, contenido, camino, vecino);
                }
            }
        }
    }


    public void enviarMensaje(String origen, String destino, String contenido, String camino, String vecino) {
        try {
            String[] partes = vecino.split(":");
            String ipVecino = partes[0];
            int puertoVecino = Integer.parseInt(partes[1]);
            Socket socket = new Socket(ipVecino, puertoVecino);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            String mensaje = origen + ";" + destino + ";" + contenido + ";" + camino;
            out.println(mensaje);
            socket.close();
            System.out.println(" Reenviado mensaje desde " + nombre + " hacia " + vecino);
        } catch (IOException e) {
            System.err.println(" Error enviando mensaje a " + vecino);
        }
    }

    // Enviar mensaje inicial a todos los vecinos
    public void enviarMensajeInicial(String destino, String contenido) {
        for (String vecino : vecinos) {
            enviarMensaje(nombre, destino, contenido, nombre, vecino);
        }
    }

    public static void main(String... args) {
        try {
            // Colocar Ip
            String ip = "172.16.4.233";
            // Puerto fijo (cambia según la compu)
            int puerto = 5000;
            PCNode pc = new PCNode(ip, puerto);

            // Agregar vecino (mnaulmente
            pc.agregarVecino("172.16.4.181", 5003);
            pc.agregarVecino("172.16.100.50", 5002);

            pc.iniciar();

            // Hilo interactivo para enviar mensajes
            Scanner sc = new Scanner(System.in);
            while (true) {
                try {
                    System.out.print("Destino (ip:puerto o 'exit' para salir)> ");
                    String destino = sc.nextLine();
                    if (destino.equalsIgnoreCase("exit")) {
                        System.out.println("Avisando vecinos que " + pc.nombre + " se desconecta...");
                        pc.enviarMensajeInicial("TODOS", "DESCONEXION");
                        break; // sale del while
                    }
                    System.out.print("Mensaje> ");
                    String mensaje = sc.nextLine();
                    pc.enviarMensajeInicial(destino, mensaje);
                } catch (Exception e) {
                    System.err.println("Error leyendo entrada: " + e.getMessage());
                }
            }
            sc.close();


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}