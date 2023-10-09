package edu.umg.domain;

import edu.umg.datos.Conexion;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
public class DAO {
    private static final String SQL_INSERT = "INSERT INTO usuario(username, password) VALUES(?, ?)";
    private static final String SQL_SELECT_BY_USER_PASS = "SELECT * FROM usuario WHERE nombre_usuario = ? AND contraseña = ?";

    private Connection conexionTransaccional;

    public DAO() {
    }

    public DAO(Connection conexionTransaccional) {
        this.conexionTransaccional = conexionTransaccional;
    }

    public boolean insert(DTO usuario) throws SQLException {
        Connection conn = null;
        PreparedStatement stmt = null;

        try {
            conn = this.conexionTransaccional != null ? this.conexionTransaccional : Conexion.getConnection();
            stmt = conn.prepareStatement(SQL_INSERT);
            stmt.setString(1, usuario.getNombreUsuario());
            stmt.setString(2, encriptarContraseña(usuario.getContraseña()));

            int rows = stmt.executeUpdate();
            return rows > 0;
        } finally {
            Conexion.close(stmt);
            if (this.conexionTransaccional == null) {
                Conexion.close(conn);
            }
        }
    }

    public boolean validarUsuario(String username, String password) throws SQLException {
        Connection conn = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        boolean usuarioValido = false;

        try {
            conn = Conexion.getConnection();
            String SQL_SELECT = "SELECT * FROM usuario WHERE username = ? AND password = ?";
            stmt = conn.prepareStatement(SQL_SELECT);
            stmt.setString(1, username);
            stmt.setString(2, password);
            rs = stmt.executeQuery();

            // Si se encuentra un usuario con las credenciales proporcionadas, es válido
            usuarioValido = rs.next();
        } finally {
            Conexion.close(rs);
            Conexion.close(stmt);
            if (conn != null) {
                conn.close();
            }
        }

        return usuarioValido;
    }

    // Función para encriptar la contraseña (puedes usar otra función más segura)
    private String encriptarContraseña(String contraseña) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(contraseña.getBytes());
            StringBuilder hexString = new StringBuilder();
            if (contraseña == null) {
                throw new IllegalArgumentException("La contraseña no puede ser null");
            }
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error al encriptar la contraseña.", e);
        }
    }

}
