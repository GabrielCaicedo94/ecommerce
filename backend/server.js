require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const jwt = require("jsonwebtoken"); 
const bcrypt = require("bcryptjs"); 
const JWT_SECRET_CLIENTE = process.env.JWT_SECRET_CLIENTE || 'tu_secreto_cliente_seguro';

const app = express();
const PORT = process.env.PORT || 3000;

// ------------------------------------------------------------------
// MIDDLEWARE Y CONFIGURACIÓN (JWT)
// ------------------------------------------------------------------

// 1. CORS: Configuración para desarrollo
const allowedOrigins = ['http://localhost:5500', 'http://127.0.0.1:5500'];
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: false 
}));

// 2. JSON Parser
app.use(express.json()); 

// Conexión MySQL
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD, 
    database: process.env.DB_DATABASE
});

// Middleware para verificar el Token JWT
function requireAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ mensaje: "Acceso no autorizado. Token no proporcionado." });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        if (decoded.isAdmin) {
            next(); 
        } else {
            res.status(403).json({ mensaje: "Acceso denegado. Permisos insuficientes." });
        }
    } catch (err) {
        return res.status(401).json({ mensaje: "Acceso no autorizado. Token inválido o expirado." });
    }
}

// ------------------------------------------------------------------
// RUTAS DE AUTENTICACIÓN (JWT)
// ------------------------------------------------------------------

// RUTA LOGIN: Compara el hash y devuelve un token JWT real
app.post("/login", async (req, res) => {
    const { clave } = req.body;
    const hashToCompare = process.env.ADMIN_HASH; 

    if (!hashToCompare || !process.env.JWT_SECRET) {
        return res.status(500).json({ mensaje: "Error de configuración: Clave secreta o Hash no disponible." });
    }

    const match = await bcrypt.compare(clave, hashToCompare);

    if (match) {
        const token = jwt.sign({ isAdmin: true }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
        res.json({ success: true, mensaje: "Inicio de sesión exitoso.", token: token });
    } else {
        res.status(401).json({ success: false, mensaje: "Clave de administrador incorrecta." });
    }
});

// RUTA LOGOUT (El token se borra del cliente)
app.post("/logout", (req, res) => {
    res.json({ success: true, mensaje: "Sesión cerrada correctamente." });
});

// REGISTRO DE CLIENTES
app.post("/registro", async (req, res) => {
    const { nombres, apellidos, nombre_usuario, clave, celular, email, fecha_nacimiento } = req.body;

    // Validación básica de campos vacíos
    if (!nombres || !apellidos || !nombre_usuario || !clave || !email) {
        return res.status(400).json({ mensaje: "Todos los campos obligatorios deben estar llenos." });
    }

    try {
        // Encriptar la clave
        const clave_hashed = await bcrypt.hash(clave, 10);
        
        const sql = `
            INSERT INTO clientes (nombres, apellidos, nombre_usuario, clave_hashed, celular, email, fecha_nacimiento) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        db.query(sql, [nombres, apellidos, nombre_usuario, clave_hashed, celular, email, fecha_nacimiento], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ mensaje: "Nombre de usuario o Email ya registrado." });
                }
                console.error("Error al registrar cliente:", err);
                return res.status(500).json({ mensaje: "Error interno del servidor." });
            }
            res.status(201).json({ mensaje: "Registro exitoso. Ya puedes iniciar sesión." });
        });

    } catch (error) {
        console.error("Error de hash:", error);
        res.status(500).json({ mensaje: "Error interno del servidor." });
    }
});


// INICIO DE SESIÓN DE CLIENTES
app.post("/login-cliente", (req, res) => {
    const { nombre_usuario, clave } = req.body;
    
    if (!nombre_usuario || !clave) {
        return res.status(400).json({ mensaje: "Nombre de usuario y clave son requeridos." });
    }

    const sql = "SELECT * FROM clientes WHERE nombre_usuario = ?";
    db.query(sql, [nombre_usuario], async (err, results) => {
        if (err || results.length === 0) {
            return res.status(401).json({ mensaje: "Credenciales inválidas." });
        }
        
        const cliente = results[0];
        
        // Comparar la clave
        const match = await bcrypt.compare(clave, cliente.clave_hashed);

        if (!match) {
            return res.status(401).json({ mensaje: "Credenciales inválidas." });
        }

        // Generar Token JWT del Cliente (sin la clave hashed)
        const token = jwt.sign(
            { id: cliente.id, nombre_usuario: cliente.nombre_usuario, nombres: cliente.nombres },
            JWT_SECRET_CLIENTE,
            { expiresIn: '1d' }
        );

        res.json({ mensaje: `Bienvenido, ${cliente.nombres}!`, token, nombre_usuario: cliente.nombre_usuario });
    });
});

// ------------------------------------------------------------------
// RUTAS DE PRODUCTOS (PAGINACIÓN, CRUD, CHECKOUT)
// ------------------------------------------------------------------

// 1. OBTENER PRODUCTOS (PÚBLICO - con búsqueda, filtros y PAGINACIÓN)
app.get("/productos", (req, res) => {
    const { search, minPrice, maxPrice, page, limit, category } = req.query; 

    // --- Configuración de Paginación ---
    const pageNumber = parseInt(page) || 1; 
    const itemsPerPage = parseInt(limit) || 100; 
    const offset = (pageNumber - 1) * itemsPerPage; 
    
    // Preparación de la consulta
    let sql = "SELECT * FROM productos";
    let countSql = "SELECT COUNT(*) as total FROM productos";
    let params = [];
    let countParams = [];
    let conditions = [];

    // --- 1. FILTROS (SEARCH, MIN/MAX PRICE) ---

    // FILTRO DE CATEGORÍA
    if (category) {
        conditions.push("categoria = ?");
        countParams.push(category); 
        params.push(category); 
    }

    if (search) {
        conditions.push("nombre LIKE ?");
        countParams.push(`%${search}%`); 
        params.push(`%${search}%`); 
    }

    const min = parseFloat(minPrice);
    if (!isNaN(min) && min >= 0) {
        conditions.push("precio >= ?");
        countParams.push(min);
        params.push(min);
    }

    const max = parseFloat(maxPrice);
    if (!isNaN(max) && max > 0) {
        conditions.push("precio <= ?");
        countParams.push(max);
        params.push(max);
    }

    // --- 2. CONSTRUIR LA CLÁUSULA WHERE (Aplica a ambas consultas)
    if (conditions.length > 0) {
        sql += " WHERE " + conditions.join(" AND ");
        countSql += " WHERE " + conditions.join(" AND ");
    }
    
    db.query(countSql, countParams, (err, countResults) => {
        if (err) {
            console.error("Error al obtener conteo:", err);
            return res.status(500).json({ mensaje: "Error del servidor al obtener el conteo de productos." });
        }
        
        const totalItems = countResults[0].total;

        // --- 3. APLICAR PAGINACIÓN A LA CONSULTA DE PRODUCTOS ---
        sql += " ORDER BY nombre ASC LIMIT ?, ?";
        params.push(offset, itemsPerPage); 

        db.query(sql, params, (err, results) => {
            if (err) {
                console.error("Error al obtener productos con filtro:", err);
                return res.status(500).json({ mensaje: "Error del servidor al obtener los productos." });
            }
            
            res.json({
                products: results,
                currentPage: pageNumber,
                totalPages: Math.ceil(totalItems / itemsPerPage)
            });
        });
    });
});

// 2. AGREGAR PRODUCTO (PROTEGIDO)
app.post("/productos", requireAdmin, (req, res) => {
    const { nombre, precio, imagen, descripcion, categoria } = req.body;
    
    // VALIDACIÓN DE DATOS
    if (!nombre || !precio) {
        return res.status(400).json({ mensaje: "Error de validación: El nombre y el precio son obligatorios." });
    }
    const precioNumerico = parseFloat(precio);
    if (isNaN(precioNumerico) || precioNumerico <= 0) {
        return res.status(400).json({ mensaje: "Error de validación: El precio debe ser un número positivo." });
    }

    const sql = "INSERT INTO productos(nombre, precio, imagen, descripcion, categoria) VALUES (?,?,?,?,?)";

    db.query(sql, [nombre, precioNumerico, imagen, descripcion, categoria], err => {
        if (err) {
            console.error("Error al insertar en DB:", err);
            return res.status(500).json({ mensaje: "Error del servidor al guardar el producto." });
        }
        res.json({ mensaje: "Producto agregado con éxito" });
    });
});

// 3. ELIMINAR PRODUCTO (PROTEGIDO)
app.delete("/productos/:id", requireAdmin, (req, res) => {
    const idProducto = req.params.id; 
    const sql = "DELETE FROM productos WHERE id = ?";

    db.query(sql, [idProducto], (err, result) => {
        if (err) {
            console.error("Error al eliminar producto:", err);
            return res.status(500).json({ mensaje: "Error del servidor al eliminar el producto." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ mensaje: "Producto no encontrado." });
        }
        res.json({ mensaje: `Producto con ID ${idProducto} eliminado con éxito.` });
    });
});

// 4. ACTUALIZAR PRODUCTO (PROTEGIDO)
app.put("/productos/:id", requireAdmin, (req, res) => {
    const idProducto = req.params.id;
    const { nombre, precio, imagen, descripcion, categoria } = req.body;
    const precioNumerico = parseFloat(precio); 

    // VALIDACIÓN
    if (!nombre || !precio) {
        return res.status(400).json({ mensaje: "Error de validación: El nombre y el precio son obligatorios." });
    }
    if (isNaN(precioNumerico) || precioNumerico <= 0) {
        return res.status(400).json({ mensaje: "Error de validación: El precio debe ser un número positivo." });
    }

    const sql = `UPDATE productos SET nombre = ?, precio = ?, imagen = ?, descripcion = ?, categoria = ? WHERE id = ?`;
    
    db.query(sql, [nombre, precioNumerico, imagen, descripcion, categoria, idProducto], (err, result) => {
        if (err) {
            console.error("Error al actualizar producto:", err);
            return res.status(500).json({ mensaje: "Error del servidor al actualizar el producto." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ mensaje: "Producto no encontrado para actualizar." });
        }
        res.json({ mensaje: `Producto con ID ${idProducto} actualizado con éxito.` });
    });
});

// 5. OBTENER UN SOLO PRODUCTO POR ID (PÚBLICO)
app.get("/productos/:id", (req, res) => {
    const idProducto = req.params.id; 
    const sql = "SELECT * FROM productos WHERE id = ?";

    db.query(sql, [idProducto], (err, results) => {
        if (err) {
            console.error("Error al obtener producto:", err);
            return res.status(500).json({ mensaje: "Error del servidor al obtener el producto." });
        }
        if (results.length === 0) {
            return res.status(404).json({ mensaje: "Producto no encontrado." });
        }
        res.json(results[0]); 
    });
});

// 6. RUTA: POST /ordenes - PROCESAR CHECKOUT 
app.post('/ordenes', (req, res) => {
    const { nombre_cliente, email_cliente, telefono_cliente, direccion_envio, total, carrito } = req.body;

    db.beginTransaction(err => {
        if (err) return res.status(500).json({ mensaje: 'Error interno del servidor.' });

        // 2. INSERTAR la Orden (Encabezado)
        const sqlInsertOrder = `INSERT INTO ordenes (nombre_cliente, email_cliente, telefono_cliente, direccion_envio, total) VALUES (?, ?, ?, ?, ?)`;
        const orderValues = [nombre_cliente, email_cliente, telefono_cliente, direccion_envio, total];

        db.query(sqlInsertOrder, orderValues, (err, result) => {
            if (err) return db.rollback(() => { res.status(500).json({ mensaje: 'Error al guardar la orden.' }); });

            const ordenId = result.insertId;
            let detallesGuardados = 0;

            // 3. INSERTAR los Detalles de la Orden 
            if (carrito && carrito.length > 0) {
                carrito.forEach(item => {
                    const sqlInsertDetail = `INSERT INTO detalles_orden (orden_id, producto_id, cantidad, precio_unitario) VALUES (?, ?, ?, ?)`;
                    const detailValues = [ordenId, item.id, item.cantidad, item.precio];

                    db.query(sqlInsertDetail, detailValues, (err) => {
                        if (err) return db.rollback(() => { res.status(500).json({ mensaje: 'Error al guardar detalles del producto.' }); });

                        detallesGuardados++;

                        if (detallesGuardados === carrito.length) {
                            db.commit(err => {
                                if (err) return db.rollback(() => { res.status(500).json({ mensaje: 'Error al confirmar la transacción.' }); });
                                
                                res.status(201).json({ mensaje: '¡Orden procesada con éxito!', ordenId: ordenId });
                            });
                        }
                    });
                });
            } else {
                db.rollback(() => { res.status(400).json({ mensaje: 'El carrito está vacío.' }); });
            }
        });
    });
});

//7. Registrar entrada o ajuste de inventario
app.post('/inventario/ajuste', (req, res) => {
    // Extraemos los datos del cuerpo de la petición
    const { id_producto, cantidad, tipo, motivo } = req.body;

    // Validación: Si falta el ID o la cantidad, detenemos el proceso antes de que falle
    if (!id_producto || !cantidad) {
        return res.status(400).json({ mensaje: "Faltan datos: ID o Cantidad" });
    }

    const sqlUpdate = tipo === 'ENTRADA' 
        ? "UPDATE productos SET stock = stock + ? WHERE id = ?" 
        : "UPDATE productos SET stock = stock - ? WHERE id = ?";

    // Primera consulta: Actualizar stock
    db.query(sqlUpdate, [cantidad, id_producto], (err, result) => {
        if (err) {
            console.error("Error al actualizar stock:", err);
            return res.status(500).json({ mensaje: "Error en base de datos al actualizar", detalle: err });
        }

        // Segunda consulta: Insertar en el historial (Kardex)
        const sqlInsert = "INSERT INTO movimientos_inventario (id_producto, tipo, cantidad, motivo) VALUES (?, ?, ?, ?)";
        const motivoFinal = motivo || 'Ajuste manual';

        db.query(sqlInsert, [id_producto, tipo, cantidad, motivoFinal], (err2) => {
            if (err2) {
                console.error("Error al registrar movimiento:", err2);
                return res.status(500).json({ mensaje: "Error al registrar el historial", detalle: err2 });
            }
            
            // Respuesta exitosa en formato JSON
            res.json({ success: true, mensaje: "Inventario actualizado y registrado correctamente" });
        });
    });
});

// INICIO DEL SERVIDOR
app.listen(PORT, () => {
    console.log(`Servidor de la API corriendo en http://localhost:${PORT}`);
});