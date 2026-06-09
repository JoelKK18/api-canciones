require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sequelize = require('./db');
const { User } = require('./models.js');
const { Song } = require('./models.js');
const authenticateToken = require('./authMiddleware');

const app = express();
app.use(express.json());

// ==========================================
// RUTAS DE AUTENTICACIÓN
// ==========================================

// Registrar Usuario
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ username, password: hashedPassword });
    res.status(201).json({ message: 'Usuario registrado', userId: newUser.id });
  } catch (error) {
    res.status(400).json({ error: 'Error al registrar: ' + error.message });
  }
});

// Login (Generar JWT)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ where: { username } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const token = jwt.sign(
      { id: user.id, username: user.username }, 
      process.env.JWT_SECRET || 'clave_secreta_alterna', 
      { expiresIn: '2h' }
    );
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==========================================
// CRUD DE CANCIONES (PROTEGIDAS CON JWT)
// ==========================================

// POST: Crear canción
app.post('/api/canciones', authenticateToken, async (req, res) => {
  try {
    const { titulo, duracion, artista, genero, popularidad } = req.body;
    const nuevaCancion = await Song.create({ titulo, duracion, artista, genero, popularidad });
    res.status(201).json(nuevaCancion);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// GET: Obtener canciones
app.get('/api/canciones', authenticateToken, async (req, res) => {
  try {
    const canciones = await Song.findAll();
    res.json(canciones);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT: Modificar canción
app.put('/api/canciones/:id', authenticateToken, async (req, res) => {
  try {
    const { titulo, duracion, artista, genero, popularidad } = req.body;
    const cancion = await Song.findByPk(req.params.id);
    if (!cancion) return res.status(404).json({ error: 'Canción no encontrada' });

    await cancion.update({ titulo, duracion, artista, genero, popularidad });
    res.json({ message: 'Canción actualizada', cancion });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// DELETE: Eliminar canción
app.delete('/api/canciones/:id', authenticateToken, async (req, res) => {
  try {
    const cancion = await Song.findByPk(req.params.id);
    if (!cancion) return res.status(404).json({ error: 'Canción no encontrada' });

    await cancion.destroy();
    res.json({ message: 'Canción eliminada correctamente' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==========================================
// ARRANCAR EL SERVIDOR
// ==========================================
const PORT = process.env.PORT || 3000;

sequelize.sync({ force: false })
  .then(() => {
    console.log('Base de datos PostgreSQL sincronizada con éxito.');
    app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));
  })
  .catch(err => {
    console.error('Error al conectar con la Base de Datos:', err);
  });