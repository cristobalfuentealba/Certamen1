import express from 'express';
import bodyParser from 'body-parser';
import { scrypt, randomBytes, randomUUID } from 'node:crypto';

const app = express();
app.use(bodyParser.json()); // Middleware para parsear JSON en los cuerpos de las solicitudes


const users = [{
    username: 'admin',
    name: 'Gustavo Alfredo Marín Sáez',
    password: '1b6ce880ac388eb7fcb6bcaf95e20083:341dfbbe86013c940c8e898b437aa82fe575876f2946a2ad744a0c51501c7dfe6d7e5a31c58d2adc7a7dc4b87927594275ca235276accc9f628697a4c00b4e01',
    token: ''
}];
const todos = [];
// Servir archivos estáticos desde el directorio 'public'
app.use(express.static('public'));

// Función asincrónica para validar la contraseña comparándola con el hash almacenado
async function validarContraseña(contraseña, hashAlmacenado) {
    const [salt, hash] = hashAlmacenado.split(':');
    const hashRecreado = await generarHash(contraseña, salt);
    return hashRecreado === hash;
}
// Función para generar un hash utilizando scrypt a partir de una contraseña y un salt
async function generarHash(contraseña, salt) {
    return new Promise((resolve, reject) => {
        scrypt(contraseña, salt, 64, (err, derivedKey) => {
            if (err) reject(err);
            resolve(derivedKey.toString('hex'));
        });
    });
}
// Genera un token de autenticación y lo almacena en el objeto del usuario
function generarBearerToken(username) {
    const token = randomBytes(48).toString('hex'); // Genera un token de 48 bytes
    const user = users.find(u => u.username === username);
    if (user) {
        user.token = token; // Guarda el token en el objeto del usuario
    }
    return token;
}
// Middleware para validar la presencia y validez del token en las solicitudes
function validateMiddleware(req, res, next) {
    const token = req.headers['x-authorization'];
    if (!token) {
        return res.status(401).send('Token no proporcionado');
    }
    const user = users.find(u => u.token === token);
    if (!user) {
        return res.status(401).send('Token inválido'); 
    }   next();
}

// Ruta para devolver un simple mensaje 'Hello World!' como texto plano
app.get('/api', (req, res) => {
    res.contentType('text/plain');
    res.status(200).send('Hello World!');
});
// Ruta de autenticación que verifica el usuario y la contraseña y devuelve un token
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send("Ingrese un usuario y contraseña válidos");
    }
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(401).send("Usuario o contraseña Incorrectos");
    }
    const isValid = await validarContraseña(password, user.password);
    if (!isValid) {
        return res.status(401).send("Usuario o contraseña Incorrectos");
    }
    const token = generarBearerToken(username);
    res.status(200).send({
        username: user.username,
        name: user.name,
        token: token
    });
});
// Rutas CRUD para manejar las tareas (to-do) con autenticación requerida
app.get("/api/todos", validateMiddleware, (req, res) => {
    res.status(200).json(todos.map(todo => ({
        id: todo.id,
        title: todo.title,
        completed: todo.completed
    })));
});
//Endpoint para obtener los detalles de una tarea específica por su ID
app.get("/api/todos/:id", validateMiddleware, (req, res) => {
    const { id } = req.params;
    const todo = todos.find(t => t.id === id);
    if (!todo) {
        return res.status(404).send("Item no existe");
    }
    res.status(200).json({ id: todo.id, title: todo.title, completed: todo.completed });
});
//Endpoint para crear una nueva tarea
app.post("/api/todos", validateMiddleware, (req, res) => {
    const { title } = req.body;
    if (!title) {
        return res.status(400).send("Se requiere un título para la tarea");
    }
    const todo = {
        id: randomUUID(),
        title: title,
        completed: false 
    };
    todos.push(todo);
    res.status(201).json(todo);
});
//Endpoint para actualizar una tarea existente
app.put("/api/todos/:id", validateMiddleware, (req, res) => {
    const { id } = req.params;
    const { title, completed } = req.body;
    const todo = todos.find(t => t.id === id);
    if (!todo) {
        return res.status(404).send("Item no existe");
    }
    if (title) todo.title = title;
    if (typeof completed === 'boolean') todo.completed = completed; // Verificamos que completed es un boolean
    res.status(200).json(todo);
});
//Endpoint para eliminar una tarea existente
app.delete("/api/todos/:id", validateMiddleware, (req, res) => {
    const { id } = req.params;
    const index = todos.findIndex(t => t.id === id);
    if (index === -1) {
        return res.status(404).send("Item no existe");
    }
    todos.splice(index, 1);
    res.status(204).send();
});

export default app;