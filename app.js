import express from 'express'
import bodyParser from 'body-parser'
import { scrypt, randomBytes, randomUUID } from 'node:crypto'

const app = express()
app.use(bodyParser.json());

//Se definen dos arrays para almacenar los datos de los usuarios y las tareas
const users = [{
	username: 'admin',
	name: 'Gustavo Alfredo Marín Sáez',
	password: '1b6ce880ac388eb7fcb6bcaf95e20083:341dfbbe86013c940c8e898b437aa82fe575876f2946a2ad744a0c51501c7dfe6d7e5a31c58d2adc7a7dc4b87927594275ca235276accc9f628697a4c00b4e01' // certamen123
}]
const todos = []

app.use(express.static('public'))

//SERVICIO
//implementa una función asincrónica llamada validarContraseña,
//se compara una contraseña proporcionada con el hash almacenado para verificar si la contraseña es válida.

async function validarContraseña(contraseña, hashAlmacenado) {
    const [salt, hash] = hashAlmacenado.split(':');
    const hashRecreado = await generarHash(contraseña, salt);
    return hashRecreado === hash; 
}
//Función asincrónica para genera hash de una contraseña utilizando un salt	
async function generarHash(contraseña, salt) {
    return new Promise((resolve, reject) => {
        scrypt(contraseña, salt, 64, (err, derivedKey) => {
            if (err) reject(err);
            resolve(derivedKey.toString('hex'));
        });
    });
}

function generarBearerToken(username) {

    // Generar una cadena aleatoria para el token
    const token = randomBytes(32).toString('hex');

    const fechaActual = new Date();
    // Combinar los datos custom y el token en un objeto
	//creación de un token de autenticación para un usuario, que incluye el nombre de usuario, 
	//la hora exacta en que se creó el token y la hora en que dejará de ser válido (3 horas después de su creación).
    const tokenData = {
        username: username,
    };

    // Convertir los bytes en una cadena hexadecimal
    const tokenHex = token.toString('hex');

    // Concatenar la cadena JSON con la cadena hexadecimal
    const tokenCompleto = JSON.stringify(tokenData);

    return tokenCompleto;
}

//Middleware de Validación
function validateMiddleware(req, res, next) {
    const authHeader = req.headers['x-authorization'];
    let user = "";
 // Se intenta parsear el encabezado de autorización para extraer el nombre de usuario
    if (authHeader && authHeader.trim() !== '') {
        try {
            // Convertir el string JSON a un objeto JSON
            const jsonObject = JSON.parse(authHeader);
            user = jsonObject.username;
        } catch (error) {
			//Si hay un error en el parseo, se envía un estado 401 de no autorizado
            console.error('Error al analizar el encabezado de autorización JSON:', error.message);
            return res.status(401).send();
        }
    } else {
		//Si el encabezado de autorización está vacío o no definido, también se envía un estado 401
        console.log('El encabezado de autorización está vacío o no está definido.');
        return res.status(401).send();
    }

	//Verifica si el usuario extraído del token está presente en el array de usuarios
    const userIndex = users.findIndex((u) => u.username == user)

	//Si el usuario no se encuentra, se envía un estado 401 de no autorizado
    if (userIndex == -1) {
        console.log("error validacion")
        return res.status(401).send();
    } else {
		// Si el usuario es válido, se procede con la siguiente función en la cadena de middleware
        console.log("validado")
        next();
    }
}

//visitamos la dirección "/api", y si está correcto responde enviando el mensaje "Hello World!
app.get('/api', (req, res) => {
	res.contentType('text/plain');
	res.status(200).send('Hello World!');
})

//LOGIN 
//Establece el tipo de contenido de la respuesta como JSON
app.post('/api/login', async (req, res)  => {
	res.contentType('application/json');

	//Obtiene el nombre de usuario y la contraseña de la solicitud
	const userInput = req.body.username;
	const pwInput = req.body.password;

	// Verifica que se hayan proporcionado el nombre de usuario y la contraseña
	if (userInput == undefined || userInput == "")
		res.status(400).send("Ingrese un usuario válido")
	if (pwInput == undefined || pwInput == "") 
		res.status(400).send("Ingrese una contraseña válida")

	const indiceUsuario = users.findIndex((user) => user.username == userInput);

	if (indiceUsuario == -1) {
		res.status(401).send("Usuario o contraseña Incorrectos")
	} else {

		try {
			const isValidCredentials = await validarContraseña(pwInput, users[indiceUsuario].password);
			if (!isValidCredentials)
			{
				res.status(401).send("Usuario o contraseña Incorrectos")
			}
			else
			{
				// Si las credenciales son válidas, genera un token de autenticación
				const resp = { 
					username: users[indiceUsuario].username, 
					name: users[indiceUsuario].name,
					token: generarBearerToken(users[indiceUsuario].username)
				}

				res.status(200).send(resp);
			}
		}
		catch (err)
		{
			console.log(err)
		}
	}
})

//Endpoint para obtener todas las tareas
app.get("/api/todos", validateMiddleware, (req, res)  =>  {
	res.contentType('application/json');
	let lista = []

	todos.forEach(element => {
		// Itera sobre todas las tareas y las agrega a una lista
		lista.push({
			id: element.id,
			title: element.title,
			completed: element.completed
		})
	});

	res.status(200).send(lista);
})
// Endpoint para obtener los detalles de una tarea específica por su ID
app.get("/api/todos/:id", validateMiddleware, (req, res) => {
	res.contentType('application/json');

	const id = req.params.id;

	const todoIndex = todos.findIndex((t) => t.id == id);
// Si la tarea no existe, responde con un error 404
	if (todoIndex == -1) {
		res.status(404).send("Item no existe");
	} else {
		const respuesta = {
			id: todo[todoIndex].id,
			title: todo[todoIndex].title,
			completed: todo[todoIndex].completed
		}
		res.status(200).send(respuesta);
	}
})

// Endpoint para crear una nueva tarea
app.post("/api/todos", validateMiddleware, (req, res) => {
	res.contentType('application/json');
	
	try {
		const title = req.body.title;
// Crea una nueva tarea con un ID único generado y el título proporcionad
		const todo = {
			id: randomUUID().toString(),
			title: title,
			completed: false
		}

		todos.push(todo);
	
		res.status(201).send(todo);
	} catch (err) {
		res.status(400);
	} 
})

// Endpoint para actualizar una tarea existente
app.put("/api/todos/:id", validateMiddleware, (req, res) => {
	res.contentType('application/json');

	const id = req.params.id;
	const title = req.body.title;
	const completed = req.body.completed;
	
	try {

		const todoIndex = todos.findIndex((todo) => todo.id == id);

		let todoExist = todos[todoIndex];
		// Actualiza el título y/o el estado completado de la tarea con los datos proporcionados
		const todo = {
			id: id,
			title: title ? title : todoExist.title,
			completed: completed ? completed : todoExist.completed
		}
	
		todos[todoIndex] = todo;

		res.status(200).send(todo);
	} catch (err) {
		res.status(400);
	} 
})

// Endpoint para eliminar una tarea existente
app.delete("/api/todos/:id", validateMiddleware, (req, res) => {
	const id = req.params.id;

	try {
		const todosArray = todos;
		const todoIndex = todos.findIndex((todo) => todo.id == id);

		todos.splice(todoIndex, 1);
		res.status(204).send();

	} catch (err) {
		res.status(404);
	} 
})


// ... hasta aquí

export default app