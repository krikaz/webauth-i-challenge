const express = require('express');
const bcrypt = require('bcryptjs');

const session = require('express-session');
const KnexSessionStore = require('connect-session-knex')(session);

const Users = require('./users/users-model.js');
const server = express();

const restricted = require('./users/restricted-middleware');

server.use(express.json());
server.use(
	session({
		name: 'sessionId', // name of the cookie
		secret: 'keep it secret, keep it long', // we intend to encrypt
		cookie: {
			maxAge: 1000 * 60 * 60,
			secure: false,
			httpOnly: true,
		},
		resave: false,
		saveUninitialized: true,
		// extra chunk of config
		store: new KnexSessionStore({
			knex: require('./database/dbConfig.js'), // configured instance of knex
			tablename: 'sessions', // table that will store sessions inside the db, name it anything you want
			sidfieldname: 'sid', // column that will hold the session id, name it anything you want
			createtable: true, // if the table does not exist, it will create it automatically
			clearInterval: 1000 * 60 * 60, // time it takes to check for old sessions and remove them from the database to keep it clean and performant
		}),
	})
);

server.get('/', (req, res) => {
	res.send("It's working!");
});

function checkCredentialsInBody(req, res, next) {
	// checks req.body for username and password
	// auths
	let { username, password } = req.body;

	Users.findBy({ username })
		.first()
		.then(user => {
			if (user && bcrypt.compareSync(password, user.password)) {
				res.status(200).json({ message: `Welcome ${user.username}!` });
				req.session.user = user;
			} else {
				res.status(401).json({ message: 'Invalid Credentials' });
			}
		})
		.catch(error => {
			res.status(500).json(error);
		});
}

server.post('/api/auth/register', (req, res) => {
	let user = req.body;
	user.password = bcrypt.hashSync(user.password, 12);

	Users.add(user)
		.then(saved => {
			res.status(201).json(saved);
		})
		.catch(error => {
			res.status(500).json(error);
		});
});

server.post('/api/auth/login', checkCredentialsInBody, (req, res) => {
	let { username } = req.body;

	Users.findBy({ username })
		.first()
		.catch(error => {
			res.status(500).json(error);
		});
});

server.get('/api/users', (req, res) => {
	Users.find()
		.then(users => {
			res.json(users);
		})
		.catch(err => res.send(err));
});

server.get('/api/restricted', restricted, (req, res) => {
	res.send('restricted area for restricted users').catch(err => res.send(err));
});

const port = 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
