const express = require('express');
const bcrypt = require('bcryptjs');
const md5 = require('md5');

const Users = require('./users/users-model.js');
const server = express();

server.use(express.json());

server.get('/', (req, res) => {
	res.send("It's working!");
});

// 1- build a custom middleware
// that can check username & password
// so that logic goes away from the login endpoint

// 2- build a custom bcrypt
//    - uses md5
//    - uses a unique random salt
//    - runs the hashing a configurable number of times
//    - has a helper to check whether a password matches a hash

const sillyBcrypt = {
	hash(rawPassword, iterations) {
		// computes random salt
		// md5 the cancatenated rawPassword + salt
		// does it "iterations" number of times
		let randomSalt = new Date().getTime();
		let result = rawPassword + randomSalt;
		for (let i = 0; i < iterations; i++) {
			result = md5(result);
		}
		return randomSalt, iterations, result;
	},

	compare(rawPassword, sillyBcryptHash) {
		// pull the number of iterations and the salt from the sillyBcryptHash
		// recompute a hash
		// check that results are identical
	},
};

function restricted(req, res, next) {
	// checks req.header for username & password
	// performs the authentication
	// if auths -> next()
	// res.json('no way')
}

function checkCredentialsInBody(req, res, next) {
	// checks req.body for username and password
	// auths
	let { username, password } = req.body;

	Users.findBy({ username })
		.first()
		.then(user => {
			if (user && bcrypt.compareSync(password, user.password)) {
				res.status(200).json({ message: `Welcome ${user.username}!` });
			} else {
				res.status(401).json({ message: 'Invalid Credentials' });
			}
		})
		.catch(error => {
			res.status(500).json(error);
		});
}

server.post('/api/register', (req, res) => {
	// we use bcrypt here to hash password and saved the hashed thing
	// alg$12$my_saltxxxxxxxxxxxxxxxxxxx"
	// we save that into the db instead of the plain text password
	let user = req.body;
	user.password = bcrypt.hashSync(user.password, 12);
	// use a very slow hashing function
	// generate a random long salt
	// hash the password together with the salt
	// the result will be hashed again etc etc etc 84932579283742398

	Users.add(user)
		.then(saved => {
			res.status(201).json(saved);
		})
		.catch(error => {
			res.status(500).json(error);
		});
});

server.post('/api/login', checkCredentialsInBody, (req, res) => {
	// use bcrypt to compara the saved hash
	// against the result of hashing again the provided password
	let { username } = req.body;

	Users.findBy({ username })
		.first()
		.catch(error => {
			res.status(500).json(error);
		});
});

server.get('/api/users', restricted, (req, res) => {
	Users.find()
		.then(users => {
			res.json(users);
		})
		.catch(err => res.send(err));
});

const port = 4000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
