# aaauth: Simple. OPinionated. Auth.
 
aaauth is a simple, opinionated, auth library. It provides a router and a middleware function which you can use.

```js
import express from 'express';
import Aaauth from 'aaauth';

import {createUser, userExists, getUser, storeRefreshToken, refreshTokenExists, invalidateRefreshToken} from './db.js';

const app = express();

const aaauth = Aaauth({
	jwtSecret: process.env.JWT_SECRET,
	createUser, userExists, getUser, storeRefreshToken, refreshTokenExists, invalidateRefreshToken
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(aaauth.router);

app.get('/', (req, res) => { // Normal route
	res.send('Hello World!');
});

app.get('/secure', aaauth.authenticate, (req, res) => { // Secure route: needs access token
	res.send('Hello World!');
});

app.listen(3000, () => {
	console.log('Example app listening on port 3000!');
});
```

## Docs

The aaauth library exposes a single function: `Aaauth`. This function takes an object with the following properties:

 * `jwtSecret: string`: The secret used to sign the JWT.
 * `createUser(user: {username: string, password: string, ...other details})`: A function which creates a user.
 * `userExists(user: {username: string})`: A function which checks if a user exists.
 * `getUser(user: {username: string})`: A function which gets a user.
 * `storeRefreshToken(token: string)`: A function which stores a refresh token.
 * `refreshTokenExists(token: string)`: A function which checks if a refresh token exists.
 * `invalidateRefreshToken(token: string`: A function which invalidates a refresh token.
