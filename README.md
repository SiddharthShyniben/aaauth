# aaauth: Simple. OPinionated. Auth.
 
aaauth is a simple, opinionated, auth library. It provides a router and a middleware function which you can use.

## Example:

```js
import express from 'express';
import Aaauth from './index.js';

import {createUser, userExists, getUser, storeRefreshToken, refreshTokenExists, invalidateRefreshToken} from './db.js';

const app = express();

const aaauth = Aaauth({
	jwtSecret: process.env.JWT_SECRET,
	createUser,
	userExists,
	getUser,
	storeRefreshToken,
	refreshTokenExists,
	invalidateRefreshToken
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
