const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const { GraphQLClient, gql } = require('graphql-request');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const HASURA_GRAPHQL_ENDPOINT = process.env.HASURA_GRAPHQL_ENDPOINT;
const HASURA_ADMIN_SECRET = process.env.HASURA_ADMIN_SECRET;

const graphQLClient = new GraphQLClient(HASURA_GRAPHQL_ENDPOINT, {
  headers: {
    'x-hasura-admin-secret': HASURA_ADMIN_SECRET,
  },
});

// User Registration
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  
  const mutation = gql`
    mutation ($username: String!, $password: String!) {
      insert_users(objects: { username: $username, password: $password }) {
        returning {
          id
        }
      }
    }
  `;
  
  await graphQLClient.request(mutation, { username, password: hashedPassword });
  res.status(201).send('User registered');
});

// User Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  const query = gql`
    query ($username: String!) {
      users(where: { username: { _eq: $username } }) {
        id
        password
      }
    }
  `;
  
  const { users } = await graphQLClient.request(query, { username });
  
  if (users.length === 0 || !(await bcrypt.compare(password, users[0].password))) {
    return res.status(401).send('Invalid credentials');
  }
  
  const token = jwt.sign({ id: users[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Middleware to authenticate JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(403);
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Deposit and Withdraw
app.post('/transaction', authenticateJWT, async (req, res) => {
  const { accountId, amount, transactionType } = req.body;
  
  const mutation = gql`
    mutation ($accountId: uuid!, $amount: numeric!, $transactionType: String!) {
      insert_transactions(objects: { account_id: $accountId, amount: $amount, transaction_type: $transactionType }) {
        returning {
          id
        }
      }
      update_accounts(where: { id: { _eq: $accountId } }, _inc: { balance: transactionType === 'deposit' ? $amount : -$amount }) {
        returning {
          balance
        }
      }
    }
  `;
  
  await graphQLClient.request(mutation, { accountId, amount, transactionType });
  res.send('Transaction successful');
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
