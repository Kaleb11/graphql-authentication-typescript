import express from 'express';
import { ApolloServer } from 'apollo-server-express';
import typeDefs from './graphql/schema';
import resolvers from './graphql/resolvers';
import authenticate from './middleware/authenticate';
import { ResolverMap } from './types';
import connectDB from './utils/connectdb';
const app = express();
const dotenv = require("dotenv");
dotenv.config();

const PORT = process.env.port || 4000;

// Connect to MongoDB
connectDB()

// Middleware to authenticate incoming requests
app.use(authenticate);

const server = new ApolloServer({
  typeDefs,
  resolvers: resolvers as ResolverMap, // Type assertion
 
});
// Start the Apollo Server first
async function startApolloServer() {
  await server.start();

  // Apply Apollo Server as middleware
  server.applyMiddleware({ app });

 
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}${server.graphqlPath}`);
  });
}

// Start Apollo Server
startApolloServer();