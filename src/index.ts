import express from 'express';
import { ApolloServer } from 'apollo-server-express';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import typeDefs from './graphql/schema';
import resolvers from './graphql/resolvers';
import User, { IUser } from './models/User';
import { ResolverMap } from './types';

const app = express();

// Connect to MongoDB

const connectDB = async () => {
  try {
      const conn = await mongoose.connect('mongodb+srv://kalebtilahun29:tAEEFo8LdufRIcgP@cluster0.damkjmk.mongodb.net/graphql-auth?retryWrites=true&w=majority');
      console.log(`Mongo db connected: ${conn.connection.host}`);
  } catch (error) {
      console.log(error);
      process.exit(1);
  }
};
connectDB()
// Middleware to authenticate incoming requests
const authenticate = async (req: any, _: any, next: any) => {
  const token = req.headers.authorization;
  if (token) {
    try {
      const { userId } = jwt.verify(token, 'your-secret-key') as { userId: string };
      req.user = await User.findById(userId);
    } catch (error) {
      console.error('Error verifying token:', error);
    }
  }
  next();
};

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

  const PORT = 4000;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}${server.graphqlPath}`);
  });
}

startApolloServer();