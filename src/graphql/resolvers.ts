// src/graphql/resolvers.ts
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User, { IUser } from '../models/User';
import { ResolverMap } from '../types';

const resolvers: ResolverMap = {
  Query: {
    me: (_, __, { user }) => {
      return user;
    },
  },
  Mutation: {
    register: async (_, { username, email, password }) => {
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({ username, email, password: hashedPassword });
      await user.save();

      const token = jwt.sign({ userId: user.id }, 'your-secret-key', {
        expiresIn: '1h',
      });

      return { token, user };
    },
    login: async (_, { email, password }) => {
      const user = await User.findOne({ email });

      if (!user) {
        throw new Error('No user with that email');
      }

      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        throw new Error('Incorrect password');
      }

      const token = jwt.sign({ userId: user.id }, 'your-secret-key', {
        expiresIn: '1h',
      });

      return { token, user };
    },
  },
};

export default resolvers;
