// src/graphql/resolvers.ts
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User, { IUser } from '../models/User';
import { ResolverMap } from '../types';
import {ApolloError, AuthenticationError } from 'apollo-server-express'; // Import the AuthenticationError class
import speakeasy from 'speakeasy'; // Import speakeasy
import qrcode from 'qrcode'; // Import qrcode
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
    changePassword: async (_, { email, oldPassword, newPassword }) => {
      const user = await User.findOne({ email });

      if (!user) {
        const error = new ApolloError('User not found', 'USER_NOT_FOUND');
        error.extensions = { statusCode: 404 }; // Set custom status code
        throw error;
      }

      const valid = await bcrypt.compare(oldPassword, user.password);
      if (!valid) {
        throw new AuthenticationError('Incorrect old password.');
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      await user.save();

      return true;
    },
    enableTwoFactorAuth: async (_, { email }) => {
      const user = await User.findOne({ email });

      if (!user) {
        throw new Error('User not found');
      }

      // Generate a secret key for the user
      const secret = speakeasy.generateSecret();

      // Store the secret key with the user
      user.twoFactorSecret = secret.base32;
      await user.save();

      // Generate OTP URL for QR code
      const otpUrl = speakeasy.otpauthURL({
        secret: secret.ascii,
        label: 'graphqlauth:' + user.id,
        issuer: 'graphqlauth',
      });

      // Generate QR code image
      const qrCodeImage = await qrcode.toDataURL(otpUrl);

      return { qrCodeImage };
    },
    verifyTwoFactorAuth: async (_, { email, token }) => {
      const user =await User.findOne({ email });

      if (!user) {
        throw new Error('User not found');
      }

      // Verify the provided token using speakeasy
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: token,
      });

      if (verified) {
        return true;
      } else {
        throw new Error('Invalid token');
      }
    },
  },
};

export default resolvers;
