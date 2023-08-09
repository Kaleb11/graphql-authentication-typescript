import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User, { IUser } from '../models/User';
import { ResolverMap } from '../types';
import {ApolloError, AuthenticationError } from 'apollo-server-express'; // Import the AuthenticationError class
import speakeasy from 'speakeasy'; // Import speakeasy
import qrcode from 'qrcode'; // Import qrcode
const dotenv = require("dotenv");
dotenv.config();
//import qrcode from 'qrcode-terminal';
import fs from 'fs';
import path from 'path';
const TOKEN_KEY = process.env.token || 'secret';

const resolvers: ResolverMap = {
  Query: {
    me: (_, __, { user }) => {
      return user;
    },
  },
  Mutation: {
    // User registration mutation
    register: async (_, { username, email, password }) => {
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
    
      // Create a new user with the hashed password
      const user = new User({ username, email, password: hashedPassword });
      await user.save();
    
      // Generate a JWT token for the new user
      const token = jwt.sign({ userId: user.id }, TOKEN_KEY, {
        expiresIn: '1h',
      });
    
      // Return the token and user details
      return { token, user };
    },
    

    // User login mutation
    login: async (_, { email, password }) => {
      // Find the user by email
      const user = await User.findOne({ email });
    
      // If user doesn't exist, throw an error
      if (!user) {
        throw new AuthenticationError('No user with that email');
      }
    
      // Compare the entered password with the stored password
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        throw new AuthenticationError('Incorrect password');
      }
    
      // Generate a JWT token for the authenticated user
      const token = jwt.sign({ userId: user.id }, TOKEN_KEY, {
        expiresIn: '1h',
      });
    
      // Return the token and user details
      return { token, user };
    },
    

    // User change password mutation
    changePassword: async (_, { email, oldPassword, newPassword }) => {
      // Find the user by email
      const user = await User.findOne({ email });

      // If user doesn't exist, throw an error with a custom status code
      if (!user) {
        const error = new ApolloError('User not found', 'USER_NOT_FOUND');
        error.extensions = { statusCode: 404 }; // Set custom status code
        throw error;
      }

      // Compare the old password with the stored password
      const valid = await bcrypt.compare(oldPassword, user.password);
      if (!valid) {
        throw new AuthenticationError('Incorrect old password.');
      }

      // Hash the new password and update the user's password
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      await user.save();

      return true; // Password change successful
    },

    
    // User enable two factor authentication mutation
    enableTwoFactorAuth: async (_, { email }) => {
      // Find the user by email
      const user = await User.findOne({ email });
    
      // If user doesn't exist, throw an error
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
      const qrCodeImageBuffer = await qrcode.toBuffer(otpUrl);
    
      // Create a unique filename for the QR code image
      const filename = `${user.id}-qrcode.png`;
    
      // Save the QR code image to a directory (e.g., "public/images")
      const imagePath = path.join(__dirname, '../../public', 'images', filename);
      try {
        // Save the QR code image to the specified path
        fs.writeFileSync(imagePath, qrCodeImageBuffer);
      } catch (error) {
        // Handle error
        console.error('Error saving QR code image:', error);
        throw new Error}
      // Get the relative path from /public portion
      const relativeImagePath = path.relative(path.join( 'Graphql-authentication-Typescript'), imagePath);
       // Remove the first two dots from the relative path
      const cleanedImagePath = relativeImagePath.replace(/^(\.\.)+/, '');
      // Return the image file path or a URL
      return { qrCodeImagePath: cleanedImagePath };
    },


    // User verify two factor authentication mutation
    verifyTwoFactorAuth: async (_, { email, token }) => {
      // Find the user by email
      const user = await User.findOne({ email });

      // If user doesn't exist, throw an error
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
        return true; // Token verified successfully
      } else {
        throw new Error('Invalid token');
      }
    },


    // User login with 2FA mutation
    loginWith2FA: async (_, { email, password, code }) => {
      // Find the user by email
      const user = await User.findOne({ email });

      if (!user) {
        throw new AuthenticationError('Invalid credentials');
      }

      // Compare the password with the stored password
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        throw new AuthenticationError('Invalid credentials');
      }

      if (!user.twoFactorSecret) {
        throw new AuthenticationError('2FA not enabled');
      }

      // Verify the provided 2FA code using speakeasy
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: code,
      });

      if (!verified) {
        throw new AuthenticationError('Invalid 2FA code');
      }

      // Generate a new JWT token for the user
      const token = jwt.sign({ userId: user.id }, TOKEN_KEY, {
        expiresIn: '1h',
      });

      return { token, user };
    },

  },
};

export default resolvers;
