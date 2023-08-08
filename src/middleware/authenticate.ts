import jwt from 'jsonwebtoken';
import User from '../models/User'; // Import the User model
const dotenv = require("dotenv");
dotenv.config();

// Load the token key from environment variable or use a default value
const TOKEN_KEY = process.env.token || 'secret';

// Middleware function for authentication
const authenticate = async (req: any, _: any, next: any) => {
    const token = req.headers.authorization;

    // Check if a token is present in the request headers
    if (token) {
      try {
        // Verify the token and extract the userId
        const { userId } = jwt.verify(token, TOKEN_KEY) as { userId: string };
        
        // Find the user by the userId and attach it to the request object
        req.user = await User.findById(userId);
      } catch (error) {
        // Log and handle any error that occurs during token verification
        console.error('Error verifying token:', error);
      }
    }

    // Move to the next middleware or route handler
    next();
};

// Export the authenticate middleware for use in other parts of the application
export default authenticate;
