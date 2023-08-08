import mongoose from 'mongoose';
const dotenv = require("dotenv");
dotenv.config();

// MongoDB connection URL, fallback to a default value
const mongoUrl = process.env.mongourl || 'mongodb+srv://kalebtilahun29:tAEEFo8LdufRIcgP@cluster0.damkjmk.mongodb.net/graphql-auth?retryWrites=true&w=majority';

// Function to connect to the MongoDB database
const connectDB = async () => {
  try {
    // Attempt to establish a connection to the MongoDB database
    const conn = await mongoose.connect(mongoUrl);
    console.log(`MongoDB connected: ${conn.connection.host}`);
  } catch (error) {
    // Log any error that occurs during the connection attempt
    console.error('MongoDB connection error:', error);
    process.exit(1); // Exit the process with a non-zero status code
  }
};

// Export the connectDB function for use in other parts of the application
export default connectDB;
