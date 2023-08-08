import mongoose, { Document, Schema } from 'mongoose';

export interface IUser extends Document {
  username: string;
  email: string;
  password: string;
  twoFactorSecret:string;
}

const userSchema: Schema = new Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  twoFactorSecret: {type:String, required:false,unique:true}
});

const User = mongoose.model<IUser>('User', userSchema);

export default User;
