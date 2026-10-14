import mongoose, {Schema} from "mongoose";
import bcrypt from "bcrypt";

const userSchema = new Schema(
  {
    username:{
      type: String,
      unique: true,
      required: true,
      lowercase: true,
      trim: true,
      index: true
    },
    email: {
      type: String,
      unique: true,
      required: true,
      lowercase: true,
      trim: true,
      index: true
    },
    passwordHash: {
      type: String,
      required: true
    }
  }, {timestamps: true}
);

userSchema.methods.changePassword = async function(password){
  this.passwordHash = await bcrypt.hash(password, 10);
  await this.save();
}

userSchema.methods.changeUserName = async function(username){
  this.username = username;
  await this.save();
}

const User = mongoose.model("User", userSchema);

const createUser = async function({username, email, password}){
  const passwordHash = await bcrypt.hash(password, 10);
  const user = new User(
    {
      username,
      email,
      passwordHash
    }
  )

  await user.save();
  return user;
}

export {User, createUser}