const mongoose = require("mongoose");
const mongoosePaginate = require("mongoose-paginate");
const bcrypt = require("bcryptjs");

const UserSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: true 
  },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    lowercase: true 
  },
  password: { 
    type: String, 
    required: true 
  },
  role: { 
    type: String, 
    enum: ["admin", "user"], 
    default: "user" 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
    },
});

// Criptografa a senha antes de salvar
UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 4);
});

// Compara senha fornecida com a salva no banco
UserSchema.methods = {
  compareHash(password) {
    return bcrypt.compare(password, this.password);
  },
};

UserSchema.plugin(mongoosePaginate);
module.exports = mongoose.model("User", UserSchema);

